# Bounded, inert web deception for Huginn. No network calls or request evaluation.
import hashlib as hpw_hashlib
import json as hpw_json
import os as hpw_os
import re as hpw_re
import time as hpw_time
from urllib.parse import unquote as hpw_unquote, urlsplit as hpw_urlsplit

HPW_VERSION = 1
HPW_MAX_URI = 2048
HPW_MAX_BODY = 4096
HPW_MAX_BUNDLE = 65536
HPW_BUNDLE = 'webreply.json'
HPW_BAIT = '/etc/huginn-honeypot/bait.json'
# Slow export: the robots-only backup file trickles out like a slow device. Bounded so it can never tie up the honeypot.
HPW_DRIP_KINDS = ('robots_backup',)
HPW_DRIP_SECS = 5.0
HPW_DRIP_PARTS = 10
HPW_DRIP_MAX = 32
HPW_DRIP_PER_IP = 2
HPW_DRIPS = {}


def hpw_bait(path=HPW_BAIT):
    """Read only planted values, never invent a credential or inspect host secrets."""
    try:
        with open(path, 'rb') as f:
            raw = f.read(HPW_MAX_BUNDLE + 1)
        if len(raw) > HPW_MAX_BUNDLE:
            return {}
        data = hpw_json.loads(raw)
        if not isinstance(data, dict) or len(data) > 256:
            return {}
        return {k: v for k, v in data.items()
                if isinstance(k, str) and len(k) <= 100 and isinstance(v, str)
                and hpw_re.fullmatch(r'[A-Za-z0-9/+_=!@#$%.,~\-]{8,160}', v)
                and not v.lower().startswith(('replace-', 'changeme'))}
    except (OSError, ValueError, RecursionError):
        return {}


def hpw_robots(identity):
    """Four stable paths, distinct across identities; not linked from other replies."""
    ident = identity['id']
    if not hpw_re.fullmatch(r'[a-z0-9-]{1,32}', ident):
        raise ValueError('Invalid web identity')
    tag = hpw_hashlib.sha256(('huginn-robots-v1:' + ident).encode()).hexdigest()[:10]
    if identity['kind'] == 'router':
        return ['/cgi-bin/diag-' + tag + '.cgi', '/config/archive-' + tag + '/',
                '/support/' + tag + '/status', '/admin/export-' + tag + '.cfg']
    return ['/backup/archive-' + tag + '/', '/maintenance/' + tag + '/status',
            '/config/export-' + tag + '.ini', '/storage/snapshot-' + tag + '/']


def hpw_build(identity, bait_path=HPW_BAIT):
    bait = hpw_bait(bait_path)
    paths = hpw_robots(identity)
    replies = {}
    def add(kind, body, ctype='text/plain; charset=utf-8'):
        if len(body.encode('utf-8')) > HPW_MAX_BODY:
            raise ValueError('Reply exceeds limit')
        replies[kind] = [ctype, body]
    if bait:
        def secret(*names):
            for name in names:
                for key in sorted(bait):
                    if key == name or key.endswith('_' + name):
                        return bait[key]
            return bait[sorted(bait)[0]]
        db = secret('env_db', 'nc_db', 'mysql_backup', 'nas_smb', 'cam_admin')
        redis = secret('redis')
        keyid = secret('aws_key_id', 'b2_key_id')
        aws = secret('aws_secret', 'b2_key')
        kind = 'gateway' if identity['kind'] == 'router' else 'storage'
        add('env', 'APP_ENV=production\nAPP_NAME=' + kind + '\nDB_HOST=127.0.0.1\nDB_DATABASE=device\nDB_USERNAME=backup\nDB_PASSWORD=' + db + '\nREDIS_PASSWORD=' + redis + '\n')
        add('git', '[core]\n\trepositoryformatversion = 0\n\tbare = false\n[remote "origin"]\n\turl = /srv/git/device-config.git\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n')
        add('git_head', 'ref: refs/heads/main\n')
        add('aws', '[default]\naws_access_key_id = ' + keyid + '\naws_secret_access_key = ' + aws + '\nregion = eu-north-1\n')
        add('aws_config', '[default]\nregion = eu-north-1\noutput = json\n')
        add('phpinfo', 'phpinfo()\nPHP Version => 7.4.33\nSystem => Linux device 4.19.0 armv7l\nServer API => CGI/FastCGI\nConfiguration File (php.ini) Path => /etc/php\nDOCUMENT_ROOT => /var/www\nDB_PASSWORD => ' + db + '\n')
        add('traversal', 'root:x:0:0:root:/root:/bin/sh\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\nbackup:x:1000:1000:Backup:/home/backup:/bin/sh\n')
        add('phpunit', 'uid=33(www-data) gid=33(www-data) groups=33(www-data)\n')
        add('mcp', hpw_json.dumps({'name': 'device-management', 'version': '1.0', 'capabilities': {'tools': {}}}, separators=(',', ':')), 'application/json')
        add('actuator', hpw_json.dumps({'activeProfiles': ['production'], 'propertySources': [{'name': 'applicationConfig', 'properties': {'device.mode': {'value': kind}, 'spring.datasource.password': {'value': db}}}]}, separators=(',', ':')), 'application/json')
        add('robots_backup', '[device]\nrole=' + kind + '\nusername=backup\npassword=' + db + '\n')
    return {'version': HPW_VERSION, 'identity': {'id': identity['id'], 'kind': identity['kind']},
            'robots': paths, 'replies': replies}


def hpw_write_skin(folder, identity, bait_path=HPW_BAIT):
    """Called as root. Publish identity metadata, never a persistent credential snapshot."""
    bundle = {'version': HPW_VERSION, 'identity': {'id': identity['id'], 'kind': identity['kind']},
              'robots': hpw_robots(identity), 'replies': {}}
    files = {HPW_BUNDLE: hpw_json.dumps(bundle, separators=(',', ':')),
             'robots.txt': 'User-agent: *\n' + ''.join('Disallow: ' + p + '\n' for p in bundle['robots'])}
    for name, text in files.items():
        path = hpw_os.path.join(folder, name)
        tmp = path + '.new'
        fd = hpw_os.open(tmp, hpw_os.O_WRONLY | hpw_os.O_CREAT | hpw_os.O_EXCL | hpw_os.O_NOFOLLOW, 0o644)
        try:
            with hpw_os.fdopen(fd, 'w', encoding='utf-8') as f:
                f.write(text)
            hpw_os.chmod(tmp, 0o644)
            hpw_os.replace(tmp, path)
        finally:
            if hpw_os.path.exists(tmp):
                hpw_os.unlink(tmp)


def hpw_load(factory):
    """Bounded bundle/bait reads once per second; bait metadata changes invalidate immediately."""
    now = hpw_time.monotonic()
    try:
        st = hpw_os.stat(HPW_BAIT)
        signature = (st.st_ino, st.st_mtime_ns, st.st_size, st.st_mode)
    except OSError:
        signature = None
    cached = getattr(factory, '_hpw_cache', None)
    if cached is not None and cached[0] > now and cached[2] == signature:
        return cached[1]
    data = {}
    try:
        with open(hpw_os.path.join(factory.skindir, HPW_BUNDLE), 'rb') as f:
            raw = f.read(HPW_MAX_BUNDLE + 1)
        if len(raw) <= HPW_MAX_BUNDLE:
            obj = hpw_json.loads(raw)
            if (isinstance(obj, dict) and obj.get('version') == HPW_VERSION
                    and isinstance(obj.get('robots'), list) and len(obj['robots']) == 4
                    and all(isinstance(p, str) and hpw_re.fullmatch(r'/[a-z0-9/_.-]{1,160}', p) for p in obj['robots'])
                    and isinstance(obj.get('identity'), dict)
                    and obj['identity'].get('kind') in ('nas', 'router')
                    and isinstance(obj['identity'].get('id'), str)
                    and hpw_re.fullmatch(r'[a-z0-9-]{1,32}', obj['identity']['id'])
                    and isinstance(obj.get('replies'), dict) and len(obj['replies']) <= 12):
                # Re-read the planted values, never trust a stale credential snapshot.
                data = hpw_build(obj['identity'], HPW_BAIT)
    except (OSError, ValueError, RecursionError):
        pass
    factory._hpw_cache = (now + 1.0, data, signature)
    return data


def hpw_target(uri):
    if not isinstance(uri, bytes) or len(uri) > HPW_MAX_URI:
        return None
    try:
        text = uri.decode('ascii')
        if not text.startswith('/') or text.startswith('//'):
            return None
        for _ in range(2):
            text = hpw_unquote(text)
        parts = hpw_urlsplit(text)
        if parts.scheme or parts.netloc:
            return None
        if any(ord(c) < 32 or ord(c) == 127 for c in text):
            return None
        return parts.path, parts.query
    except (ValueError, UnicodeError):
        return None


def hpw_kind(path, query):
    low = path.lower()
    if low.endswith('/.git/config'):
        return 'git'
    if low.endswith('/.git/head'):
        return 'git_head'
    if low.endswith('/.aws/credentials'):
        return 'aws'
    if low.endswith('/.aws/config'):
        return 'aws_config'
    if hpw_re.search(r'/(?:\.env)(?:\.[a-z0-9_-]{1,24}){0,3}$', low):
        return 'env'
    if hpw_re.search(r'/(?:phpinfo|info)\.php$', low):
        return 'phpinfo'
    if low.endswith('/vendor/phpunit/phpunit/src/util/php/eval-stdin.php') or low.endswith('/phpunit/src/util/php/eval-stdin.php'):
        return 'phpunit'
    combined = low + '?' + query.lower()
    if '/etc/passwd' in combined and ('../' in combined or hpw_re.search(r'(?:[?&])(?:file|path|page)=/?etc/passwd(?:&|$)', combined)):
        return 'traversal'
    if low in ('/mcp', '/mcp/'):
        return 'mcp'
    if low in ('/actuator/env', '/actuator/env/'):
        return 'actuator'
    return None


def hpw_reply(factory, uri, method, body=b''):
    """Return (reply_type, body, content_type, robots_hit), or an empty reply."""
    target = hpw_target(uri)
    if target is None:
        return None, None, None, False
    path, query = target
    bundle = hpw_load(factory)
    robots = bundle.get('robots', [])
    hit = any(path == p or (p.endswith('/') and path.startswith(p)) for p in robots)
    if method not in (b'GET', b'HEAD', b'POST', b'PUT'):
        return None, None, None, hit
    if path == '/robots.txt' and method in (b'GET', b'HEAD') and robots:
        payload = 'User-agent: *\n' + ''.join('Disallow: ' + p + '\n' for p in robots)
        return None, payload.encode(), 'text/plain; charset=utf-8', False
    kind = 'robots_backup' if hit else hpw_kind(path, query)
    entry = bundle.get('replies', {}).get(kind)
    if not isinstance(entry, list) or len(entry) != 2:
        return None, None, None, hit
    ctype, payload = entry
    if ctype not in ('text/plain; charset=utf-8', 'application/json') or not isinstance(payload, str):
        return None, None, None, hit
    if not hpw_re.fullmatch('[a-z_]{1,20}', kind):
        return None, None, None, hit
    if kind == 'mcp' and method == b'POST':
        if len(body) > 500:
            return None, None, None, hit
        try:
            rpc = hpw_json.loads(body)
            if not isinstance(rpc, dict) or rpc.get('jsonrpc') != '2.0':
                return None, None, None, hit
            rid = rpc.get('id')
            if not (type(rid) is int or isinstance(rid, str)) or len(str(rid)) > 64:
                return None, None, None, hit
            if rpc.get('method') == 'initialize':
                result = {'protocolVersion': '2024-11-05', 'capabilities': {'tools': {}}, 'serverInfo': {'name': 'device-management', 'version': '1.0'}}
            elif rpc.get('method') == 'tools/list':
                result = {'tools': [{'name': 'device_status', 'description': 'Read device status', 'inputSchema': {'type': 'object', 'properties': {}}}]}
            else:
                payload = hpw_json.dumps({'jsonrpc': '2.0', 'id': rid, 'error': {'code': -32601, 'message': 'Method not found'}})
                result = None
            if result is not None:
                payload = hpw_json.dumps({'jsonrpc': '2.0', 'id': rid, 'result': result})
        except (ValueError, RecursionError):
            return None, None, None, hit
    raw = payload.encode('utf-8')
    if len(raw) > HPW_MAX_BODY:
        return None, None, None, hit
    return kind, raw, ctype, hit


def hpw_drip_ok(kind, method, ip):
    """Only a GET of a chosen export, and only while there is room; otherwise the fast reply as before."""
    return (kind in HPW_DRIP_KINDS and method == b'GET' and isinstance(ip, str)
            and sum(HPW_DRIPS.values()) < HPW_DRIP_MAX and HPW_DRIPS.get(ip, 0) < HPW_DRIP_PER_IP)


def hpw_drip(request, payload, ip, ended, reactor=None):
    """Send payload in small parts over HPW_DRIP_SECS without blocking the reactor. ended(how, secs) runs exactly once:
    "done" when the whole reply was handed to the connection and finished, "gone" when the client left first."""
    if reactor is None:
        from twisted.internet import reactor
    from twisted.web.server import NOT_DONE_YET
    size = max(1, -(-len(payload) // HPW_DRIP_PARTS))
    parts = [payload[i:i + size] for i in range(0, len(payload), size)] or [b'']
    step = HPW_DRIP_SECS / len(parts)
    start = hpw_time.monotonic()
    state = {'call': None, 'open': True}
    HPW_DRIPS[ip] = HPW_DRIPS.get(ip, 0) + 1

    def close(how):
        if not state['open']:
            return
        state['open'] = False
        if state['call'] is not None and state['call'].active():
            state['call'].cancel()
        state['call'] = None
        left = HPW_DRIPS.get(ip, 1) - 1
        if left > 0:
            HPW_DRIPS[ip] = left
        else:
            HPW_DRIPS.pop(ip, None)
        try:
            ended(how, round(hpw_time.monotonic() - start, 1))
        except Exception:
            pass

    def lost(_result):
        close('gone')   # the client hung up before the last byte

    def tick(i):
        state['call'] = None
        if not state['open']:
            return
        try:
            request.write(parts[i])
            if i + 1 < len(parts):
                state['call'] = reactor.callLater(step, tick, i + 1)
                return
            request.finish()
            close('done')
        except Exception:
            close('gone')

    try:
        request.notifyFinish().addErrback(lost)
    except Exception:
        close('gone')    # nothing was sent yet: free the slot, the caller answers at once instead
        raise
    tick(0)          # headers and the first part at once, the rest slowly
    return NOT_DONE_YET
