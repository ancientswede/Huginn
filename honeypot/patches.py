#!/usr/bin/env python3
# patches.py — small local patches Huginn applies to Cowrie and OpenCanary (part of Huginn, AGPL-3.0-or-later).
# Used by install-honeypot.sh and update-honeypot.sh, so an upgrade of Cowrie/OpenCanary gets them back.
#
#   patches.py cowrie-free FILE        Cowrie's "free" reads the persona's fake /proc/meminfo, not the host's
#   patches.py opencanary-http FILE    OpenCanary logs every probed web path (it never logged 404s)
#   patches.py opencanary-ports CONF   move disabled OpenCanary modules off ports used by enabled ones
#   patches.py cowrie-forward FILE     Cowrie answers a plain HTTP proxy check with 200 and holds TLS for a while (never forwards)
#   patches.py cowrie-ping FILE        Cowrie's ping accepts "-c N" (upstream bug: every "ping -c 1 host" failed)
#   patches.py cowrie-upload DIR       a file uploaded over SFTP/scp is still there for the next command (DIR = src/cowrie)
#   patches.py cowrie-wget FILE        wget prints what a real wget prints (BusyBox on the camera, no early "connected")
#   patches.py cowrie-exec FILE        an uploaded program for this CPU "runs" silently and is logged (nothing is executed)
#
# Exit code: 0 = patched/changed, 3 = already patched/nothing to do, 1 = the upstream code changed (not patched).
import hashlib, json, sys

# The exact upstream code and its replacement (kept at top level: indentation inside these strings matters).
FREE_OLD = '''        try:
            with open("/proc/meminfo") as proc_file:
                for line in proc_file:'''
FREE_NEW = '''        try:
            # Huginn patch: read the persona's fake /proc/meminfo (honeyfs) first, the host's real one only as fallback.
            try:
                lines = self.fs.file_contents("/proc/meminfo").decode("utf-8", "replace").splitlines()
            except Exception:
                with open("/proc/meminfo") as real_file:
                    lines = real_file.read().splitlines()
            if True:
                for line in lines:'''
FREE_OLD2 = '''        # Got a map with all tokens from /proc/meminfo and sizes in KBs
        return mem_info_map'''
FREE_NEW2 = '''        for k in ("MemTotal", "MemFree", "Buffers", "Cached", "SwapTotal", "SwapFree", "Shmem"):
            mem_info_map.setdefault(k, 0)
        mem_info_map.setdefault("MemAvailable", mem_info_map["MemFree"] + mem_info_map["Cached"] + mem_info_map["Buffers"])
        # Got a map with all tokens from /proc/meminfo and sizes in KBs
        return mem_info_map'''

HTTP_OLD = """    def render(self, request):
        request.setHeader(b"Server", self.factory.banner)
        request.setResponseCode(int(self.error_code))
        return Resource.render(self, request)"""
HTTP_LEGACY = '    def render(self, request):\n        # Huginn patch: log every probed path. Scanners mostly ask for paths that do not exist (404),\n        # which OpenCanary never logged, so the most interesting web traffic was invisible.\n        try:\n            ua = request.getHeader("user-agent") or "<not supplied>"\n            logdata = {"PATH": request.uri.decode("utf-8", "replace")[:500],\n                       "METHOD": request.method.decode("ascii", "replace")[:10],\n                       "STATUS": self.error_code, "USERAGENT": ua}\n            if request.method in (b"POST", b"PUT") and request.content is not None:\n                request.content.seek(0)\n                body = request.content.read(500)\n                request.content.seek(0)\n                if body:\n                    logdata["BODY"] = body.decode("utf-8", "replace")\n            self.factory.log(logdata, transport=request.transport, logtype=self.factory.logger.LOG_HTTP_GET)\n        except Exception:\n            pass\n        request.setHeader(b"Server", self.factory.banner)\n        request.setResponseCode(int(self.error_code))\n        return Resource.render(self, request)'
HTTP_NEW = '    def render(self, request):\n        # Huginn webreply v2: bounded, inert replies, one log record per request, a slow robots export.\n        payload, reply_type, ctype, robots, slow, ip = None, None, None, False, False, None\n        body = b""\n        try:\n            if request.method in (b"POST", b"PUT") and request.content is not None:\n                request.content.seek(0)\n                body = request.content.read(500)\n                request.content.seek(0)\n            if str(self.error_code) == "404":\n                reply_type, payload, ctype, robots = hpw_reply(self.factory, request.uri, request.method, body)\n        except Exception:\n            pass\n        status = 200 if payload is not None else int(self.error_code)\n        if payload is not None and reply_type is not None:\n            try:\n                ip = request.getClientAddress().host\n                slow = hpw_drip_ok(reply_type, request.method, ip)\n            except Exception:\n                slow = False\n        request.setHeader(b"Server", self.factory.banner)\n        request.setResponseCode(status)\n        if payload is not None:\n            request.setHeader(b"Content-Type", ctype.encode("ascii"))\n            request.setHeader(b"X-Content-Type-Options", b"nosniff")\n            request.setHeader(b"Content-Security-Policy", b"default-src \'none\'; sandbox")\n            request.setHeader(b"Cache-Control", b"no-store")\n            request.setHeader(b"Content-Length", str(len(payload)).encode("ascii"))\n        try:\n            ua = request.getHeader("user-agent") or "<not supplied>"\n            logdata = {"PATH": request.uri.decode("utf-8", "replace")[:500],\n                       "METHOD": request.method.decode("ascii", "replace")[:10],\n                       "STATUS": status, "USERAGENT": ua[:500]}\n            if body:\n                logdata["BODY"] = body.decode("utf-8", "replace")\n            if reply_type is not None and payload is not None:\n                logdata["HP_REPLY"] = reply_type\n            if robots:\n                logdata["HP_ROBOTS"] = "1"\n            if slow:\n                logdata["HP_SLOW"] = "1"\n            self.factory.log(logdata, transport=request.transport, logtype=self.factory.logger.LOG_HTTP_GET)\n        except Exception:\n            pass\n        if payload is not None:\n            if slow:\n                factory, path, method = self.factory, request.uri.decode("utf-8", "replace")[:500], request.method.decode("ascii", "replace")[:10]\n                # The socket may be closed by the time the export ends, so keep the addresses now.\n                us, peer = request.transport.getHost(), request.transport.getPeer()\n                where = {"src_host": peer.host, "src_port": peer.port, "dst_host": us.host, "dst_port": us.port}\n                def ended(how, secs):\n                    # A second record: did the client wait for the whole slow export ("done") or hang up ("gone")?\n                    factory.log({"PATH": path, "METHOD": method, "HP_DRIP": how, "HP_DRIP_SECS": secs},\n                                logtype=factory.logger.LOG_HTTP_GET, **where)\n                try:\n                    return hpw_drip(request, payload, ip, ended)\n                except Exception:\n                    pass\n            return b"" if request.method == b"HEAD" else payload\n        return Resource.render(self, request)'
HTTP_HELPER = '# Bounded, inert web deception for Huginn. No network calls or request evaluation.\nimport hashlib as hpw_hashlib\nimport json as hpw_json\nimport os as hpw_os\nimport re as hpw_re\nimport time as hpw_time\nfrom urllib.parse import unquote as hpw_unquote, urlsplit as hpw_urlsplit\n\nHPW_VERSION = 1\nHPW_MAX_URI = 2048\nHPW_MAX_BODY = 4096\nHPW_MAX_BUNDLE = 65536\nHPW_BUNDLE = \'webreply.json\'\nHPW_BAIT = \'/etc/huginn-honeypot/bait.json\'\n# Slow export: the robots-only backup file trickles out like a slow device. Bounded so it can never tie up the honeypot.\nHPW_DRIP_KINDS = (\'robots_backup\',)\nHPW_DRIP_SECS = 5.0\nHPW_DRIP_PARTS = 10\nHPW_DRIP_MAX = 32\nHPW_DRIP_PER_IP = 2\nHPW_DRIPS = {}\n\n\ndef hpw_bait(path=HPW_BAIT):\n    """Read only planted values, never invent a credential or inspect host secrets."""\n    try:\n        with open(path, \'rb\') as f:\n            raw = f.read(HPW_MAX_BUNDLE + 1)\n        if len(raw) > HPW_MAX_BUNDLE:\n            return {}\n        data = hpw_json.loads(raw)\n        if not isinstance(data, dict) or len(data) > 256:\n            return {}\n        return {k: v for k, v in data.items()\n                if isinstance(k, str) and len(k) <= 100 and isinstance(v, str)\n                and hpw_re.fullmatch(r\'[A-Za-z0-9/+_=!@#$%.,~\\-]{8,160}\', v)\n                and not v.lower().startswith((\'replace-\', \'changeme\'))}\n    except (OSError, ValueError, RecursionError):\n        return {}\n\n\ndef hpw_robots(identity):\n    """Four stable paths, distinct across identities; not linked from other replies."""\n    ident = identity[\'id\']\n    if not hpw_re.fullmatch(r\'[a-z0-9-]{1,32}\', ident):\n        raise ValueError(\'Invalid web identity\')\n    tag = hpw_hashlib.sha256((\'huginn-robots-v1:\' + ident).encode()).hexdigest()[:10]\n    if identity[\'kind\'] == \'router\':\n        return [\'/cgi-bin/diag-\' + tag + \'.cgi\', \'/config/archive-\' + tag + \'/\',\n                \'/support/\' + tag + \'/status\', \'/admin/export-\' + tag + \'.cfg\']\n    return [\'/backup/archive-\' + tag + \'/\', \'/maintenance/\' + tag + \'/status\',\n            \'/config/export-\' + tag + \'.ini\', \'/storage/snapshot-\' + tag + \'/\']\n\n\ndef hpw_build(identity, bait_path=HPW_BAIT):\n    bait = hpw_bait(bait_path)\n    paths = hpw_robots(identity)\n    replies = {}\n    def add(kind, body, ctype=\'text/plain; charset=utf-8\'):\n        if len(body.encode(\'utf-8\')) > HPW_MAX_BODY:\n            raise ValueError(\'Reply exceeds limit\')\n        replies[kind] = [ctype, body]\n    if bait:\n        def secret(*names):\n            for name in names:\n                for key in sorted(bait):\n                    if key == name or key.endswith(\'_\' + name):\n                        return bait[key]\n            return bait[sorted(bait)[0]]\n        db = secret(\'env_db\', \'nc_db\', \'mysql_backup\', \'nas_smb\', \'cam_admin\')\n        redis = secret(\'redis\')\n        keyid = secret(\'aws_key_id\', \'b2_key_id\')\n        aws = secret(\'aws_secret\', \'b2_key\')\n        kind = \'gateway\' if identity[\'kind\'] == \'router\' else \'storage\'\n        add(\'env\', \'APP_ENV=production\\nAPP_NAME=\' + kind + \'\\nDB_HOST=127.0.0.1\\nDB_DATABASE=device\\nDB_USERNAME=backup\\nDB_PASSWORD=\' + db + \'\\nREDIS_PASSWORD=\' + redis + \'\\n\')\n        add(\'git\', \'[core]\\n\\trepositoryformatversion = 0\\n\\tbare = false\\n[remote "origin"]\\n\\turl = /srv/git/device-config.git\\n\\tfetch = +refs/heads/*:refs/remotes/origin/*\\n\')\n        add(\'git_head\', \'ref: refs/heads/main\\n\')\n        add(\'aws\', \'[default]\\naws_access_key_id = \' + keyid + \'\\naws_secret_access_key = \' + aws + \'\\nregion = eu-north-1\\n\')\n        add(\'aws_config\', \'[default]\\nregion = eu-north-1\\noutput = json\\n\')\n        add(\'phpinfo\', \'phpinfo()\\nPHP Version => 7.4.33\\nSystem => Linux device 4.19.0 armv7l\\nServer API => CGI/FastCGI\\nConfiguration File (php.ini) Path => /etc/php\\nDOCUMENT_ROOT => /var/www\\nDB_PASSWORD => \' + db + \'\\n\')\n        add(\'traversal\', \'root:x:0:0:root:/root:/bin/sh\\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\\nbackup:x:1000:1000:Backup:/home/backup:/bin/sh\\n\')\n        add(\'phpunit\', \'uid=33(www-data) gid=33(www-data) groups=33(www-data)\\n\')\n        add(\'mcp\', hpw_json.dumps({\'name\': \'device-management\', \'version\': \'1.0\', \'capabilities\': {\'tools\': {}}}, separators=(\',\', \':\')), \'application/json\')\n        add(\'actuator\', hpw_json.dumps({\'activeProfiles\': [\'production\'], \'propertySources\': [{\'name\': \'applicationConfig\', \'properties\': {\'device.mode\': {\'value\': kind}, \'spring.datasource.password\': {\'value\': db}}}]}, separators=(\',\', \':\')), \'application/json\')\n        add(\'robots_backup\', \'[device]\\nrole=\' + kind + \'\\nusername=backup\\npassword=\' + db + \'\\n\')\n    return {\'version\': HPW_VERSION, \'identity\': {\'id\': identity[\'id\'], \'kind\': identity[\'kind\']},\n            \'robots\': paths, \'replies\': replies}\n\n\ndef hpw_write_skin(folder, identity, bait_path=HPW_BAIT):\n    """Called as root. Publish identity metadata, never a persistent credential snapshot."""\n    bundle = {\'version\': HPW_VERSION, \'identity\': {\'id\': identity[\'id\'], \'kind\': identity[\'kind\']},\n              \'robots\': hpw_robots(identity), \'replies\': {}}\n    files = {HPW_BUNDLE: hpw_json.dumps(bundle, separators=(\',\', \':\')),\n             \'robots.txt\': \'User-agent: *\\n\' + \'\'.join(\'Disallow: \' + p + \'\\n\' for p in bundle[\'robots\'])}\n    for name, text in files.items():\n        path = hpw_os.path.join(folder, name)\n        tmp = path + \'.new\'\n        fd = hpw_os.open(tmp, hpw_os.O_WRONLY | hpw_os.O_CREAT | hpw_os.O_EXCL | hpw_os.O_NOFOLLOW, 0o644)\n        try:\n            with hpw_os.fdopen(fd, \'w\', encoding=\'utf-8\') as f:\n                f.write(text)\n            hpw_os.chmod(tmp, 0o644)\n            hpw_os.replace(tmp, path)\n        finally:\n            if hpw_os.path.exists(tmp):\n                hpw_os.unlink(tmp)\n\n\ndef hpw_load(factory):\n    """Bounded bundle/bait reads once per second; bait metadata changes invalidate immediately."""\n    now = hpw_time.monotonic()\n    try:\n        st = hpw_os.stat(HPW_BAIT)\n        signature = (st.st_ino, st.st_mtime_ns, st.st_size, st.st_mode)\n    except OSError:\n        signature = None\n    cached = getattr(factory, \'_hpw_cache\', None)\n    if cached is not None and cached[0] > now and cached[2] == signature:\n        return cached[1]\n    data = {}\n    try:\n        with open(hpw_os.path.join(factory.skindir, HPW_BUNDLE), \'rb\') as f:\n            raw = f.read(HPW_MAX_BUNDLE + 1)\n        if len(raw) <= HPW_MAX_BUNDLE:\n            obj = hpw_json.loads(raw)\n            if (isinstance(obj, dict) and obj.get(\'version\') == HPW_VERSION\n                    and isinstance(obj.get(\'robots\'), list) and len(obj[\'robots\']) == 4\n                    and all(isinstance(p, str) and hpw_re.fullmatch(r\'/[a-z0-9/_.-]{1,160}\', p) for p in obj[\'robots\'])\n                    and isinstance(obj.get(\'identity\'), dict)\n                    and obj[\'identity\'].get(\'kind\') in (\'nas\', \'router\')\n                    and isinstance(obj[\'identity\'].get(\'id\'), str)\n                    and hpw_re.fullmatch(r\'[a-z0-9-]{1,32}\', obj[\'identity\'][\'id\'])\n                    and isinstance(obj.get(\'replies\'), dict) and len(obj[\'replies\']) <= 12):\n                # Re-read the planted values, never trust a stale credential snapshot.\n                data = hpw_build(obj[\'identity\'], HPW_BAIT)\n    except (OSError, ValueError, RecursionError):\n        pass\n    factory._hpw_cache = (now + 1.0, data, signature)\n    return data\n\n\ndef hpw_target(uri):\n    if not isinstance(uri, bytes) or len(uri) > HPW_MAX_URI:\n        return None\n    try:\n        text = uri.decode(\'ascii\')\n        if not text.startswith(\'/\') or text.startswith(\'//\'):\n            return None\n        for _ in range(2):\n            text = hpw_unquote(text)\n        parts = hpw_urlsplit(text)\n        if parts.scheme or parts.netloc:\n            return None\n        if any(ord(c) < 32 or ord(c) == 127 for c in text):\n            return None\n        return parts.path, parts.query\n    except (ValueError, UnicodeError):\n        return None\n\n\ndef hpw_kind(path, query):\n    low = path.lower()\n    if low.endswith(\'/.git/config\'):\n        return \'git\'\n    if low.endswith(\'/.git/head\'):\n        return \'git_head\'\n    if low.endswith(\'/.aws/credentials\'):\n        return \'aws\'\n    if low.endswith(\'/.aws/config\'):\n        return \'aws_config\'\n    if hpw_re.search(r\'/(?:\\.env)(?:\\.[a-z0-9_-]{1,24}){0,3}$\', low):\n        return \'env\'\n    if hpw_re.search(r\'/(?:phpinfo|info)\\.php$\', low):\n        return \'phpinfo\'\n    if low.endswith(\'/vendor/phpunit/phpunit/src/util/php/eval-stdin.php\') or low.endswith(\'/phpunit/src/util/php/eval-stdin.php\'):\n        return \'phpunit\'\n    combined = low + \'?\' + query.lower()\n    if \'/etc/passwd\' in combined and (\'../\' in combined or hpw_re.search(r\'(?:[?&])(?:file|path|page)=/?etc/passwd(?:&|$)\', combined)):\n        return \'traversal\'\n    if low in (\'/mcp\', \'/mcp/\'):\n        return \'mcp\'\n    if low in (\'/actuator/env\', \'/actuator/env/\'):\n        return \'actuator\'\n    return None\n\n\ndef hpw_reply(factory, uri, method, body=b\'\'):\n    """Return (reply_type, body, content_type, robots_hit), or an empty reply."""\n    target = hpw_target(uri)\n    if target is None:\n        return None, None, None, False\n    path, query = target\n    bundle = hpw_load(factory)\n    robots = bundle.get(\'robots\', [])\n    hit = any(path == p or (p.endswith(\'/\') and path.startswith(p)) for p in robots)\n    if method not in (b\'GET\', b\'HEAD\', b\'POST\', b\'PUT\'):\n        return None, None, None, hit\n    if path == \'/robots.txt\' and method in (b\'GET\', b\'HEAD\') and robots:\n        payload = \'User-agent: *\\n\' + \'\'.join(\'Disallow: \' + p + \'\\n\' for p in robots)\n        return None, payload.encode(), \'text/plain; charset=utf-8\', False\n    kind = \'robots_backup\' if hit else hpw_kind(path, query)\n    entry = bundle.get(\'replies\', {}).get(kind)\n    if not isinstance(entry, list) or len(entry) != 2:\n        return None, None, None, hit\n    ctype, payload = entry\n    if ctype not in (\'text/plain; charset=utf-8\', \'application/json\') or not isinstance(payload, str):\n        return None, None, None, hit\n    if not hpw_re.fullmatch(\'[a-z_]{1,20}\', kind):\n        return None, None, None, hit\n    if kind == \'mcp\' and method == b\'POST\':\n        if len(body) > 500:\n            return None, None, None, hit\n        try:\n            rpc = hpw_json.loads(body)\n            if not isinstance(rpc, dict) or rpc.get(\'jsonrpc\') != \'2.0\':\n                return None, None, None, hit\n            rid = rpc.get(\'id\')\n            if not (type(rid) is int or isinstance(rid, str)) or len(str(rid)) > 64:\n                return None, None, None, hit\n            if rpc.get(\'method\') == \'initialize\':\n                result = {\'protocolVersion\': \'2024-11-05\', \'capabilities\': {\'tools\': {}}, \'serverInfo\': {\'name\': \'device-management\', \'version\': \'1.0\'}}\n            elif rpc.get(\'method\') == \'tools/list\':\n                result = {\'tools\': [{\'name\': \'device_status\', \'description\': \'Read device status\', \'inputSchema\': {\'type\': \'object\', \'properties\': {}}}]}\n            else:\n                payload = hpw_json.dumps({\'jsonrpc\': \'2.0\', \'id\': rid, \'error\': {\'code\': -32601, \'message\': \'Method not found\'}})\n                result = None\n            if result is not None:\n                payload = hpw_json.dumps({\'jsonrpc\': \'2.0\', \'id\': rid, \'result\': result})\n        except (ValueError, RecursionError):\n            return None, None, None, hit\n    raw = payload.encode(\'utf-8\')\n    if len(raw) > HPW_MAX_BODY:\n        return None, None, None, hit\n    return kind, raw, ctype, hit\n\n\ndef hpw_drip_ok(kind, method, ip):\n    """Only a GET of a chosen export, and only while there is room; otherwise the fast reply as before."""\n    return (kind in HPW_DRIP_KINDS and method == b\'GET\' and isinstance(ip, str)\n            and sum(HPW_DRIPS.values()) < HPW_DRIP_MAX and HPW_DRIPS.get(ip, 0) < HPW_DRIP_PER_IP)\n\n\ndef hpw_drip(request, payload, ip, ended, reactor=None):\n    """Send payload in small parts over HPW_DRIP_SECS without blocking the reactor. ended(how, secs) runs exactly once:\n    "done" when the whole reply was handed to the connection and finished, "gone" when the client left first."""\n    if reactor is None:\n        from twisted.internet import reactor\n    from twisted.web.server import NOT_DONE_YET\n    size = max(1, -(-len(payload) // HPW_DRIP_PARTS))\n    parts = [payload[i:i + size] for i in range(0, len(payload), size)] or [b\'\']\n    step = HPW_DRIP_SECS / len(parts)\n    start = hpw_time.monotonic()\n    state = {\'call\': None, \'open\': True}\n    HPW_DRIPS[ip] = HPW_DRIPS.get(ip, 0) + 1\n\n    def close(how):\n        if not state[\'open\']:\n            return\n        state[\'open\'] = False\n        if state[\'call\'] is not None and state[\'call\'].active():\n            state[\'call\'].cancel()\n        state[\'call\'] = None\n        left = HPW_DRIPS.get(ip, 1) - 1\n        if left > 0:\n            HPW_DRIPS[ip] = left\n        else:\n            HPW_DRIPS.pop(ip, None)\n        try:\n            ended(how, round(hpw_time.monotonic() - start, 1))\n        except Exception:\n            pass\n\n    def lost(_result):\n        close(\'gone\')   # the client hung up before the last byte\n\n    def tick(i):\n        state[\'call\'] = None\n        if not state[\'open\']:\n            return\n        try:\n            request.write(parts[i])\n            if i + 1 < len(parts):\n                state[\'call\'] = reactor.callLater(step, tick, i + 1)\n                return\n            request.finish()\n            close(\'done\')\n        except Exception:\n            close(\'gone\')\n\n    try:\n        request.notifyFinish().addErrback(lost)\n    except Exception:\n        close(\'gone\')    # nothing was sent yet: free the slot, the caller answers at once instead\n        raise\n    tick(0)          # headers and the first part at once, the rest slowly\n    return NOT_DONE_YET\n'
# Earlier Huginn web patches (render + helper), recognised so an update can replace them: 0.25.0 and 0.27.0.
HTTP_KNOWN = {'81d3c3c7bdf5e9b93a580de6c1ae0d7720eb2dbe61e08692a57a7101e126cd67', 'f7bcca555c760438aa4d7b235acd2f4513b8d5b47eef735012f32332572bb07c'}
HTTP_ROUTE = '        root.putChild(b"robots.txt", Error(factory=self))\n'


def patch(path, pairs):
    s = open(path).read()
    if "Huginn patch" in s:
        return 3
    for old, _new in pairs:
        if s.count(old) != 1:
            return 1
    open(path + ".orig", "w").write(s)
    for old, new in pairs:
        s = s.replace(old, new)
    open(path, "w").write(s)
    return 0


def cowrie_free(path):
    return patch(path, [(FREE_OLD, FREE_NEW), (FREE_OLD2, FREE_NEW2)])


def known_web_patch(original, current, route, suffix):
    # current == upstream with an earlier Huginn render (X) and helper (H) put in, and nothing else changed?
    pre, _, post = original.partition(HTTP_OLD)
    post = post.replace(route, route + HTTP_ROUTE)
    if not current.startswith(pre):
        return False
    i = current.find(post + suffix[:suffix.index('\n', 1) + 1], len(pre))
    if i < 0:
        return False
    render, helper = current[len(pre):i], current[i + len(post) + suffix.index('\n', 1) + 1:]
    return hashlib.sha256((render + "\0" + helper).encode()).hexdigest() in HTTP_KNOWN


def opencanary_http(path):
    # Only replace a known old patch; reject unknown local changes without touching files.
    from pathlib import Path
    target = Path(path)
    current = target.read_text()
    route = '        root.putChild(b"index.html", page)\n'
    suffix = '\n# Huginn webreply helper v1\n' + HTTP_HELPER
    def changed(original):
        if original.count(HTTP_OLD) != 1 or original.count(route) != 1:
            return None
        result = original.replace(HTTP_OLD, HTTP_NEW).replace(route, route + HTTP_ROUTE) + suffix
        compile(result, str(target), 'exec')
        return result
    backup = Path(path + '.orig')
    if 'Huginn webreply v' in current or 'Huginn patch' in current:
        if not backup.is_file():
            return 1
        original = backup.read_text()
        desired = changed(original)
        if desired is None:
            return 1
        if current == desired:
            return 3
        legacy = original.replace(HTTP_OLD, HTTP_LEGACY)
        if current != legacy and not known_web_patch(original, current, route, suffix):
            return 1
    else:
        original = current
        desired = changed(original)
        if desired is None:
            return 1
        # A package upgrade can leave an old .orig behind: refresh it from the new upstream.
        backup.write_text(original)
    target.write_text(desired)
    return 0

# Cowrie's fake SSH proxy (direct-tcpip) logs the first data and answers "Connection refused". Most logged-in bots
# only came to use the box as a proxy, so they test it (GET yahoo.com/ ...) and leave. The patch answers such a plain
# HTTP check with an empty 200 page and holds TLS silently for a while. Nothing is ever forwarded or connected.
FWD_OLD = """                data=repr(data),
                id=self.id,
            )
        self._close("Connection refused")"""
FWD_NEW = """                data=repr(data),
                id=self.id,
            )
        # Huginn proxyreply v2: answer a plain HTTP proxy check, hold TLS for a while; never connect anywhere.
        try:
            reply = hp_proxy_reply(self.hostport[1], data)
        except Exception:
            reply = None
        if reply is None:
            self._close("Connection refused")
            return
        self._hp_answered = True
        if events:
            events.dispatch(
                "cowrie.direct-tcpip.hp-reply",
                "huginn: answered direct-tcp forward request %(id)s to %(dst_ip)s:%(dst_port)s with %(hp_reply)s",
                dst_ip=self.hostport[0],
                dst_port=self.hostport[1],
                hp_reply=reply[0],
                hp_request=reply[2],
                id=self.id,
            )
        if reply[0] == "hold":
            hp_hold(self)
            return
        self.write(reply[1])
        self.loseConnection()"""
# Once answered (or while TLS is held), more data on the channel is ignored before Cowrie fingerprints and logs it.
FWD_TOP_OLD = """        events = self.conn.transport.events  # type: ignore[union-attr]
        # Try to fingerprint the forwarded traffic
"""
FWD_TOP_NEW = """        # Huginn proxyreply v2: after the answer, or while TLS is held, the rest is not fingerprinted or logged again.
        if getattr(self, "_hp_answered", False):
            return
        events = self.conn.transport.events  # type: ignore[union-attr]
        # Try to fingerprint the forwarded traffic
"""
FWD_HELPER = r"""
# Huginn proxyreply helper v2. Pure parsing; no network calls, no evaluation of what the client sent.
import re as hp_re
from email.utils import formatdate as hp_formatdate

HP_HOLD_SECS = 30
HP_HOLD_MAX = 64
HP_HOLDS = [0]
HP_REQUEST = hp_re.compile(rb"(GET|HEAD|POST) (/[\x21-\x7e]{0,2047}|http://[\x21-\x7e]{1,2040}) HTTP/1\.[01]\r?\n")
HP_HOST = hp_re.compile(rb"\nhost:[ \t]*([A-Za-z0-9.-]{1,253})(?::[0-9]{1,5})?\r?\n", hp_re.I)


def hp_proxy_reply(port, data):
    # (kind, bytes to send, short request text) or None for the old "Connection refused".
    if not isinstance(data, bytes):
        return None
    if port == 80:
        m = HP_REQUEST.match(data[:4096])
        if not m:
            return None
        h = HP_HOST.search(data[:4096])
        host = h.group(1).decode("ascii").lower().strip(".") if h else ""
        path = m.group(2).decode("ascii")
        if path.startswith("http://"):
            rest = path[7:]
            host = host or rest.split("/", 1)[0].split(":", 1)[0].lower()
            path = "/" + rest.split("/", 1)[1] if "/" in rest else "/"
        page = ('<!DOCTYPE html>\n<html><head><meta charset="utf-8"><title>%s</title></head><body></body></html>\n' % host).encode("ascii")
        head = ("HTTP/1.1 200 OK\r\nDate: %s\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: %d\r\n"
                "Cache-Control: no-store\r\nConnection: close\r\n\r\n" % (hp_formatdate(usegmt=True), len(page))).encode("ascii")
        method = m.group(1).decode("ascii")
        return ("http200", head + (b"" if method == "HEAD" else page), ("%s %s%s" % (method, host or "?", path))[:200])
    if port == 443 and data[:1] == b"\x16" and HP_HOLDS[0] < HP_HOLD_MAX:
        return ("hold", b"", "TLS")
    return None


def hp_hold(channel, reactor=None):
    # Say nothing until the client gives up or HP_HOLD_SECS pass, like a slow upstream; then close.
    # The slot is freed as soon as the channel closes, not only when the timer runs out.
    if reactor is None:
        from twisted.internet import reactor
    state = {"held": True, "call": None}
    HP_HOLDS[0] += 1

    def release():
        if state["held"]:
            state["held"] = False
            HP_HOLDS[0] = max(0, HP_HOLDS[0] - 1)
        call = state["call"]
        if call is not None and call.active():
            call.cancel()

    def done():
        state["call"] = None
        release()
        try:
            channel.loseConnection()
        except Exception:
            pass

    upstream_closed = channel.closed

    def closed():
        release()
        return upstream_closed()

    channel.closed = closed
    try:
        state["call"] = reactor.callLater(HP_HOLD_SECS, done)
    except Exception:
        release()
        raise
"""
# Earlier proxy patches (one replaced block + the helper appended), recognised so an update can replace them.
FWD_KNOWN = {'9d2a593633c4c01c3dabbe4d11e9adf5a557587b003c79f7e252e509521335e1'}


def write_group(changes):
    # changes = {path: (text read before, new text[, upstream text])}. Every file gets "path.orig" (the upstream text,
    # by default the text read before) and the new text, or nothing changes: all files are staged next to their targets, then swapped in with os.replace (which
    # replaces a symlink itself instead of writing through it). Returns 0, or 1 when nothing was changed.
    import os
    import tempfile
    staged = []
    try:
        for path, (old, new, *orig) in changes.items():
            if os.path.islink(path) or not os.path.isfile(path):
                raise OSError("not a regular file: %s" % path)
            with open(path) as f:
                if f.read() != old:
                    raise OSError("changed while patching: %s" % path)
            mode = os.stat(path).st_mode & 0o7777
            for target, text in ((path + ".orig", orig[0] if orig else old), (path, new)):
                fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path) or ".", prefix=".huginn-")
                staged.append((tmp, target, path))
                with os.fdopen(fd, "w") as f:
                    f.write(text)
                os.chmod(tmp, mode)
    except OSError:
        for tmp, _target, _path in staged:
            try:
                os.unlink(tmp)
            except OSError:
                pass
        return 1
    # What each target held before (None: it did not exist, or was a link), to put back on failure.
    before = {}
    for _tmp, target, _path in staged:
        try:
            before[target] = None if os.path.islink(target) else open(target).read()
        except OSError:
            before[target] = None
    done = []
    try:
        for tmp, target, path in staged:
            os.replace(tmp, target)
            done.append(target)
    except OSError:
        # Put back what was already swapped in, so no file is left half patched.
        for target in done:
            try:
                if before[target] is None:
                    os.unlink(target)
                else:
                    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(target) or ".", prefix=".huginn-")
                    with os.fdopen(fd, "w") as f:
                        f.write(before[target])
                    os.replace(tmp, target)
            except OSError:
                pass
        for tmp, _target, _path in staged:
            try:
                os.unlink(tmp)
            except OSError:
                pass
        return 1
    return 0


def known_patch(original, current, old, known):
    # Is current == upstream with block `old` replaced by an earlier Huginn text X and a helper H appended, where
    # sha256(X + "\0" + H) is in `known`? Every place the upstream remainder could start is tried.
    import hashlib
    pre, sep, post = original.partition(old)
    if not sep or not current.startswith(pre):
        return False
    i = current.find(post, len(pre))
    while i >= 0:
        if hashlib.sha256((current[len(pre):i] + "\0" + current[i + len(post):]).encode()).hexdigest() in known:
            return True
        i = current.find(post, i + 1)
    return False


def cowrie_forward(path):
    import os
    s = open(path).read()
    if "Huginn proxyreply v2" in s:
        return 3
    upstream = s
    if "Huginn proxyreply v1" in s:
        # Built by 0.26: replace it, but only when it is exactly that patch on top of the saved upstream file.
        try:
            upstream = open(path + ".orig").read()
        except OSError:
            return 1
        if os.path.islink(path + ".orig") or not known_patch(upstream, s, FWD_OLD, FWD_KNOWN):
            return 1
    if upstream.count(FWD_OLD) != 1 or upstream.count(FWD_TOP_OLD) != 1:
        return 1
    new = upstream.replace(FWD_TOP_OLD, FWD_TOP_NEW).replace(FWD_OLD, FWD_NEW) + FWD_HELPER
    compile(new, path, "exec")
    # .orig keeps the true upstream text, also when an 0.26 patch is replaced.
    return write_group({path: (s, new, upstream)})


# Cowrie's ping reads its options with "ci:", so "-c" never takes a value and "ping -c 1 8.8.8.8" always says
# "bad number of packets to transmit". Most telnet bots check the network with exactly that and leave.
PING_OLD = '            optlist, args = getopt.gnu_getopt(self.args, "ci:")'
PING_NEW = ('            # Huginn ping v1: "-c" takes a count (upstream had "ci:", so every "ping -c N host" failed).\n'
            '            optlist, args = getopt.gnu_getopt(self.args, "c:i:")')

# Every new SSH channel (the SFTP upload, then "chmod +x" in an exec channel) built a new, empty fake file system,
# so an uploaded file was gone at once: "chmod: cannot access '/root/.16': No such file or directory" and the bot
# left without running it. Keep one file system per connection, and let SFTP set a file's mode (OpenSSH's scp
# uses SFTP and gave up on "fsetstat: Operation unsupported").
UPLOAD_LIMIT = 10 * 1024 * 1024
UPLOAD = {
    "shell/server.py": [(
        "        self.fs = fs.HoneyPotFilesystem(self.arch, home)\n",
        "        # Huginn upload v1: one fake file system per connection, so an uploaded file is still there for the next command.\n"
        "        if self.fs is not None:\n"
        "            return\n"
        "        self.fs = fs.HoneyPotFilesystem(self.arch, home)\n")],
    "shell/session.py": [(
        "        if self.avatar.temporary:\n"
        "            self.server.fs.mkdir(",
        "        # Huginn upload v1: the file system now lives as long as the connection, so make the home only once.\n"
        "        if self.avatar.temporary and not self.server.fs.exists(self.avatar.home):\n"
        "            self.server.fs.mkdir(")],
    # "scp FILE host:/tmp/x" runs "scp -t /tmp/x" on the server; Cowrie ignored the target and saved the file under
    # its source name in the current directory, so the bot's "chmod +x /tmp/x" failed.
    "commands/scp.py": [(
        '        self.out_dir = ""\n',
        '        self.out_dir = ""\n'
        '        # Huginn upload v1: "scp -t TARGET" names the file (or the directory) the upload goes to.\n'
        '        self.hp_target = args[0] if args and any(o[0] == "-t" for o in optlist) else ""\n'),
        ('                    scpname = r.group(3).decode(errors="replace")\n',
         '                    scpname = r.group(3).decode(errors="replace")\n'
         '                    # Huginn upload v1: a name in an scp file record is one plain name, as real scp insists.\n'
         '                    if "/" in scpname or scpname in (".", ".."):\n'
         '                        self.errorWrite("scp: error: unexpected filename: %s\\n" % scpname)\n'
         '                        return b""\n'),
        ('                        fname = scpname\n',
         '                        fname = scpname\n'
         '                        if getattr(self, "hp_target", ""):\n'
         '                            fname = self.hp_target\n'
         '                            if fname.endswith("/") or self.fs.isdir(self.fs.resolve_path(fname, self.cwd)):\n'
         '                                fname = posixpath.join(fname, scpname)\n')],
    # While an SFTP upload runs, the file points at its temp copy; at close the copy is renamed to its hash, but
    # update_realfile only sets an empty pointer, so "cat"/running the file failed with "No such file".
    # Keep upstream's checks (a plain file, under 25 MB) so cat never reads a huge file into memory.
    "shell/fs.py": [(
        "        self.update_realfile(self.getfile(self.filenames[fd]), shasumfile)\n",
        "        # Huginn upload v1: point the file at its saved copy (the temp name it had while uploading is gone).\n"
        "        node = self.getfile(self.filenames[fd])\n"
        "        if (node is not None and os.path.isfile(shasumfile) and not os.path.islink(shasumfile)\n"
        "                and node[A_SIZE] < 25000000):\n"
        "            node[A_REALFILE] = shasumfile\n")],
    "shell/filetransfer.py": [(
        "    def setAttrs(self, attrs):\n"
        "        raise NotImplementedError\n",
        "    def setAttrs(self, attrs):\n"
        "        # Huginn upload v1: scp/sftp set the mode of the file they just wrote; do it in the fake file system.\n"
        "        try:\n"
        "            self.sftpserver._setAttrs(self.filename, attrs)\n"
        "        except Exception:\n"
        "            pass\n"),
        # The limit counted only bytes that arrived: one byte written at offset 2**40 made a huge sparse file that
        # Cowrie then read whole to hash it. Count the file's size too, and use 10 MB when Cowrie has no limit set.
        ("        if self.bytesReceivedLimit and self.bytesReceived > self.bytesReceivedLimit:\n",
         "        # Huginn upload v1: the limit holds for the file's size too, and 10 MB applies when none is set.\n"
         "        if max(self.bytesReceived, self.size) > (self.bytesReceivedLimit or %d):\n" % UPLOAD_LIMIT)],
}


def patched(text, pairs):
    # The new text, or None when an anchor is not there exactly once.
    for old, rep in pairs:
        if text.count(old) != 1:
            return None
        text = text.replace(old, rep)
    return text


def patch_once(path, marker, pairs):
    s = open(path).read()
    if marker in s:
        return 3
    new = patched(s, pairs)
    if new is None:
        return 1
    compile(new, path, "exec")
    return write_group({path: (s, new)})


def cowrie_ping(path):
    return patch_once(path, "Huginn ping v1", [(PING_OLD, PING_NEW)])


def cowrie_upload(srcdir):
    # All files or none: build and compile every new file first, then swap them in together.
    import os
    changes = {}
    for rel, pairs in UPLOAD.items():
        path = os.path.join(srcdir, rel)
        try:
            s = open(path).read()
        except OSError:
            return 1
        if "Huginn upload v1" in s:
            continue
        new = patched(s, pairs)
        if new is None:
            return 1
        compile(new, path, "exec")
        changes[path] = (s, new)
    if not changes:
        return 3
    return write_group(changes)

# Cowrie's wget answers in GNU wget's words even on the BusyBox camera, prints "connected" before it has tried, and says
# "unable to resolve host address" for a plain IP address. Rewrite only what is printed (see hp_wget_text).
WGET_OLD = 'class Command_wget(HoneyPotCommand):\n    """\n    wget command\n    """\n'
WGET_NEW = WGET_OLD + (
    '\n    # Huginn wget v1: print what a real wget on this box would print.\n'
    '    def errorWrite(self, data):\n'
    '        for out in hp_wget_text(self, data):\n'
    '            super().errorWrite(out)\n')
WGET_HELPER = '\n\n# Huginn wget helper v1. Only rewrites what wget prints; nothing here connects anywhere or changes what is downloaded.\nimport ipaddress as hp_ipaddress\n\nHP_WGET_ERRORS = {"failed: Connection timed out.\\n": "Connection timed out", "failed: Network is unreachable.\\n": "Network is unreachable",\n                  "failed: Operation timed out.\\n": "Connection timed out", "cancel failed: Operation timed out.\\n": "Connection timed out",\n                  "No data received.\\n": "Connection timed out", "failed: Connection refused.\\n": "Connection refused"}\n\n\ndef hp_wget_busybox(cmd):\n    # Embedded personas (ARM/MIPS/PowerPC) have BusyBox wget, not GNU wget.\n    try:\n        arch = str(cmd.protocol.user.server.arch or "")\n    except Exception:\n        arch = ""\n    return any(k in arch for k in ("arm", "aarch64", "mips", "ppc"))\n\n\ndef hp_is_ip(host):\n    try:\n        hp_ipaddress.ip_address(str(host).strip("[]"))\n        return True\n    except ValueError:\n        return False\n\n\ndef hp_wget_text(cmd, data):\n    # Returns what to print instead of `data` (possibly nothing, possibly several pieces).\n    if not isinstance(data, str):\n        return [data]\n    bb = hp_wget_busybox(cmd)\n    host, port = str(getattr(cmd, "host", "") or ""), getattr(cmd, "port", 80) or 80\n    quiet = bool(getattr(cmd, "quiet", False))\n    pend = getattr(cmd, "_hp_pend", None)\n    conn_bb = "Connecting to %s:%s (%s:%s)\\n" % (host, port, host, port)\n    if data.startswith("--") and "--  " in data[:40]:                  # GNU\'s "--date--  URL" line\n        return [] if bb else [data]\n    if data.startswith("Resolving ") or data.startswith("wget: unable to resolve host address"):\n        if hp_is_ip(host):                                               # an address is never "resolved": the connection fails\n            if data.startswith("wget: unable"):\n                return []\n            if bb:\n                return [conn_bb, "wget: can\'t connect to remote host (%s): Connection refused\\n" % host]\n            return [] if quiet else ["Connecting to %s:%s... failed: Connection refused.\\n" % (host, port)]\n        if bb:\n            return [] if data.startswith("Resolving ") else ["wget: bad address \'%s\'\\n" % host]\n        return [data]\n    if data.startswith("Connecting to ") and data.endswith("... connected.\\n"):\n        cmd._hp_pend = data                                              # Cowrie says "connected" before it has tried: wait\n        return []\n    if data.endswith("request sent, awaiting response... "):\n        if pend is not None:\n            cmd._hp_pend = pend + data\n            return []\n        return [] if bb else [data]\n    if data.startswith("Connecting to ") and data.endswith("... "):     # the rate-limited path, failure follows\n        cmd._hp_conn = True\n        return [conn_bb] if bb else [data]\n    if data == "Retrying.\\n\\n":\n        return [] if bb else [data]\n    if data in HP_WGET_ERRORS:\n        why = HP_WGET_ERRORS[data]\n        cmd._hp_pend = None\n        if bb:\n            return ([] if getattr(cmd, "_hp_conn", False) or quiet else [conn_bb]) + ["wget: can\'t connect to remote host (%s): %s\\n" % (host, why)]\n        if pend is not None:\n            return ["Connecting to %s:%s... failed: %s.\\n" % (host, port, why)]\n        return [] if quiet else [data]\n    out = []\n    if pend is not None:                                                 # something came back: the connection was real\n        out.append(conn_bb if bb else pend)\n        cmd._hp_pend = None\n    out.append(data)\n    return out\n'

# An uploaded program used to fail with "cannot execute binary file: Exec format error", so bots stopped right there.
EXEC_OLD = ('                    self.exit_code = 126\n'
            '                    return\n'
            '                run_script_file(\n')
EXEC_NEW = ('                    self.exit_code = 126\n'
            '                    return\n'
            '                # Huginn exec v1: a program for this CPU "runs" silently and is logged; nothing is executed.\n'
            '                if hp_exec_sim(self, path, name):\n'
            '                    return\n'
            '                run_script_file(\n')
EXEC_HELPER = '\n\n# Huginn exec helper v1. Nothing is ever executed: an uploaded program for this persona\'s CPU "runs" silently (exit 0), and\n# the attempt is logged with its arguments and hash. Wrong CPU keeps upstream\'s "cannot execute binary file", as a real box.\nimport hashlib as hp_hashlib\n\nHP_ELF_MACHINES = {"aarch64": {183}, "x64": {62, 3}, "x86": {3}, "arm": {40}, "mips": {8}, "ppc": {20, 21}}\n\n\ndef hp_exec_sim(cmd, path, name):\n    try:\n        data = cmd.fs.file_contents(path)\n    except Exception:\n        return False\n    if not isinstance(data, bytes) or len(data) < 20 or data[:4] != b"\\x7fELF":\n        return False\n    machine = int.from_bytes(data[18:20], "little" if data[5] == 1 else "big")\n    try:\n        arch = str(cmd.protocol.user.server.arch or "")\n    except Exception:\n        arch = ""\n    family = next((k for k in HP_ELF_MACHINES if k in arch), "")\n    if machine not in HP_ELF_MACHINES.get(family, set()):\n        return False\n    try:\n        cmd.protocol.events.dispatch(\n            "cowrie.session.hp-exec",\n            "huginn: simulated run of %(path)s",\n            path=str(path)[:300],\n            args=" ".join(str(a) for a in cmd.args)[:500],\n            shasum=hp_hashlib.sha256(data).hexdigest(),\n            arch=arch,\n        )\n    except Exception:\n        pass\n    cmd.exit_code = 0\n    return True\n'


def patch_append(path, marker, old, new, helper):
    # Replace one block and append a helper, all at once (see write_group).
    s = open(path).read()
    if marker in s:
        return 3
    if s.count(old) != 1:
        return 1
    out = s.replace(old, new) + helper
    compile(out, path, "exec")
    return write_group({path: (s, out)})


def cowrie_wget(path):
    return patch_append(path, "Huginn wget v1", WGET_OLD, WGET_NEW, WGET_HELPER)


def cowrie_exec(path):
    return patch_append(path, "Huginn exec v1", EXEC_OLD, EXEC_NEW, EXEC_HELPER)


def opencanary_ports(p):
    c = json.load(open(p))
    mods = {k[:-8] for k in c if k.endswith(".enabled")}
    used = {c.get(m + ".port") for m in mods if c.get(m + ".enabled") and isinstance(c.get(m + ".port"), int)}
    free, changed = 62000, False
    for m in sorted(mods):
        if not c.get(m + ".enabled") and c.get(m + ".port") in used:
            while free in used:
                free += 1
            c[m + ".port"] = free; used.add(free); free += 1; changed = True
    if changed:
        json.dump(c, open(p, "w"), indent=2)
    return 0 if changed else 3


if __name__ == "__main__":
    cmds = {"cowrie-free": cowrie_free, "cowrie-forward": cowrie_forward, "cowrie-ping": cowrie_ping,
            "cowrie-upload": cowrie_upload, "cowrie-wget": cowrie_wget, "cowrie-exec": cowrie_exec,
            "opencanary-http": opencanary_http, "opencanary-ports": opencanary_ports}
    if len(sys.argv) != 3 or sys.argv[1] not in cmds:
        sys.exit("usage: patches.py {cowrie-free|cowrie-forward|cowrie-ping|cowrie-upload|cowrie-wget|cowrie-exec|opencanary-http|opencanary-ports} FILE")
    sys.exit(cmds[sys.argv[1]](sys.argv[2]))
