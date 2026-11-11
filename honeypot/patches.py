#!/usr/bin/env python3
# patches.py — small local patches Huginn applies to Cowrie and OpenCanary (part of Huginn, AGPL-3.0-or-later).
# Used by install-honeypot.sh and update-honeypot.sh, so an upgrade of Cowrie/OpenCanary gets them back.
#
#   patches.py cowrie-free FILE        Cowrie's "free" reads the persona's fake /proc/meminfo, not the host's
#   patches.py opencanary-http FILE    OpenCanary logs every probed web path (it never logged 404s)
#   patches.py opencanary-ports CONF   move disabled OpenCanary modules off ports used by enabled ones
#
# Exit code: 0 = patched/changed, 3 = already patched/nothing to do, 1 = the upstream code changed (not patched).
import json, sys

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
HTTP_NEW = '    def render(self, request):\n        # Huginn webreply v1: bounded, inert replies and one log record per request.\n        payload, reply_type, ctype, robots = None, None, None, False\n        body = b""\n        try:\n            if request.method in (b"POST", b"PUT") and request.content is not None:\n                request.content.seek(0)\n                body = request.content.read(500)\n                request.content.seek(0)\n            if str(self.error_code) == "404":\n                reply_type, payload, ctype, robots = hpw_reply(self.factory, request.uri, request.method, body)\n        except Exception:\n            pass\n        status = 200 if payload is not None else int(self.error_code)\n        request.setHeader(b"Server", self.factory.banner)\n        request.setResponseCode(status)\n        if payload is not None:\n            request.setHeader(b"Content-Type", ctype.encode("ascii"))\n            request.setHeader(b"X-Content-Type-Options", b"nosniff")\n            request.setHeader(b"Content-Security-Policy", b"default-src \'none\'; sandbox")\n            request.setHeader(b"Cache-Control", b"no-store")\n            request.setHeader(b"Content-Length", str(len(payload)).encode("ascii"))\n        try:\n            ua = request.getHeader("user-agent") or "<not supplied>"\n            logdata = {"PATH": request.uri.decode("utf-8", "replace")[:500],\n                       "METHOD": request.method.decode("ascii", "replace")[:10],\n                       "STATUS": status, "USERAGENT": ua[:500]}\n            if body:\n                logdata["BODY"] = body.decode("utf-8", "replace")\n            if reply_type is not None and payload is not None:\n                logdata["HP_REPLY"] = reply_type\n            if robots:\n                logdata["HP_ROBOTS"] = "1"\n            self.factory.log(logdata, transport=request.transport, logtype=self.factory.logger.LOG_HTTP_GET)\n        except Exception:\n            pass\n        if payload is not None:\n            return b"" if request.method == b"HEAD" else payload\n        return Resource.render(self, request)'
HTTP_HELPER = '# Bounded, inert web deception for Huginn. No network calls or request evaluation.\nimport hashlib as hpw_hashlib\nimport json as hpw_json\nimport os as hpw_os\nimport re as hpw_re\nimport time as hpw_time\nfrom urllib.parse import unquote as hpw_unquote, urlsplit as hpw_urlsplit\n\nHPW_VERSION = 1\nHPW_MAX_URI = 2048\nHPW_MAX_BODY = 4096\nHPW_MAX_BUNDLE = 65536\nHPW_BUNDLE = \'webreply.json\'\nHPW_BAIT = \'/etc/huginn-honeypot/bait.json\'\n\n\ndef hpw_bait(path=HPW_BAIT):\n    """Read only planted values, never invent a credential or inspect host secrets."""\n    try:\n        with open(path, \'rb\') as f:\n            raw = f.read(HPW_MAX_BUNDLE + 1)\n        if len(raw) > HPW_MAX_BUNDLE:\n            return {}\n        data = hpw_json.loads(raw)\n        if not isinstance(data, dict) or len(data) > 256:\n            return {}\n        return {k: v for k, v in data.items()\n                if isinstance(k, str) and len(k) <= 100 and isinstance(v, str)\n                and hpw_re.fullmatch(r\'[A-Za-z0-9/+_=!@#$%.,~\\-]{8,160}\', v)\n                and not v.lower().startswith((\'replace-\', \'changeme\'))}\n    except (OSError, ValueError, RecursionError):\n        return {}\n\n\ndef hpw_robots(identity):\n    """Four stable paths, distinct across identities; not linked from other replies."""\n    ident = identity[\'id\']\n    if not hpw_re.fullmatch(r\'[a-z0-9-]{1,32}\', ident):\n        raise ValueError(\'Invalid web identity\')\n    tag = hpw_hashlib.sha256((\'huginn-robots-v1:\' + ident).encode()).hexdigest()[:10]\n    if identity[\'kind\'] == \'router\':\n        return [\'/cgi-bin/diag-\' + tag + \'.cgi\', \'/config/archive-\' + tag + \'/\',\n                \'/support/\' + tag + \'/status\', \'/admin/export-\' + tag + \'.cfg\']\n    return [\'/backup/archive-\' + tag + \'/\', \'/maintenance/\' + tag + \'/status\',\n            \'/config/export-\' + tag + \'.ini\', \'/storage/snapshot-\' + tag + \'/\']\n\n\ndef hpw_build(identity, bait_path=HPW_BAIT):\n    bait = hpw_bait(bait_path)\n    paths = hpw_robots(identity)\n    replies = {}\n    def add(kind, body, ctype=\'text/plain; charset=utf-8\'):\n        if len(body.encode(\'utf-8\')) > HPW_MAX_BODY:\n            raise ValueError(\'Reply exceeds limit\')\n        replies[kind] = [ctype, body]\n    if bait:\n        def secret(*names):\n            for name in names:\n                for key in sorted(bait):\n                    if key == name or key.endswith(\'_\' + name):\n                        return bait[key]\n            return bait[sorted(bait)[0]]\n        db = secret(\'env_db\', \'nc_db\', \'mysql_backup\', \'nas_smb\', \'cam_admin\')\n        redis = secret(\'redis\')\n        keyid = secret(\'aws_key_id\', \'b2_key_id\')\n        aws = secret(\'aws_secret\', \'b2_key\')\n        kind = \'gateway\' if identity[\'kind\'] == \'router\' else \'storage\'\n        add(\'env\', \'APP_ENV=production\\nAPP_NAME=\' + kind + \'\\nDB_HOST=127.0.0.1\\nDB_DATABASE=device\\nDB_USERNAME=backup\\nDB_PASSWORD=\' + db + \'\\nREDIS_PASSWORD=\' + redis + \'\\n\')\n        add(\'git\', \'[core]\\n\\trepositoryformatversion = 0\\n\\tbare = false\\n[remote "origin"]\\n\\turl = /srv/git/device-config.git\\n\\tfetch = +refs/heads/*:refs/remotes/origin/*\\n\')\n        add(\'git_head\', \'ref: refs/heads/main\\n\')\n        add(\'aws\', \'[default]\\naws_access_key_id = \' + keyid + \'\\naws_secret_access_key = \' + aws + \'\\nregion = eu-north-1\\n\')\n        add(\'aws_config\', \'[default]\\nregion = eu-north-1\\noutput = json\\n\')\n        add(\'phpinfo\', \'phpinfo()\\nPHP Version => 7.4.33\\nSystem => Linux device 4.19.0 armv7l\\nServer API => CGI/FastCGI\\nConfiguration File (php.ini) Path => /etc/php\\nDOCUMENT_ROOT => /var/www\\nDB_PASSWORD => \' + db + \'\\n\')\n        add(\'traversal\', \'root:x:0:0:root:/root:/bin/sh\\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\\nbackup:x:1000:1000:Backup:/home/backup:/bin/sh\\n\')\n        add(\'phpunit\', \'uid=33(www-data) gid=33(www-data) groups=33(www-data)\\n\')\n        add(\'mcp\', hpw_json.dumps({\'name\': \'device-management\', \'version\': \'1.0\', \'capabilities\': {\'tools\': {}}}, separators=(\',\', \':\')), \'application/json\')\n        add(\'actuator\', hpw_json.dumps({\'activeProfiles\': [\'production\'], \'propertySources\': [{\'name\': \'applicationConfig\', \'properties\': {\'device.mode\': {\'value\': kind}, \'spring.datasource.password\': {\'value\': db}}}]}, separators=(\',\', \':\')), \'application/json\')\n        add(\'robots_backup\', \'[device]\\nrole=\' + kind + \'\\nusername=backup\\npassword=\' + db + \'\\n\')\n    return {\'version\': HPW_VERSION, \'identity\': {\'id\': identity[\'id\'], \'kind\': identity[\'kind\']},\n            \'robots\': paths, \'replies\': replies}\n\n\ndef hpw_write_skin(folder, identity, bait_path=HPW_BAIT):\n    """Called as root. Publish identity metadata, never a persistent credential snapshot."""\n    bundle = {\'version\': HPW_VERSION, \'identity\': {\'id\': identity[\'id\'], \'kind\': identity[\'kind\']},\n              \'robots\': hpw_robots(identity), \'replies\': {}}\n    files = {HPW_BUNDLE: hpw_json.dumps(bundle, separators=(\',\', \':\')),\n             \'robots.txt\': \'User-agent: *\\n\' + \'\'.join(\'Disallow: \' + p + \'\\n\' for p in bundle[\'robots\'])}\n    for name, text in files.items():\n        path = hpw_os.path.join(folder, name)\n        tmp = path + \'.new\'\n        fd = hpw_os.open(tmp, hpw_os.O_WRONLY | hpw_os.O_CREAT | hpw_os.O_EXCL | hpw_os.O_NOFOLLOW, 0o644)\n        try:\n            with hpw_os.fdopen(fd, \'w\', encoding=\'utf-8\') as f:\n                f.write(text)\n            hpw_os.chmod(tmp, 0o644)\n            hpw_os.replace(tmp, path)\n        finally:\n            if hpw_os.path.exists(tmp):\n                hpw_os.unlink(tmp)\n\n\ndef hpw_load(factory):\n    """Bounded bundle/bait reads once per second; bait metadata changes invalidate immediately."""\n    now = hpw_time.monotonic()\n    try:\n        st = hpw_os.stat(HPW_BAIT)\n        signature = (st.st_ino, st.st_mtime_ns, st.st_size, st.st_mode)\n    except OSError:\n        signature = None\n    cached = getattr(factory, \'_hpw_cache\', None)\n    if cached is not None and cached[0] > now and cached[2] == signature:\n        return cached[1]\n    data = {}\n    try:\n        with open(hpw_os.path.join(factory.skindir, HPW_BUNDLE), \'rb\') as f:\n            raw = f.read(HPW_MAX_BUNDLE + 1)\n        if len(raw) <= HPW_MAX_BUNDLE:\n            obj = hpw_json.loads(raw)\n            if (isinstance(obj, dict) and obj.get(\'version\') == HPW_VERSION\n                    and isinstance(obj.get(\'robots\'), list) and len(obj[\'robots\']) == 4\n                    and all(isinstance(p, str) and hpw_re.fullmatch(r\'/[a-z0-9/_.-]{1,160}\', p) for p in obj[\'robots\'])\n                    and isinstance(obj.get(\'identity\'), dict)\n                    and obj[\'identity\'].get(\'kind\') in (\'nas\', \'router\')\n                    and isinstance(obj[\'identity\'].get(\'id\'), str)\n                    and hpw_re.fullmatch(r\'[a-z0-9-]{1,32}\', obj[\'identity\'][\'id\'])\n                    and isinstance(obj.get(\'replies\'), dict) and len(obj[\'replies\']) <= 12):\n                # Re-read the planted values, never trust a stale credential snapshot.\n                data = hpw_build(obj[\'identity\'], HPW_BAIT)\n    except (OSError, ValueError, RecursionError):\n        pass\n    factory._hpw_cache = (now + 1.0, data, signature)\n    return data\n\n\ndef hpw_target(uri):\n    if not isinstance(uri, bytes) or len(uri) > HPW_MAX_URI:\n        return None\n    try:\n        text = uri.decode(\'ascii\')\n        if not text.startswith(\'/\') or text.startswith(\'//\'):\n            return None\n        for _ in range(2):\n            text = hpw_unquote(text)\n        parts = hpw_urlsplit(text)\n        if parts.scheme or parts.netloc:\n            return None\n        if any(ord(c) < 32 or ord(c) == 127 for c in text):\n            return None\n        return parts.path, parts.query\n    except (ValueError, UnicodeError):\n        return None\n\n\ndef hpw_kind(path, query):\n    low = path.lower()\n    if low.endswith(\'/.git/config\'):\n        return \'git\'\n    if low.endswith(\'/.git/head\'):\n        return \'git_head\'\n    if low.endswith(\'/.aws/credentials\'):\n        return \'aws\'\n    if low.endswith(\'/.aws/config\'):\n        return \'aws_config\'\n    if hpw_re.search(r\'/(?:\\.env)(?:\\.[a-z0-9_-]{1,24}){0,3}$\', low):\n        return \'env\'\n    if hpw_re.search(r\'/(?:phpinfo|info)\\.php$\', low):\n        return \'phpinfo\'\n    if low.endswith(\'/vendor/phpunit/phpunit/src/util/php/eval-stdin.php\') or low.endswith(\'/phpunit/src/util/php/eval-stdin.php\'):\n        return \'phpunit\'\n    combined = low + \'?\' + query.lower()\n    if \'/etc/passwd\' in combined and (\'../\' in combined or hpw_re.search(r\'(?:[?&])(?:file|path|page)=/?etc/passwd(?:&|$)\', combined)):\n        return \'traversal\'\n    if low in (\'/mcp\', \'/mcp/\'):\n        return \'mcp\'\n    if low in (\'/actuator/env\', \'/actuator/env/\'):\n        return \'actuator\'\n    return None\n\n\ndef hpw_reply(factory, uri, method, body=b\'\'):\n    """Return (reply_type, body, content_type, robots_hit), or an empty reply."""\n    target = hpw_target(uri)\n    if target is None:\n        return None, None, None, False\n    path, query = target\n    bundle = hpw_load(factory)\n    robots = bundle.get(\'robots\', [])\n    hit = any(path == p or (p.endswith(\'/\') and path.startswith(p)) for p in robots)\n    if method not in (b\'GET\', b\'HEAD\', b\'POST\', b\'PUT\'):\n        return None, None, None, hit\n    if path == \'/robots.txt\' and method in (b\'GET\', b\'HEAD\') and robots:\n        payload = \'User-agent: *\\n\' + \'\'.join(\'Disallow: \' + p + \'\\n\' for p in robots)\n        return None, payload.encode(), \'text/plain; charset=utf-8\', False\n    kind = \'robots_backup\' if hit else hpw_kind(path, query)\n    entry = bundle.get(\'replies\', {}).get(kind)\n    if not isinstance(entry, list) or len(entry) != 2:\n        return None, None, None, hit\n    ctype, payload = entry\n    if ctype not in (\'text/plain; charset=utf-8\', \'application/json\') or not isinstance(payload, str):\n        return None, None, None, hit\n    if not hpw_re.fullmatch(\'[a-z_]{1,20}\', kind):\n        return None, None, None, hit\n    if kind == \'mcp\' and method == b\'POST\':\n        if len(body) > 500:\n            return None, None, None, hit\n        try:\n            rpc = hpw_json.loads(body)\n            if not isinstance(rpc, dict) or rpc.get(\'jsonrpc\') != \'2.0\':\n                return None, None, None, hit\n            rid = rpc.get(\'id\')\n            if not (type(rid) is int or isinstance(rid, str)) or len(str(rid)) > 64:\n                return None, None, None, hit\n            if rpc.get(\'method\') == \'initialize\':\n                result = {\'protocolVersion\': \'2024-11-05\', \'capabilities\': {\'tools\': {}}, \'serverInfo\': {\'name\': \'device-management\', \'version\': \'1.0\'}}\n            elif rpc.get(\'method\') == \'tools/list\':\n                result = {\'tools\': [{\'name\': \'device_status\', \'description\': \'Read device status\', \'inputSchema\': {\'type\': \'object\', \'properties\': {}}}]}\n            else:\n                payload = hpw_json.dumps({\'jsonrpc\': \'2.0\', \'id\': rid, \'error\': {\'code\': -32601, \'message\': \'Method not found\'}})\n                result = None\n            if result is not None:\n                payload = hpw_json.dumps({\'jsonrpc\': \'2.0\', \'id\': rid, \'result\': result})\n        except (ValueError, RecursionError):\n            return None, None, None, hit\n    raw = payload.encode(\'utf-8\')\n    if len(raw) > HPW_MAX_BODY:\n        return None, None, None, hit\n    return kind, raw, ctype, hit\n'
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
    if 'Huginn webreply v1' in current or 'Huginn patch' in current:
        if not backup.is_file():
            return 1
        original = backup.read_text()
        desired = changed(original)
        if desired is None:
            return 1
        if current == desired:
            return 3
        legacy = original.replace(HTTP_OLD, HTTP_LEGACY)
        if current != legacy:
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
    cmds = {"cowrie-free": cowrie_free, "opencanary-http": opencanary_http, "opencanary-ports": opencanary_ports}
    if len(sys.argv) != 3 or sys.argv[1] not in cmds:
        sys.exit("usage: patches.py {cowrie-free|opencanary-http|opencanary-ports} FILE")
    sys.exit(cmds[sys.argv[1]](sys.argv[2]))
