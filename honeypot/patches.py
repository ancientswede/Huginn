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
HTTP_NEW = """    def render(self, request):
        # Huginn patch: log every probed path. Scanners mostly ask for paths that do not exist (404),
        # which OpenCanary never logged, so the most interesting web traffic was invisible.
        try:
            ua = request.getHeader("user-agent") or "<not supplied>"
            logdata = {"PATH": request.uri.decode("utf-8", "replace")[:500],
                       "METHOD": request.method.decode("ascii", "replace")[:10],
                       "STATUS": self.error_code, "USERAGENT": ua}
            if request.method in (b"POST", b"PUT") and request.content is not None:
                request.content.seek(0)
                body = request.content.read(500)
                request.content.seek(0)
                if body:
                    logdata["BODY"] = body.decode("utf-8", "replace")
            self.factory.log(logdata, transport=request.transport, logtype=self.factory.logger.LOG_HTTP_GET)
        except Exception:
            pass
        request.setHeader(b"Server", self.factory.banner)
        request.setResponseCode(int(self.error_code))
        return Resource.render(self, request)"""


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
    return patch(path, [(HTTP_OLD, HTTP_NEW)])


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
