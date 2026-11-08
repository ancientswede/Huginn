# Attackers control most of what Huginn shows (usernames, passwords, commands, URLs, file names, SSH versions), and
# external services control the rest (network names, malware tags). Plant HTML/JS in every such field and make sure no
# page renders it as markup.
import http.client, json, re, threading, time, unittest, urllib.parse
from http.server import ThreadingHTTPServer

from tests.helpers import app

P = '"><img src=x onerror=alert(1)><script>alert(2)</script><svg/onload=alert(3)>\'`javascript:alert(4)'
IP = "198.51.100.66"
SHA = "c0" * 32
TTY = "d0" * 32
BAD = re.compile(r"<img src=x|<script>alert|<svg/onload|href=[\"']?javascript:", re.I)


def ev(kind, a=None, b=None, session="xs1", src="cowrie", dt=0.0):
    ts = time.time() - 600 + dt
    return ("xss|%s|%s|%s|%s" % (kind, a, b, dt), ts, IP, src, kind, session, a, b)


class XSS(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        con = app.connect()
        app.store(con, [
            ev("connect", "ssh", "2225"), ev("version", P, None, dt=1), ev("hassh", "ab" * 16, None, dt=1.5),
            ev("login_fail", P, P, dt=2), ev("login_ok", P, P, dt=3), ev("cmd", P, None, dt=4), ev("cmd", "wget " + P, None, dt=5),
            ev("file", "http://203.0.113.9/" + P, SHA, dt=6), ev("file_fail", "http://203.0.113.9/x" + P, None, dt=7),
            ev("tcpip", P, None, dt=8), ev("exploit", P, P, dt=9), ev("tty", TTY, "100", dt=10), ev("closed", "12.5", None, dt=11),
            ev("canary", "http", "GET /" + P, session=None, src="canary", dt=12),
            ev("canary", "mysql", P + " / " + P, session=None, src="canary", dt=13),
        ])
        app.store_files(con, [{"sha": SHA, "size": 10, "type": P, "arch": P, "family": P, "iocs": [P, "http://x/" + P]}])
        with con:
            con.execute("UPDATE files SET mb=? WHERE sha=?", (json.dumps({"found": True, "signature": P, "tags": [P]}), SHA))
            con.execute("INSERT OR REPLACE INTO enrich(ip,fetched,ok,cc,country,city,asn,org,isp,rdns,ports,tags,vulns,hostnames,research) "
                        "VALUES(?,?,1,?,?,?,?,?,?,?,?,?,?,?,0)", (IP, time.time(), "X<", P, P, P, P, P, P, P, P, P, P))
            con.execute("INSERT OR REPLACE INTO flags(ip,flag,note,updated) VALUES(?,?,?,?)", (IP, "block", P, time.time()))
        st = app.settings(con)
        st["title"] = P
        app.set_meta(con, "settings", json.dumps(st))
        for k in ("last_error", "last_notify", "last_notify_error", "update_error"):
            app.set_meta(con, k, P)
        app.set_meta(con, "pw", app.hash_pw("xss-test-password"))
        app.set_meta(con, "last_ingest", time.time())
        cls.cmdhash = con.execute("SELECT cmdhash FROM sessions WHERE session='xs1'").fetchone()[0]
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), app.Handler)
        cls.port = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        r, _ = cls.req("POST", "/login", "password=xss-test-password",
                       {"Origin": "http://127.0.0.1:%d" % cls.port, "Content-Type": "application/x-www-form-urlencoded"})
        cls.cookie = (r.getheader("Set-Cookie") or "").split(";")[0]

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        con = app.connect()
        st = app.settings(con)
        st["title"] = "Huginn"
        app.set_meta(con, "settings", json.dumps(st))
        with con:
            con.execute("DELETE FROM flags WHERE ip=?", (IP,))
            con.execute("DELETE FROM enrich WHERE ip=?", (IP,))

    @classmethod
    def req(cls, method, path, body=None, headers=None):
        c = http.client.HTTPConnection("127.0.0.1", cls.port, timeout=15)
        h = {"Host": "127.0.0.1:%d" % cls.port}
        h.update(headers or {})
        c.request(method, path, body=body, headers=h)
        r = c.getresponse()
        data = r.read().decode("utf-8", "replace")
        c.close()
        return r, data

    def test_no_page_renders_planted_markup(self):
        q = urllib.parse.quote(P)
        pages = ["/", "/personas", "/new", "/new?all=" + q, "/ips", "/ips?q=" + q, "/ips?cc=" + q, "/ips?sort=" + q, "/ip/" + IP, "/campaigns",
                 "/campaign/script/%s" % self.cmdhash, "/campaign/hassh/" + "ab" * 16, "/campaign/file/" + SHA, "/files",
                 "/creds", "/creds?q=" + q, "/creds?days=" + q, "/blocklist", "/blocklist?min=" + q, "/settings", "/settings?ok=" + q,
                 "/account", "/account?ok=" + q, "/replay/%s?ip=%s" % (TTY, q), "/nope/" + q]
        for path in pages:
            r, body = self.req("GET", path, headers={"Cookie": self.cookie})
            self.assertIn(r.status, (200, 400, 404), path)
            m = BAD.search(body)
            self.assertIsNone(m, "%s renders planted markup: ...%s..." % (path, body[max(0, m.start() - 80):m.end() + 20] if m else ""))

    def test_exports_and_feeds(self):
        r, body = self.req("GET", "/ip/%s/export.json" % IP, headers={"Cookie": self.cookie})
        self.assertEqual(r.getheader("Content-Type").split(";")[0], "application/json")
        json.loads(body)
        r, body = self.req("GET", "/creds/export.csv?days=all", headers={"Cookie": self.cookie})
        for line in body.splitlines()[1:]:
            for cell in line.split(","):
                self.assertFalse(cell[:1] in ("=", "+", "-", "@"), cell)
        tok = app.get_meta(app.connect(), "feed_token")
        for fmt in ("txt", "nft", "ipset", "mikrotik", "csv"):
            r, body = self.req("GET", "/feed/%s/%s" % (tok, fmt))
            self.assertIsNone(BAD.search(body), fmt)
            self.assertNotIn("\n" + IP + ";", body)

    def test_json_endpoints_are_json(self):
        r, body = self.req("GET", "/api/creds-check/0000.json", headers={"Cookie": self.cookie})
        self.assertEqual(r.getheader("Content-Type"), "application/json")
        self.assertEqual(r.getheader("X-Content-Type-Options"), "nosniff")

    def test_redirect_back_stays_on_site(self):
        for ref in ("http://127.0.0.1:%d//evil.example/x", "http://127.0.0.1:%d/\\evil.example", "http://127.0.0.1:%d/ok?x=1"):
            r, _ = self.req("POST", "/settings/theme", "",
                            {"Cookie": self.cookie, "Origin": "http://127.0.0.1:%d" % self.port, "Referer": ref % self.port,
                             "Content-Type": "application/x-www-form-urlencoded"})
            loc = r.getheader("Location") or ""
            self.assertTrue(loc.startswith("/") and not loc.startswith("//") and "\\" not in loc, loc)


if __name__ == "__main__":
    unittest.main()


class ExternalData(unittest.TestCase):
    # ipwho.is, Shodan InternetDB and the attacker's own reverse DNS are outside our control.
    def test_enrichment_is_validated(self):
        def fake(url):
            if "ipwho.is" in url:
                return {"success": True, "country_code": "SE\n203.0.113.0/24", "country": "Sweden\x00" + "x" * 500, "city": P,
                        "connection": {"asn": "64500; rm -rf /", "org": "Org\r\nX-Evil: 1", "isp": P}}
            return {"ports": [22, "80\n1.2.3.4", 99999999], "tags": ["scanner", "bad tag<script>"],
                    "vulns": ["CVE-2024-1234", "<img src=x>"], "hostnames": ["ok.example", "evil\nhost"]}
        orig, orig_dns = app.http_json, app.socket.gethostbyaddr
        app.http_json, app.socket.gethostbyaddr = fake, lambda ip: ("ptr.example\n\x1b[31m" + "y" * 400, [], [])
        try:
            d, ok, _ = app.enrich_ip("198.51.100.77")
        finally:
            app.http_json, app.socket.gethostbyaddr = orig, orig_dns
        self.assertEqual(ok, 1)
        self.assertIsNone(d["cc"])
        self.assertIsNone(d["asn"])
        self.assertEqual(d["ports"], "22")
        self.assertEqual(d["tags"], "scanner")
        self.assertEqual(d["vulns"], "CVE-2024-1234")
        self.assertEqual(d["hostnames"], "ok.example")
        for k in ("country", "org", "isp", "city", "rdns"):
            self.assertFalse(any(not c.isprintable() for c in d[k] or ""), k)
            self.assertLessEqual(len(d[k] or ""), 253, k)

    def test_csv_feed_cannot_gain_rows(self):
        con = app.connect()
        ip = "198.51.100.78"
        app.store(con, [("csvfeed|" + ip, time.time() - 60, ip, "cowrie", "login_ok", "cf1", "root", "x")])
        with con:
            con.execute("INSERT OR REPLACE INTO enrich(ip,fetched,ok,cc) VALUES(?,?,1,?)", (ip, time.time(), "SE\n0.0.0.0/0,9,x,SE,evil"))
            con.execute("INSERT OR REPLACE INTO flags(ip,flag,note,updated) VALUES(?,?,?,?)", (ip, "block", "", time.time()))
        try:
            body, _ = app.render_feed("csv", [ip])
        finally:
            with con:
                con.execute("DELETE FROM flags WHERE ip=?", (ip,))
        rows = body.strip().splitlines()
        self.assertEqual(len(rows), 2, body)
        self.assertNotIn("0.0.0.0/0", body)
