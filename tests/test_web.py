# The web server: login, CSRF protection, feed tokens, security headers and that every page renders.
import http.client, json, threading, time, unittest, urllib.parse
from http.server import ThreadingHTTPServer

from tests.helpers import app

PW = "test-password-123"


class Web(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        con = app.connect()
        app.set_meta(con, "pw", app.hash_pw(PW))
        app.set_meta(con, "last_ingest", time.time())
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), app.Handler)
        cls.port = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.cookie = cls.login(PW)[1]

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    @classmethod
    def req(cls, method, path, body=None, headers=None):
        c = http.client.HTTPConnection("127.0.0.1", cls.port, timeout=10)
        h = {"Host": "127.0.0.1:%d" % cls.port}
        h.update(headers or {})
        c.request(method, path, body=body, headers=h)
        r = c.getresponse()
        data = r.read().decode("utf-8", "replace")
        c.close()
        return r, data

    @classmethod
    def login(cls, pw, origin=True):
        h = {"Content-Type": "application/x-www-form-urlencoded"}
        if origin:
            h["Origin"] = "http://127.0.0.1:%d" % cls.port
        r, _ = cls.req("POST", "/login", urllib.parse.urlencode({"password": pw}), h)
        ck = (r.getheader("Set-Cookie") or "").split(";")[0]
        return r.status, ck

    def get(self, path):
        return self.req("GET", path, headers={"Cookie": self.cookie})

    def test_healthz(self):
        r, body = self.req("GET", "/healthz")
        self.assertEqual(r.status, 200)
        self.assertIn(app.HUGINN_VERSION, body)

    def test_needs_login(self):
        for p in ("/", "/ips", "/settings", "/blocklist"):
            r, _ = self.req("GET", p)
            self.assertEqual((p, r.status, r.getheader("Location")), (p, 303, "/login"))

    def test_wrong_password_and_csrf(self):
        self.assertEqual(self.login("wrong-password")[0], 401)
        self.assertEqual(self.login(PW, origin=False)[0], 403)
        r, _ = self.req("POST", "/login", "password=" + PW, {"Origin": "http://evil.example", "Content-Type": "application/x-www-form-urlencoded"})
        self.assertEqual(r.status, 403)

    def test_cookie_flags(self):
        self.assertTrue(self.cookie.startswith("huginn_s="))
        r, _ = self.req("POST", "/login", "password=" + PW,
                        {"Origin": "http://127.0.0.1:%d" % self.port, "Content-Type": "application/x-www-form-urlencoded"})
        sc = r.getheader("Set-Cookie")
        self.assertIn("HttpOnly", sc)
        self.assertIn("SameSite=Strict", sc)

    def test_security_headers(self):
        r, _ = self.get("/")
        self.assertEqual(r.status, 200)
        self.assertIn("default-src 'self'", r.getheader("Content-Security-Policy"))
        self.assertEqual(r.getheader("X-Frame-Options"), "DENY")
        self.assertEqual(r.getheader("X-Content-Type-Options"), "nosniff")

    def test_pages_render(self):
        for p in ("/", "/ips", "/ips?cc=SE", "/campaigns", "/files", "/creds", "/blocklist", "/settings", "/account",
                  "/ip/198.51.100.200", "/ip/not-an-ip"):
            r, body = self.get(p)
            self.assertIn(r.status, (200, 400, 404), p)
            if r.status == 200:
                self.assertIn("Source on GitHub", body, p)

    def test_creds_endpoints(self):
        r, body = self.get("/api/creds-check/%s.json" % ("0" * app.CRED_PREFIX))
        self.assertEqual(r.status, 200)
        self.assertIn("matches", json.loads(body))
        r, _ = self.req("GET", "/api/creds-check/0000.json")
        self.assertEqual(r.status, 303)                              # needs login like everything else
        r, _ = self.get("/api/creds-check/zz.json")
        self.assertEqual(r.status, 404)
        r, body = self.get("/creds/export.txt?what=usernames&days=7")
        self.assertEqual(r.status, 200)
        self.assertIn("attachment", r.getheader("Content-Disposition"))
        r, body = self.get("/creds?q=%3Cscript%3E")
        self.assertEqual(r.status, 200)
        self.assertNotIn("<script>", body)

    def test_icons(self):
        for p in ("/favicon.ico", "/static/icon-32.png", "/static/icon-192.png"):
            r, _ = self.req("GET", p)                                 # public, like the CSS
            self.assertEqual((p, r.status, r.getheader("Content-Type")), (p, 200, "image/png"))
        r, body = self.req("GET", "/login")
        self.assertIn("icon-32.png", body)

    def test_no_inline_styles(self):
        # The CSP has style-src 'self': style="" attributes are silently ignored by browsers, so never render any.
        for p in ("/", "/ips", "/campaigns", "/files", "/creds", "/blocklist", "/settings", "/account", "/ip/198.51.100.10"):
            r, body = self.get(p)
            if r.status == 200:
                self.assertNotRegex(body, r"\sstyle=", p)

    def test_feed_token(self):
        tok = app.get_meta(app.connect(), "feed_token")
        r, body = self.req("GET", "/feed/%s/txt" % tok)
        self.assertEqual(r.status, 200)
        self.assertTrue(body.startswith("# Huginn honeypot blocklist"))
        r, _ = self.req("GET", "/feed/%s/txt" % ("x" * len(tok)))
        self.assertEqual(r.status, 404)


if __name__ == "__main__":
    unittest.main()
