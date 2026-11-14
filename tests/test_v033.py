# 0.33 VirusTotal verdicts for captured files (key on the Settings page) and GreyNoise for attacker addresses.
import http.client, io, json, threading, time, unittest, urllib.error, urllib.parse
from http.server import ThreadingHTTPServer
from unittest import mock

from tests.helpers import app

SHA1 = "a" * 64
SHA2 = "b" * 64
KEY = "0123456789abcdef" * 4
IP = "198.51.100.120"


class Resp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def http_error(url, code):
    return urllib.error.HTTPError(url, code, "x", {}, io.BytesIO(b"{}"))


class Fake:
    # Stands in for urllib.request.urlopen: answers by URL, records every request (never touches the network).
    def __init__(self, answers):
        self.answers, self.calls = answers, []

    def __call__(self, req, timeout=None):
        url = req.full_url if hasattr(req, "full_url") else req
        self.calls.append((url, dict(req.header_items()) if hasattr(req, "header_items") else {}))
        for part, ans in self.answers.items():
            if part in url:
                if isinstance(ans, int):
                    raise http_error(url, ans)
                return Resp(json.dumps(ans).encode())
        raise http_error(url, 404)


def clean(con):
    with con:
        for t in ("files", "vt", "greynoise", "ips", "enrich", "events"):
            con.execute("DELETE FROM %s" % t)
        for k in ("vt_key", "vt_day", "vt_wait_until", "vt_error", "gn_day", "gn_wait_until", "gn_error", "mb_wait_until"):
            con.execute("DELETE FROM meta WHERE k=?", (k,))


class VirusTotal(unittest.TestCase):
    def setUp(self):
        self.con = app.connect()
        clean(self.con)
        now = time.time()
        with self.con:
            self.con.execute("INSERT INTO files(sha, mtime) VALUES(?,?)", (SHA1, now))
            self.con.execute("INSERT INTO files(sha, mtime) VALUES(?,?)", (SHA2, now - 10))
        app.set_meta(self.con, "vt_key", KEY)

    def tearDown(self):
        clean(self.con)

    def run_lookup(self, answers, **kw):
        f = Fake(answers)
        with mock.patch.object(app, "api_urlopen", f):
            n = app.vt_lookup(self.con, pause=0, **kw)
        return n, f

    def test_found_and_novel(self):
        found = {"data": {"attributes": {"last_analysis_stats": {"malicious": 41, "suspicious": 2, "undetected": 19, "harmless": 0},
                                         "popular_threat_classification": {"suggested_threat_label": "trojan.mirai/gafgyt"},
                                         "first_submission_date": 1700000000}}}
        n, f = self.run_lookup({SHA1: found, SHA2: 404})
        self.assertEqual(n, 2)
        self.assertTrue(all(h.get("X-apikey") == KEY for _u, h in f.calls))
        v1, v2 = app.vt_get(SHA1, self.con), app.vt_get(SHA2, self.con)
        self.assertEqual((v1["found"], v1["mal"], v1["total"], v1["label"]), (True, 41, 62, "trojan.mirai/gafgyt"))
        self.assertEqual(v2, dict(v2, found=False))
        self.assertIn("41/62", app.vt_html(v1))
        self.assertIn("novel", app.vt_html(v2))
        self.assertEqual(app.file_family(None, "", SHA1), ("Mirai", "VirusTotal"))
        n, _f = self.run_lookup({})
        self.assertEqual(n, 0, "nothing is asked again right away")

    def test_rate_limit_pauses(self):
        n, _f = self.run_lookup({SHA1: 429, SHA2: 429})
        self.assertEqual(n, 0)
        self.assertGreater(float(app.get_meta(self.con, "vt_wait_until")), time.time() + 3000)
        n, f = self.run_lookup({SHA1: 404})
        self.assertEqual((n, f.calls), (0, []))

    def test_daily_allowance(self):
        old = app.VT_DAILY
        try:
            app.VT_DAILY = 1
            n, f = self.run_lookup({SHA1: 404, SHA2: 404})
            self.assertEqual((n, len(f.calls)), (1, 1))
            n, f = self.run_lookup({SHA2: 404})
            self.assertEqual((n, len(f.calls)), (0, 0))
        finally:
            app.VT_DAILY = old

    def test_no_key_no_lookup(self):
        app.set_meta(self.con, "vt_key", "")
        old = app.VT_KEY
        try:
            app.VT_KEY = ""
            n, f = self.run_lookup({SHA1: 404})
            self.assertEqual((n, f.calls), (0, []))
        finally:
            app.VT_KEY = old

    def test_bad_values_dropped(self):
        weird = {"data": {"attributes": {"last_analysis_stats": {"malicious": "<b>9</b>", "undetected": -5},
                                         "popular_threat_classification": {"suggested_threat_label": "<script>alert(1)</script>"}}}}
        self.run_lookup({SHA1: weird, SHA2: weird})
        v = app.vt_get(SHA1, self.con)
        self.assertEqual((v["mal"], v["total"], v["label"]), (0, 0, ""))
        self.assertEqual(app.vt_family({"label": "../../etc"}), "")


class GreyNoise(unittest.TestCase):
    def setUp(self):
        self.con = app.connect()
        clean(self.con)
        now = time.time()
        with self.con:
            for i, ip in enumerate((IP, "198.51.100.121", "10.0.0.5")):
                self.con.execute("INSERT INTO ips(ip, first, last, score) VALUES(?,?,?,?)", (ip, now, now, 50 - i))
            self.con.execute("INSERT INTO enrich(ip, fetched, ok, research) VALUES(?,?,1,0)", (IP, now))

    def tearDown(self):
        clean(self.con)

    def lookup(self, answers):
        f = Fake(answers)
        public = lambda ip: ip.startswith("198.51.100.")          # documentation addresses stand in for public ones here
        with mock.patch.object(app, "api_urlopen", f), mock.patch.object(app.time, "sleep", lambda s: None), \
                mock.patch.object(app, "sendable_ip", public):
            n = app.gn_lookup(self.con)
        return n, f

    def test_benign_scanner_is_research(self):
        n, f = self.lookup({IP: {"ip": IP, "noise": True, "riot": False, "classification": "benign", "name": "Censys\x07", "last_seen": "2026-11-13"},
                            "198.51.100.121": 404})
        self.assertEqual(n, 2)
        self.assertFalse(any("10.0.0.5" in u for u, _h in f.calls), "private addresses never leave Huginn")
        self.assertEqual(self.con.execute("SELECT research FROM enrich WHERE ip=?", (IP,)).fetchone()[0], 1)
        g = app.gn_get(self.con, IP)
        self.assertEqual((g["class"], g["name"], g["last"]), ("benign", "Censys", "2026-11-13"))
        self.assertIn("benign scanner", app.gn_html(g))
        self.assertEqual(app.gn_html(app.gn_get(self.con, "198.51.100.121")), "not seen scanning the internet")

    def test_malicious_is_not_research(self):
        self.lookup({IP: {"noise": True, "classification": "malicious", "name": "unknown"}})
        self.assertEqual(self.con.execute("SELECT research FROM enrich WHERE ip=?", (IP,)).fetchone()[0], 0)

    def test_junk_class_dropped(self):
        self.assertEqual(app.gn_parse({"noise": True, "classification": "<img>", "last_seen": "never"})["class"], "unknown")
        self.assertEqual(app.gn_parse({"last_seen": "x"})["last"], "")

    def test_limit_reached_pauses(self):
        n, _f = self.lookup({IP: 429})
        self.assertEqual(n, 0)
        self.assertGreater(float(app.get_meta(self.con, "gn_wait_until")), time.time() + 3600)
        self.assertIn("allowance", app.get_meta(self.con, "gn_error"))


class SettingsKey(unittest.TestCase):
    PW = "test-password-vt-0033"

    @classmethod
    def setUpClass(cls):
        con = app.connect()
        app.set_meta(con, "pw", app.hash_pw(cls.PW))
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), app.Handler)
        cls.port = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        r, _ = cls.req("POST", "/login", urllib.parse.urlencode({"password": cls.PW}), cls.hdr())
        cls.cookie = (r.getheader("Set-Cookie") or "").split(";")[0]

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        clean(app.connect())

    @classmethod
    def hdr(cls, extra=None):
        h = {"Origin": "http://127.0.0.1:%d" % cls.port, "Content-Type": "application/x-www-form-urlencoded"}
        h.update(extra or {})
        return h

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

    def post_key(self, key, answer):
        with mock.patch.object(app, "api_urlopen", Fake({app.VT_TEST_SHA: answer})):
            return self.req("POST", "/settings/virustotal", urllib.parse.urlencode({"key": key}), self.hdr({"Cookie": self.cookie}))

    def test_save_test_and_never_show(self):
        con = app.connect()
        r, _ = self.post_key(KEY.upper(), {"data": {}})
        self.assertEqual((r.status, r.getheader("Location")), (303, "/settings?ok=vt"))
        self.assertEqual(app.get_meta(con, "vt_key"), KEY)
        r, html = self.req("GET", "/settings?ok=vt", headers={"Cookie": self.cookie})
        self.assertIn("It works", html)
        self.assertIn("a key saved here", html)
        self.assertNotIn(KEY, html)
        self.assertNotIn(KEY[-8:], html)
        r, _ = self.req("POST", "/settings/virustotal/remove", "", self.hdr({"Cookie": self.cookie}))
        self.assertEqual(r.getheader("Location"), "/settings?ok=vtdel")
        self.assertEqual(app.get_meta(con, "vt_key"), "")

    def test_refused_and_malformed_keys_not_saved(self):
        con = app.connect()
        app.set_meta(con, "vt_key", "")
        r, html = self.post_key(KEY, 401)
        self.assertEqual(r.status, 400)
        self.assertIn("refused", html)
        r, _ = self.post_key("not-a-key", {"data": {}})
        self.assertEqual(r.status, 400)
        self.assertEqual(app.get_meta(con, "vt_key"), "")

    def test_needs_login_and_origin(self):
        app.set_meta(app.connect(), "vt_key", "")
        r, _ = self.req("POST", "/settings/virustotal", "key=" + KEY, self.hdr())          # no login
        self.assertIn(r.status, (303, 401, 403))
        self.assertNotEqual(r.getheader("Location"), "/settings?ok=vt")
        self.assertEqual(app.get_meta(app.connect(), "vt_key", ""), "")
        r, _ = self.req("POST", "/settings/virustotal", "key=" + KEY, {"Cookie": self.cookie, "Origin": "http://evil.example",
                                                                       "Content-Type": "application/x-www-form-urlencoded"})
        self.assertEqual(r.status, 403)


if __name__ == "__main__":
    unittest.main()
