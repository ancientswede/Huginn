# 0.37 The GreyNoise key on the Settings page, like the VirusTotal and MalwareBazaar keys.
import http.client, threading, time, unittest, urllib.parse
from http.server import ThreadingHTTPServer
from unittest import mock

from tests.helpers import app
from tests.test_v033 import Fake

KEY = "Abc123def456GHI789jkl012MNO345pq"
SHA = "c" * 64


IP = "203.0.113.77"


def clean(con):
    with con:
        con.execute("DELETE FROM greynoise")
        con.execute("DELETE FROM ips WHERE ip=?", (IP,))
        for k in ("gn_key", "gn_error", "gn_wait_until", "gn_day"):
            con.execute("DELETE FROM meta WHERE k=?", (k,))


class Lookup(unittest.TestCase):
    def setUp(self):
        self.con = app.connect()
        clean(self.con)
        now = time.time()
        with self.con:
            self.con.execute("INSERT INTO ips(ip, first, last, score, sessions, logins_ok, logins_fail, cmds, files, tcpip, exploits, tags) "
                             "VALUES(?,?,?,?,0,0,0,0,0,0,0,'')", (IP, now, now, 10))

    def tearDown(self):
        clean(self.con)

    def run_lookup(self, answers):
        f = Fake(answers)
        with mock.patch.object(app, "api_urlopen", f), mock.patch.object(app, "sendable_ip", lambda ip: True), \
                mock.patch.object(app.time, "sleep", lambda s: None):
            return app.gn_lookup(self.con, limit=1), f

    def test_saved_key_is_used(self):
        app.set_meta(self.con, "gn_key", KEY)
        n, f = self.run_lookup({IP: {"ip": IP, "noise": True, "classification": "malicious"}})
        self.assertEqual(n, 1)
        self.assertEqual(f.calls[0][1].get("Key"), KEY)

    def test_no_key_no_header(self):
        with mock.patch.object(app, "GN_KEY", ""):
            n, f = self.run_lookup({IP: {"ip": IP, "noise": False}})
        self.assertEqual(n, 1)
        self.assertNotIn("Key", f.calls[0][1])

    def test_daily_follows_key(self):
        with mock.patch.object(app, "GN_DAILY", -1), mock.patch.object(app, "GN_KEY", ""):
            self.assertEqual(app.gn_daily(self.con), 20)
            app.set_meta(self.con, "gn_key", KEY)
            self.assertEqual(app.gn_daily(self.con), 40)
        with mock.patch.object(app, "GN_DAILY", 0):
            self.assertEqual(app.gn_daily(self.con), 0)
            self.assertEqual(self.run_lookup({IP: {}})[0], 0)

    def test_bad_saved_value_ignored(self):
        app.set_meta(self.con, "gn_key", "bad key!")
        with mock.patch.object(app, "GN_KEY", ""):
            self.assertEqual(app.gn_key(self.con), "")

    def test_key_test(self):
        for answer, want in (({"message": "pong"}, "ok"), (401, "bad"), (403, "bad"), (429, "busy"), (500, "error")):
            f = Fake({"api.greynoise.io/ping": answer})
            with mock.patch.object(app, "api_urlopen", f):
                self.assertEqual(app.gn_test(KEY), want, answer)
            self.assertEqual(f.calls[0][0], "https://api.greynoise.io/ping")
            self.assertEqual(f.calls[0][1].get("Key"), KEY)


class SettingsKey(unittest.TestCase):
    PW = "test-password-gn-0037"

    @classmethod
    def setUpClass(cls):
        app.set_meta(app.connect(), "pw", app.hash_pw(cls.PW))
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
        with mock.patch.object(app, "api_urlopen", Fake({"api.greynoise.io/ping": answer})):
            return self.req("POST", "/settings/greynoise", urllib.parse.urlencode({"key": key}), self.hdr({"Cookie": self.cookie}))

    def test_save_show_remove(self):
        con = app.connect()
        r, _ = self.post_key(KEY, {"message": "pong"})
        self.assertEqual(r.getheader("Location"), "/settings?ok=gn")
        self.assertEqual(app.get_meta(con, "gn_key"), KEY)
        _r, html = self.req("GET", "/settings?ok=gn", headers={"Cookie": self.cookie})
        self.assertIn("GreyNoise key saved. It works.", html)
        self.assertIn("<b>GreyNoise</b>", html)
        self.assertNotIn(KEY, html)
        self.assertNotIn(KEY[-6:], html)
        r, _ = self.req("POST", "/settings/greynoise/remove", "", self.hdr({"Cookie": self.cookie}))
        self.assertEqual(r.getheader("Location"), "/settings?ok=gndel")
        self.assertEqual(app.get_meta(con, "gn_key"), "")

    def test_refused_and_malformed(self):
        con = app.connect()
        app.set_meta(con, "gn_key", "")
        r, html = self.post_key(KEY, 401)
        self.assertEqual(r.status, 400)
        self.assertIn("refused", html)
        r, _ = self.post_key("bad key with spaces!", {"message": "pong"})
        self.assertEqual(r.status, 400)
        self.assertEqual(app.get_meta(con, "gn_key"), "")

    def test_other_origin_refused(self):
        r, _ = self.req("POST", "/settings/greynoise", "key=" + KEY, {"Cookie": self.cookie, "Origin": "http://evil.example",
                                                                         "Content-Type": "application/x-www-form-urlencoded"})
        self.assertEqual(r.status, 403)


if __name__ == "__main__":
    unittest.main()
