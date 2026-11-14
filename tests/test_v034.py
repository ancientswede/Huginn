# 0.34 The MalwareBazaar key on the Settings page, like the VirusTotal key.
import http.client, threading, time, unittest, urllib.parse
from http.server import ThreadingHTTPServer
from unittest import mock

from tests.helpers import app
from tests.test_v033 import Fake

KEY = "Abc123def456GHI789jkl012MNO345pq"
SHA = "c" * 64


def clean(con):
    with con:
        con.execute("DELETE FROM files")
        for k in ("mb_key", "mb_error", "mb_wait_until"):
            con.execute("DELETE FROM meta WHERE k=?", (k,))


class Lookup(unittest.TestCase):
    def setUp(self):
        self.con = app.connect()
        clean(self.con)
        with self.con:
            self.con.execute("INSERT INTO files(sha, mtime) VALUES(?,?)", (SHA, time.time()))

    def tearDown(self):
        clean(self.con)

    def run_lookup(self, answers):
        f = Fake(answers)
        with mock.patch.object(app, "api_urlopen", f):
            return app.mb_lookup(self.con), f

    def test_saved_key_is_used(self):
        app.set_meta(self.con, "mb_key", KEY)
        n, f = self.run_lookup({"mb-api.abuse.ch": {"query_status": "ok", "data": [{"signature": "Mirai", "tags": ["elf"], "first_seen": "2026-11-01"}]}})
        self.assertEqual(n, 1)
        self.assertEqual(f.calls[0][1].get("Auth-key"), KEY)
        self.assertEqual(app.file_family(self.con.execute("SELECT * FROM files WHERE sha=?", (SHA,)).fetchone()), ("Mirai", "MalwareBazaar"))

    def test_no_key_no_lookup(self):
        old = app.MB_KEY
        try:
            app.MB_KEY = ""
            n, f = self.run_lookup({"mb-api.abuse.ch": {"query_status": "ok"}})
            self.assertEqual((n, f.calls), (0, []))
        finally:
            app.MB_KEY = old

    def test_refused_key_noted(self):
        app.set_meta(self.con, "mb_key", KEY)
        n, _f = self.run_lookup({"mb-api.abuse.ch": {"query_status": "unknown_auth_key"}})
        self.assertEqual(n, 0)
        self.assertIn("unknown_auth_key", app.get_meta(self.con, "mb_error"))

    def test_key_test(self):
        for answer, want in (({"query_status": "hash_not_found"}, "ok"), ({"query_status": "ok", "data": []}, "ok"),
                             ({"query_status": "unknown_auth_key"}, "bad"), (401, "bad"), (429, "busy"), (500, "error")):
            with mock.patch.object(app, "api_urlopen", Fake({"mb-api.abuse.ch": answer})):
                self.assertEqual(app.mb_test(KEY), want, answer)


class SettingsKey(unittest.TestCase):
    PW = "test-password-mb-0034"

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
        with mock.patch.object(app, "api_urlopen", Fake({"mb-api.abuse.ch": answer})):
            return self.req("POST", "/settings/malwarebazaar", urllib.parse.urlencode({"key": key}), self.hdr({"Cookie": self.cookie}))

    def test_save_show_remove(self):
        con = app.connect()
        r, _ = self.post_key(KEY, {"query_status": "hash_not_found"})
        self.assertEqual(r.getheader("Location"), "/settings?ok=mb")
        self.assertEqual(app.get_meta(con, "mb_key"), KEY)
        _r, html = self.req("GET", "/settings?ok=mb", headers={"Cookie": self.cookie})
        self.assertIn("MalwareBazaar key saved. It works.", html)
        self.assertIn("<b>MalwareBazaar</b>", html)
        self.assertNotIn(KEY, html)
        self.assertNotIn(KEY[-6:], html)
        r, _ = self.req("POST", "/settings/malwarebazaar/remove", "", self.hdr({"Cookie": self.cookie}))
        self.assertEqual(r.getheader("Location"), "/settings?ok=mbdel")
        self.assertEqual(app.get_meta(con, "mb_key"), "")

    def test_refused_and_malformed(self):
        con = app.connect()
        app.set_meta(con, "mb_key", "")
        r, html = self.post_key(KEY, {"query_status": "unknown_auth_key"})
        self.assertEqual(r.status, 400)
        self.assertIn("refused", html)
        r, _ = self.post_key("bad key with spaces!", {"query_status": "ok"})
        self.assertEqual(r.status, 400)
        self.assertEqual(app.get_meta(con, "mb_key"), "")

    def test_other_origin_refused(self):
        r, _ = self.req("POST", "/settings/malwarebazaar", "key=" + KEY, {"Cookie": self.cookie, "Origin": "http://evil.example",
                                                                         "Content-Type": "application/x-www-form-urlencoded"})
        self.assertEqual(r.status, 403)


if __name__ == "__main__":
    unittest.main()
