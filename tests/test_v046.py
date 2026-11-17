# 0.46 Project Honey Pot (http:BL): DNS lookup per attacker address, key on the Settings page.
import http.client, json, socket, threading, time, unittest, urllib.parse
from http.server import ThreadingHTTPServer
from unittest import mock

from tests.helpers import app

KEY = "abcdefghijkl"
IP = "203.0.113.78"


def clean(con):
    with con:
        con.execute("DELETE FROM httpbl")
        con.execute("DELETE FROM ips WHERE ip IN (?, ?)", (IP, "2001:db8::7"))
        for k in ("hb_key", "hb_error", "hb_wait_until", "hb_day"):
            con.execute("DELETE FROM meta WHERE k=?", (k,))


def fake_dns(answers):
    # answers: name -> "a.b.c.d", or an int errno for gaierror. Records every name asked.
    asked = []
    real = socket.getaddrinfo

    def gai(name, *a, **k):
        if not str(name).endswith(".httpbl.org"):
            return real(name, *a, **k)          # the test's own HTTP client
        asked.append(name)
        v = answers.get(name, socket.EAI_NONAME)
        if isinstance(v, int):
            raise socket.gaierror(v, "fake")
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (v, 0))]
    return gai, asked


class Parse(unittest.TestCase):
    def test_query_name_and_answer(self):
        gai, asked = fake_dns({KEY + ".78.113.0.203.dnsbl.httpbl.org": "127.3.25.5"})
        with mock.patch.object(app.socket, "getaddrinfo", gai):
            self.assertEqual(app.hb_query(KEY, IP), [127, 3, 25, 5])
        self.assertEqual(asked, [KEY + ".78.113.0.203.dnsbl.httpbl.org"])

    def test_not_listed(self):
        for err in (socket.EAI_NONAME, -5):
            gai, _ = fake_dns({})
            with mock.patch.object(app.socket, "getaddrinfo", lambda *a, e=err, **k: (_ for _ in ()).throw(socket.gaierror(e, "x"))):
                self.assertIsNone(app.hb_query(KEY, IP))

    def test_dns_failure_raises(self):
        with mock.patch.object(app.socket, "getaddrinfo", lambda *a, **k: (_ for _ in ()).throw(socket.gaierror(socket.EAI_AGAIN, "x"))):
            with self.assertRaises(OSError):
                app.hb_query(KEY, IP)

    def test_parse(self):
        self.assertEqual(app.hb_parse(None), {"listed": False})
        self.assertEqual(app.hb_parse([127, 3, 25, 5]), {"listed": True, "engine": False, "days": 3, "threat": 25,
                                                        "types": ["suspicious", "comment spammer"]})
        self.assertTrue(app.hb_parse([127, 0, 9, 0])["engine"])
        with self.assertRaises(OSError):
            app.hb_parse([10, 0, 0, 1])          # a resolver that invents answers is never a listing

    def test_html_escapes_and_labels(self):
        h = app.hb_html({"listed": True, "engine": False, "days": 1, "threat": 40, "types": ["harvester", "<b>x</b>"]})
        self.assertIn("harvester", h)
        self.assertIn("threat 40", h)
        self.assertIn("1 day ago", h)
        self.assertNotIn("<b>x", h)
        self.assertEqual(app.hb_html({"listed": False}), "not listed")
        self.assertIn("search engine", app.hb_html({"listed": True, "engine": True, "days": 0}))

    def test_key_test(self):
        name = KEY + ".1.1.1.127.dnsbl.httpbl.org"
        for answers, want in (({name: "127.1.1.1"}, "ok"), ({}, "bad"), ({name: socket.EAI_AGAIN}, "error")):
            gai, asked = fake_dns(answers)
            with mock.patch.object(app.socket, "getaddrinfo", gai):
                self.assertEqual(app.hb_test(KEY), want)
            self.assertEqual(asked, [name])

    def test_key_shape(self):
        con = app.connect()
        clean(con)
        app.set_meta(con, "hb_key", "ABC def!")
        with mock.patch.object(app, "HB_KEY", ""):
            self.assertEqual(app.hb_key(con), "")
        with mock.patch.object(app, "HB_KEY", KEY):
            self.assertEqual(app.hb_key(con), KEY)
        clean(con)


class Lookup(unittest.TestCase):
    def setUp(self):
        self.con = app.connect()
        clean(self.con)
        now = time.time()
        with self.con:
            for ip in (IP, "2001:db8::7"):
                self.con.execute("INSERT INTO ips(ip, first, last, score, sessions, logins_ok, logins_fail, cmds, files, tcpip, exploits, tags) "
                                 "VALUES(?,?,?,?,0,0,0,0,0,0,0,'')", (ip, now, now, 10))

    def tearDown(self):
        clean(self.con)

    def run_lookup(self, answers):
        gai, asked = fake_dns(answers)
        with mock.patch.object(app.socket, "getaddrinfo", gai), mock.patch.object(app, "sendable_ip", lambda ip: True), \
                mock.patch.object(app.time, "sleep", lambda s: None):
            return app.hb_lookup(self.con), asked

    def test_no_key_does_nothing(self):
        with mock.patch.object(app, "HB_KEY", ""):
            n, asked = self.run_lookup({})
        self.assertEqual((n, asked), (0, []))

    def test_lookup_stores_and_skips_ipv6(self):
        app.set_meta(self.con, "hb_key", KEY)
        n, asked = self.run_lookup({KEY + ".78.113.0.203.dnsbl.httpbl.org": "127.2.60.2"})
        self.assertEqual(n, 1)
        self.assertEqual(len(asked), 1)
        self.assertEqual(app.hb_get(self.con, IP)["types"], ["harvester"])
        self.assertEqual(app.day_budget(self.con, "hb_day", 300)[2], 1)
        n, asked = self.run_lookup({})          # checked less than a week ago: not asked again
        self.assertEqual((n, asked), (0, []))

    def test_dns_error_pauses(self):
        app.set_meta(self.con, "hb_key", KEY)
        n, _ = self.run_lookup({KEY + ".78.113.0.203.dnsbl.httpbl.org": socket.EAI_AGAIN})
        self.assertEqual(n, 0)
        self.assertGreater(float(app.get_meta(self.con, "hb_wait_until", "0")), time.time())
        self.assertTrue(app.get_meta(self.con, "hb_error"))
        self.assertIsNone(app.hb_get(self.con, IP))
        n, asked = self.run_lookup({})
        self.assertEqual((n, asked), (0, []))

    def test_export_has_answer(self):
        with self.con:
            self.con.execute("INSERT INTO httpbl VALUES(?,?,?)", (IP, time.time(), json.dumps({"listed": False})))
        self.assertEqual(app.export_ip(IP)["project_honeypot"], {"listed": False})


class SettingsKey(unittest.TestCase):
    PW = "test-password-hb-0046"

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

    def post_key(self, key, answers):
        gai, _ = fake_dns(answers)
        with mock.patch.object(app.socket, "getaddrinfo", gai):
            return self.req("POST", "/settings/httpbl", urllib.parse.urlencode({"key": key}), self.hdr({"Cookie": self.cookie}))

    def test_save_show_remove(self):
        con = app.connect()
        r, _ = self.post_key(KEY.upper(), {KEY + ".1.1.1.127.dnsbl.httpbl.org": "127.1.1.1"})
        self.assertEqual(r.getheader("Location"), "/settings?ok=hb#httpbl")
        self.assertEqual(app.get_meta(con, "hb_key"), KEY)
        _r, html = self.req("GET", "/settings?ok=hb#httpbl", headers={"Cookie": self.cookie})
        self.assertIn("Project Honey Pot key saved. It works.", html)
        self.assertIn("<h3>Project Honey Pot</h3>", html)
        self.assertNotIn(KEY, html)
        r, _ = self.req("POST", "/settings/httpbl/remove", "", self.hdr({"Cookie": self.cookie}))
        self.assertEqual(r.getheader("Location"), "/settings?ok=hbdel#httpbl")
        self.assertEqual(app.get_meta(con, "hb_key"), "")

    def test_refused_malformed_and_dns_down(self):
        con = app.connect()
        app.set_meta(con, "hb_key", "")
        r, html = self.post_key(KEY, {})
        self.assertEqual(r.status, 400)
        self.assertIn("did not answer", html)
        r, _ = self.post_key("abc123", {})
        self.assertEqual(r.status, 400)
        r, _ = self.post_key(KEY, {KEY + ".1.1.1.127.dnsbl.httpbl.org": socket.EAI_AGAIN})
        self.assertEqual(r.status, 502)
        self.assertEqual(app.get_meta(con, "hb_key"), "")

    def test_other_origin_refused(self):
        r, _ = self.req("POST", "/settings/httpbl", "key=" + KEY, {"Cookie": self.cookie, "Origin": "http://evil.example",
                                                                   "Content-Type": "application/x-www-form-urlencoded"})
        self.assertEqual(r.status, 403)


if __name__ == "__main__":
    unittest.main()
