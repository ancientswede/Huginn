# 0.38 Prometheus metrics on /metrics (off by default, bearer token) and JSON logs.
import http.client, io, json, threading, time, unittest, urllib.parse
from http.server import ThreadingHTTPServer
from unittest import mock

from tests.helpers import app

IP = "203.0.113.91"


def clean(con):
    with con:
        for k in ("metrics_on", "metrics_token", "metric_totals"):
            con.execute("DELETE FROM meta WHERE k=?", (k,))
        con.execute("DELETE FROM events WHERE ip=?", (IP,))
        con.execute("DELETE FROM ips WHERE ip=?", (IP,))
    app._metrics_cache["at"] = 0


class Counters(unittest.TestCase):
    def setUp(self):
        self.con = app.connect()
        clean(self.con)

    def tearDown(self):
        clean(self.con)

    def rows(self, n, src="canary", kind="canary", a="vnc"):
        now = time.time()
        return [("h-v038-%s-%s-%d-%f" % (src, kind, i, now), now - i, IP, src, kind, None, a, "x") for i in range(n)]

    def test_store_counts_new_rows_only(self):
        app.store(self.con, self.rows(3))
        app.store(self.con, self.rows(3)[:0] + [r for r in self.rows(2, kind="canary", a="http")])
        tot = json.loads(app.get_meta(self.con, "metric_totals"))
        self.assertEqual(tot.get("canary|canary|vnc"), 3)
        self.assertEqual(tot.get("canary|canary|http"), 2)
        before = dict(tot)
        rows = self.rows(1)
        app.store(self.con, rows)
        app.store(self.con, rows)                     # the same row again is not new
        tot = json.loads(app.get_meta(self.con, "metric_totals"))
        self.assertEqual(tot["canary|canary|vnc"], before["canary|canary|vnc"] + 1)

    def test_odd_service_becomes_other(self):
        self.assertEqual(app.metric_svc("canary", 'x"} 1\nhuginn_fake 9'), "other")
        self.assertEqual(app.metric_svc("cowrie", "anything"), "")
        self.assertEqual(app.metric_svc("traps", "smtp"), "smtp")

    def test_metrics_text(self):
        app.store(self.con, self.rows(2, a="redis"))
        txt = app.metrics_text(self.con)
        for name in ("huginn_info{", "huginn_events_ingested_total{", "huginn_events_last_24h{", "huginn_attackers{window=\"24h\"}",
                     "huginn_blocklist_entries ", "huginn_last_sync_timestamp_seconds ", "huginn_lookups_daily_limit{service=\"greynoise\"}",
                     "huginn_database_bytes "):
            self.assertIn(name, txt)
        self.assertIn('huginn_events_ingested_total{source="canary",kind="canary",service="redis"} 2', txt)
        self.assertNotIn(IP, txt, "no addresses in metrics")
        for line in txt.splitlines():
            self.assertTrue(line.startswith("# ") or line.startswith("huginn_"), line)

    def test_label_escaping(self):
        self.assertEqual(app._mlabel('a"b\\c\nd'), 'a\\"b\\\\c\\nd')


class Logs(unittest.TestCase):
    def capture(self, fmt, level, *args, **kw):
        buf = io.StringIO()
        with mock.patch.object(app, "LOG_FORMAT", fmt), mock.patch.object(app, "LOG_LEVEL", level), mock.patch.object(app.sys, "stderr", buf):
            app.log(*args, **kw)
        return buf.getvalue()

    def test_json_line(self):
        out = self.capture("json", 20, "info", "sync", "done\nfake line", new=3, secs=1.5)
        self.assertEqual(out.count("\n"), 1)
        d = json.loads(out)
        self.assertEqual((d["app"], d["level"], d["event"], d["new"], d["secs"]), ("huginn", "info", "sync", 3, 1.5))
        self.assertEqual(d["msg"], "done\nfake line")
        self.assertTrue(d["ts"].endswith("Z"))

    def test_text_line_has_no_control_characters(self):
        out = self.capture("text", 20, "warning", "login_failed", "a\nb c\x1b[31m", client="x\ry")
        self.assertEqual(out.count("\n"), 1)
        self.assertTrue(out.startswith("WARNING login_failed: a\\x0ab\\u2028c\\x1b[31m client=x\\x0dy"))

    def test_level_filter(self):
        self.assertEqual(self.capture("text", 30, "info", "sync"), "")
        self.assertNotEqual(self.capture("text", 30, "warning", "x"), "")

    def test_errors_logged_once(self):
        con = app.connect()
        buf = io.StringIO()
        with mock.patch.object(app, "LOG_FORMAT", "json"), mock.patch.object(app, "LOG_LEVEL", 20), mock.patch.object(app.sys, "stderr", buf):
            app.set_meta(con, "v038_error", "boom")
            app.set_meta(con, "v038_error", "boom")
            app.set_meta(con, "v038_error", "")
        with con:
            con.execute("DELETE FROM meta WHERE k='v038_error'")
        lines = buf.getvalue().splitlines()
        self.assertEqual(len(lines), 1)
        self.assertEqual(json.loads(lines[0])["event"], "v038_error")


class Endpoint(unittest.TestCase):
    PW = "test-password-metrics-0038"

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

    def setUp(self):
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

    def test_off_by_default(self):
        r, _ = self.req("GET", "/metrics")
        self.assertEqual(r.status, 404)
        _r, html = self.req("GET", "/settings", headers={"Cookie": self.cookie})
        self.assertIn("<h3>Metrics</h3>", html)
        self.assertIn("Off. Nothing is served", html)

    def test_turn_on_scrape_rotate_off(self):
        con = app.connect()
        r, _ = self.req("POST", "/settings/metrics", "on=1", self.hdr({"Cookie": self.cookie}))
        self.assertEqual(r.getheader("Location"), "/settings?ok=mon")
        tok = app.get_meta(con, "metrics_token")
        self.assertGreaterEqual(len(tok), 40)
        r, _ = self.req("GET", "/metrics")
        self.assertEqual(r.status, 401)
        r, _ = self.req("GET", "/metrics", headers={"Authorization": "Bearer wrong-token-0000000000"})
        self.assertEqual(r.status, 401)
        r, body = self.req("GET", "/metrics", headers={"Authorization": "Bearer " + tok})
        self.assertEqual(r.status, 200)
        self.assertTrue(r.getheader("Content-Type").startswith("text/plain; version=0.0.4"))
        self.assertIn("huginn_info{version=\"%s\"} 1" % app.HUGINN_VERSION, body)
        _r, html = self.req("GET", "/settings?ok=mon", headers={"Cookie": self.cookie})
        self.assertIn("/metrics", html)
        self.assertIn("job_name: huginn", html)
        r, _ = self.req("POST", "/settings/metrics/token", "", self.hdr({"Cookie": self.cookie}))
        self.assertEqual(r.getheader("Location"), "/settings?ok=mtok")
        r, _ = self.req("GET", "/metrics", headers={"Authorization": "Bearer " + tok})
        self.assertEqual(r.status, 401, "the old token stops working")
        self.req("POST", "/settings/metrics", "on=0", self.hdr({"Cookie": self.cookie}))
        r, _ = self.req("GET", "/metrics", headers={"Authorization": "Bearer " + app.get_meta(con, "metrics_token")})
        self.assertEqual(r.status, 404)

    def test_needs_login_and_same_origin(self):
        r, _ = self.req("POST", "/settings/metrics", "on=1", self.hdr())
        self.assertEqual(r.status, 401)
        r, _ = self.req("POST", "/settings/metrics", "on=1", {"Cookie": self.cookie, "Origin": "http://evil.example",
                                                             "Content-Type": "application/x-www-form-urlencoded"})
        self.assertEqual(r.status, 403)
        self.assertNotEqual(app.get_meta(app.connect(), "metrics_on"), "1")

    def test_env_token(self):
        with mock.patch.object(app, "METRICS_TOKEN", "env-token-1234567890abcdef"):
            r, _ = self.req("GET", "/metrics", headers={"Authorization": "Bearer env-token-1234567890abcdef"})
            self.assertEqual(r.status, 200)
            _r, html = self.req("GET", "/settings", headers={"Cookie": self.cookie})
            self.assertIn("HUGINN_METRICS_TOKEN", html)
            self.assertNotIn("env-token-1234567890abcdef", html)


if __name__ == "__main__":
    unittest.main()
