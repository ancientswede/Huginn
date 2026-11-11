# 0.24 Overview, Board layout: same data as the other pages, side by side, filtered by time range and service.
import json, re, time, unittest

from tests.helpers import app

NOW = time.time()
A, B, C = "198.51.100.71", "198.51.100.72", "198.51.100.73"


def ev(h, ts, ip, src, kind, sess, a, b):
    return ("board|%s" % h, ts, ip, src, kind, sess, a, b)


class Board(unittest.TestCase):
    def setUp(self):
        self.con = app.connect()
        with self.con:
            for t in ("events", "sessions", "ips", "seen", "enrich", "flags"):
                self.con.execute("DELETE FROM %s" % t)
            self.con.execute("DELETE FROM meta WHERE k='settings'")
        app._board_cache.clear()
        app._local.h12 = False
        rows = [ev("1", NOW - 600, A, "cowrie", "connect", "s1", "ssh", "22"),
                ev("2", NOW - 599, A, "cowrie", "login_fail", "s1", "root", "123456"),
                ev("3", NOW - 598, A, "cowrie", "login_ok", "s1", "root", "admin"),
                ev("4", NOW - 597, A, "cowrie", "cmd", "s1", "uname -a; <script>alert(1)</script>", None),
                ev("5", NOW - 590, A, "cowrie", "closed", "s1", "8.0", None)]
        rows += [ev("v%d" % i, NOW - 500 + i, B, "canary", "canary", None, "vnc", '{"VNC Password": "<Password was not in the common list>"}') for i in range(50)]
        rows += [ev("m1", NOW - 400, C, "canary", "canary", None, "mysql", "root / toor"),
                 ev("h1", NOW - 300, C, "canary", "canary", None, "http", "GET ⁄ (404)"),
                 ev("old", NOW - 3 * 86400, C, "canary", "canary", None, "redis", '{"CMD": "INFO", "ARGS": ""}')]
        app.store(self.con, rows)
        self.board()

    def tearDown(self):
        # Leave nothing behind for the other test files: same database, and row keys must not collide.
        with self.con:
            for t in ("events", "sessions", "ips", "seen", "enrich", "flags"):
                self.con.execute("DELETE FROM %s" % t)
            self.con.execute("DELETE FROM meta WHERE k='settings'")
        app._board_cache.clear()

    def board(self):
        st = app.settings(self.con)
        st["overview"] = "board"
        app.set_meta(self.con, "settings", json.dumps(st))
        app._board_cache.clear()

    def page(self, **qs):
        return app.v_overview(qs)

    def test_switch_is_remembered(self):
        self.assertIn('class="board"', self.page())
        st = app.settings(self.con)
        st["overview"] = "cards"
        app.set_meta(self.con, "settings", json.dumps(st))
        html = self.page()
        self.assertNotIn('class="board"', html)
        self.assertIn("value=board>Board</button>", html)

    def test_services_and_accepted(self):
        svcs = app.board_services(self.con, app.settings(self.con), "24h")
        self.assertEqual(svcs["ssh"]["logins"], 2)
        self.assertEqual(svcs["ssh"]["ok"], 1)
        self.assertIsNone(svcs["mysql"]["ok"])            # decoys do not say whether they let anyone in
        self.assertEqual(svcs["mysql"]["logins"], 1)
        self.assertEqual(svcs["http"]["logins"], 0)       # a request is not a login
        self.assertEqual(svcs["vnc"]["hits"], 50)
        self.assertNotIn("redis", svcs)                   # three days ago: outside 24h
        self.assertIn("redis", app.board_services(self.con, app.settings(self.con), "7d"))

    def test_feed_is_escaped_and_folded(self):
        html = self.page()
        self.assertNotIn("<script>alert(1)", html)
        self.assertIn("&lt;script&gt;", html)
        self.assertIn("×50", html)                       # 50 identical VNC rows are one line
        self.assertIn("VNC Password: &lt;Password was not in the common list&gt;", html)
        self.assertIn('class="tag t-orange">accepted', html)
        self.assertNotIn(" style=", html)

    def test_service_filter(self):
        html = self.page(svc="mysql")
        feed = html.split('class="card b-feed"')[1]
        self.assertIn("root / toor", feed)
        self.assertNotIn("uname", feed)
        self.assertIn('<tr class="sel">', html)
        d = app.board_detail(self.con, app.settings(self.con), "24h", "mysql")
        self.assertEqual(sum(d["logins"]), 1)
        self.assertEqual(sum(d["ips"]), 1)

    def test_unknown_service_and_range_are_ignored(self):
        html = self.page(svc="nope'><x", range="99y")
        self.assertIn("Last 24 hours", html)
        self.assertNotIn("nope'", html)
        self.assertNotIn('<tr class="sel">', html)

    def test_charts_cover_the_range(self):
        st = app.settings(self.con)
        d = app.board_detail(self.con, st, "24h", None)
        self.assertEqual(len(d["ips"]), 24)
        self.assertEqual(sum(d["logins"]), 3)             # 2 SSH + 1 MySQL
        d7 = app.board_detail(self.con, st, "7d", None)
        self.assertEqual(len(d7["ips"]), 42)

    def test_hidden_networks_are_left_out(self):
        with self.con:
            self.con.execute("INSERT INTO enrich(ip, fetched, ok, cc, asn) VALUES(?,?,1,'XX','64500')", (B, NOW))
        st = app.settings(self.con)
        st["hide_asn"] = ["64500"]
        app.set_meta(self.con, "settings", json.dumps(st))
        app._board_cache.clear()
        svcs = app.board_services(self.con, app.settings(self.con), "24h")
        self.assertNotIn("vnc", svcs)
        self.assertNotIn(B, self.page())

    def test_credentials_match_the_credentials_page(self):
        st = app.settings(self.con)
        d = app.board_detail(self.con, st, "24h", None)
        want = {}
        for _ts, _ip, _s, user, pw, _ok in app.cred_rows(self.con, time.time() - 86400):
            want[(user, pw)] = want.get((user, pw), 0) + 1
        self.assertEqual(dict(d["creds"]), want)
        self.assertEqual(dict(app.board_detail(self.con, st, "24h", "mysql")["creds"]), {("root", "toor"): 1})

    def test_board_text(self):
        self.assertEqual(app.board_text("tcpip", "1.2.3.4:443", None), "proxy -> 1.2.3.4:443")
        self.assertEqual(app.board_text("canary", "redis", '{"CMD": "INFO", "ARGS": ""}'), "CMD: INFO")
        self.assertIn("tarpit", app.board_text("tarpit", "40.5", "60001"))
        self.assertEqual(app.board_text("tarpit", "x", None), "held in the tarpit")


if __name__ == "__main__":
    unittest.main()
