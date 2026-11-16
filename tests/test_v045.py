# 0.45 Attackers that come back: "returned" after RETURN_DAYS quiet days, "stepped-up" when they then get further than before.
import json, time, unittest
from unittest import mock

from tests.helpers import app
from tests.test_polish import row

DAY = 86400.0
NOW = (time.time() // DAY) * DAY + 12 * 3600          # midday UTC today, so a day count never depends on the hour the test runs
A, B, C = "198.51.100.171", "198.51.100.172", "198.51.100.173"


class Base(unittest.TestCase):
    def setUp(self):
        self.con = app.connect()
        self.clean()

    def tearDown(self):
        self.clean()

    def clean(self):
        with self.con:
            for t in ("events", "sessions", "ips", "capped"):
                self.con.execute("DELETE FROM %s" % t)
            self.con.execute("DELETE FROM meta WHERE k IN ('settings','ntfy_returned','ntfy_last','returned_days')")

    def sess(self, sid, ip, ts, lo=0, cmds=0, files=0, tcpip=0):
        self.con.execute("INSERT INTO sessions(session,ip,start,end,proto,port,logins_ok,logins_fail,cmds,files,tcpip,exploits) "
                         "VALUES(?,?,?,?,'ssh',2225,?,0,?,?,?,0)", (sid, ip, ts, ts + 30, lo, cmds, files, tcpip))

    def ip(self, ip):
        with self.con:
            app.recompute_ip(self.con, ip)
        return self.con.execute("SELECT * FROM ips WHERE ip=?", (ip,)).fetchone()


class Tags(Base):
    def test_knock_then_commands_after_quiet_spell(self):
        with self.con:
            self.sess("a1", A, NOW - 20 * DAY)                  # connected only
            self.sess("a2", A, NOW - 1 * DAY, lo=1, cmds=6)     # 18 quiet days later: logs in and runs commands
        r = self.ip(A)
        tags = r["tags"].split(",")
        self.assertIn("returned", tags)
        self.assertIn("stepped-up", tags)
        back = app.return_info(self.con, A)
        self.assertEqual(back[0], 18)
        self.assertEqual((back[2], back[3]), (1, 3))
        self.assertIn(("stepped up", 5), app.score_parts(2, 1, 0, 6, 0, 0, 0, [], stepped=True))
        self.assertEqual(r["score"], sum(v for _k, v in app.score_parts(2, 1, 0, 6, 0, 0, 0, [], stepped=True)))
        self.assertNotIn("Breakdown unavailable", app.score_html(r))

    def test_same_work_again_is_only_returned(self):
        with self.con:
            self.sess("b1", B, NOW - 30 * DAY, lo=1, cmds=4)
            self.sess("b2", B, NOW - 2 * DAY, lo=1, cmds=4)
        tags = self.ip(B)["tags"].split(",")
        self.assertIn("returned", tags)
        self.assertNotIn("stepped-up", tags)

    def test_short_gap_and_decoys_count_as_presence(self):
        with self.con:
            self.sess("c1", C, NOW - 20 * DAY)
            # The decoy hits fill the gap: no day without activity for 7 or more days in a row.
            self.con.executemany("INSERT OR IGNORE INTO events(h,ts,ip,src,kind,session,a,b) VALUES(?,?,?,?,?,?,?,?)",
                                 [row(C, NOW - d * DAY) for d in (15, 10, 5)])
            self.sess("c2", C, NOW - 1 * DAY, lo=1, cmds=3)
        tags = self.ip(C)["tags"].split(",")
        self.assertNotIn("returned", tags)
        self.assertNotIn("stepped-up", tags)

    def test_quiet_days_threshold(self):
        with self.con:
            self.sess("d1", A, NOW - 8 * DAY)       # days d and d+8: 7 quiet days between them, exactly the default
            self.sess("d2", A, NOW, cmds=1)
        self.assertIn("returned", self.ip(A)["tags"].split(","))
        with self.con:
            self.con.execute("DELETE FROM sessions")
            self.sess("d3", A, NOW - 7 * DAY)       # 6 quiet days: not yet
            self.sess("d4", A, NOW, cmds=1)
        self.assertNotIn("returned", self.ip(A)["tags"].split(","))

    def test_help_and_filters(self):
        _s, tags = app.score_and_tags(1, 0, 0, 3, 0, 0, 0, [], 0, ["ssh"], back=(9, NOW, 0, 3))
        for t in tags.split(","):
            self.assertTrue(app.TAG_HELP.get(t), t)
        self.assertIn("stepped-up", app.HOT_TAGS)
        self.assertIn("stepped up", app.SCORE_HELP)
        html = app.v_help()
        self.assertIn("returned", html)
        self.assertIn("stepped-up", html)


class Page(Base):
    def test_story_says_when_and_how(self):
        with self.con:
            self.sess("e1", A, NOW - 12 * DAY)
            self.sess("e2", A, NOW - 1 * DAY, tcpip=1)
        story = app.ip_story(self.con, self.ip(A))
        self.assertIn("Came back on %s after 10 quiet days" % time.strftime("%Y-%m-%d", time.gmtime(NOW - DAY)), story)
        self.assertIn("connected before, left files or used it as a proxy since.", story)


class Alert(Base):
    def test_one_alert_per_return(self):
        with self.con:
            self.sess("f1", A, NOW - 20 * DAY)
            self.sess("f2", A, time.time() - 600, lo=1, cmds=5)
            app.recompute_ip(self.con, A)
            app.set_meta(self.con, "ntfy_last", time.time() - 7200)
        with mock.patch.object(app, "NTFY_URL", "http://ntfy.invalid/x"), mock.patch.object(app, "ntfy_post") as post:
            app.notify(self.con)
        self.assertIn("Came back and got further: %s (ran commands)" % A, post.call_args[0][0])
        self.assertEqual(post.call_args[0][2], 4)
        with self.con:
            app.set_meta(self.con, "ntfy_last", time.time() - 7200)
        with mock.patch.object(app, "NTFY_URL", "http://ntfy.invalid/x"), mock.patch.object(app, "ntfy_post") as post:
            app.notify(self.con)
        self.assertFalse(post.called and "Came back" in post.call_args[0][0])

    def test_switch_off_and_old_settings(self):
        app.set_meta(self.con, "settings", json.dumps({"notify_events": ["bait"], "v": 3}))
        self.assertIn("returned", app.settings(self.con)["notify_events"])      # saved before 0.45: the new alert once
        app.set_meta(self.con, "settings", json.dumps({"notify_events": ["bait"], "v": 4}))
        self.assertNotIn("returned", app.settings(self.con)["notify_events"])   # turned off on purpose: stays off


class Setting(Base):
    def test_quiet_days_from_settings_page(self):
        with self.con:
            self.sess("h1", A, NOW - 11 * DAY)          # 10 quiet days
            self.sess("h2", A, NOW - 0 * DAY, cmds=2)
        self.assertIn("returned", self.ip(A)["tags"].split(","))
        html = app.v_settings()
        self.assertIn('name=return_days', html)
        self.assertIn('<option value="7" selected>7 days</option>', html)
        self.assertTrue(app.save_settings({"scope": "views", "return_days": "14"}, {}))   # a click: every stored attacker again
        self.assertEqual(app.return_days(self.con), 14)
        self.assertNotIn("returned", self.con.execute("SELECT tags FROM ips WHERE ip=?", (A,)).fetchone()[0].split(","))
        self.assertTrue(app.save_settings({"scope": "views", "return_days": "5"}, {}))
        self.assertIn("returned", self.con.execute("SELECT tags FROM ips WHERE ip=?", (A,)).fetchone()[0].split(","))

    def test_odd_values_ignored(self):
        for bad in ("0", "-3", "abc", "99999", "8"):
            app.save_settings({"scope": "views", "return_days": bad}, {})
            self.assertEqual(app.return_days(self.con), 7, bad)
        app.set_meta(self.con, "settings", json.dumps({"return_days": "nonsense", "v": 4}))
        self.assertEqual(app.return_days(self.con), 7)


class Backfill(Base):
    def test_start_tags_stored_attackers(self):
        with self.con:
            self.sess("g1", B, NOW - 20 * DAY)
            self.sess("g2", B, NOW - 1 * DAY, cmds=2)
            app.recompute_ip(self.con, B)
            self.con.execute("UPDATE ips SET tags='' WHERE ip=?", (B,))       # as an older version stored it
            self.con.execute("DELETE FROM meta WHERE k='returned_days'")
        app.init_db()
        self.assertIn("stepped-up", self.con.execute("SELECT tags FROM ips WHERE ip=?", (B,)).fetchone()[0])


if __name__ == "__main__":
    unittest.main()
