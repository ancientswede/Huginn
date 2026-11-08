# The "New" page: the register of first sightings, Mark reviewed / Undo, and the score breakdown.
import time, unittest

from tests.helpers import app

NOW = time.time()


def row(ip, kind, session, a=None, b=None, ago=0):
    ts = NOW - ago
    return ("new|%s|%s|%s|%s|%s" % (ip, kind, session, a, b), ts, ip, "cowrie", kind, session, a, b)


class Shapes(unittest.TestCase):
    def test_commands(self):
        self.assertEqual(app.cmd_shape("wget http://203.0.113.5:8080/a1"), app.cmd_shape("wget http://198.51.100.7:81/a2"))
        self.assertEqual(app.cmd_shape(r"echo -ne '\x7f\x45\x4c'"), "echo -ne '<bytes>'")
        self.assertEqual(app.cmd_shape("curl 2001:db8:1:2::5"), app.cmd_shape("curl 2001:db8:9:9::7"))

    def test_random_marker_inside_a_word(self):
        self.assertEqual(app.cmd_shape("echo check_2c25458b9b7e8e4d16"), "echo check_<hex>")

    def test_compressed_ipv6(self):
        self.assertEqual(app.cmd_shape("curl http://[2001:db8::abcd]/a"), app.cmd_shape("curl http://[2001:db8::beef]/a"))
        self.assertIn("<ip>", app.cmd_shape("curl http://[2001:db8::abcd]/a"))

    def test_a_clock_time_is_no_address(self):
        self.assertEqual(app.cmd_shape("date 12:30:45"), "date <n>:<n>:<n>")

    def test_long_paths_survive(self):
        p = "cat /usr/local/share/something/quite/long/config"
        self.assertEqual(app.cmd_shape(p), p)

    def test_only_the_payload_is_replaced(self):
        self.assertTrue(app.cmd_shape(r"cd /tmp; echo '\x41\x42' > a").startswith("cd /tmp;"))

    def test_passwords(self):
        self.assertEqual(app.pw_shape("Summer2026!"), "Aa0#")
        self.assertEqual(app.pw_shape(""), "")


class Register(unittest.TestCase):
    def setUp(self):
        self.con = app.connect()
        with self.con:
            for t in ("events", "sessions", "ips", "seen"):
                self.con.execute("DELETE FROM %s" % t)
            self.con.execute("DELETE FROM meta WHERE k IN ('seen_done','review_at','review_prev')")

    def seen(self, kind):
        return {r["key"]: r for r in self.con.execute("SELECT * FROM seen WHERE kind=?", (kind,))}

    def test_backfill_dates_history_by_log_time(self):
        app.store(self.con, [row("198.51.100.20", "cmd", "s1", "uname -a", ago=3 * 86400)])
        self.assertLess(self.seen("cmd")["uname -a"]["observed"], NOW - 2 * 86400)

    def test_late_line_counts_as_new_when_it_arrives(self):
        app.store(self.con, [row("198.51.100.20", "cmd", "s1", "uname -a", ago=10)])
        # A line logged long ago that only reaches Huginn now is still new to Huginn.
        app.store(self.con, [row("198.51.100.21", "cmd", "s2", "cat /proc/cpuinfo", ago=9 * 86400)])
        self.assertGreater(self.seen("cmd")["cat /proc/cpuinfo"]["observed"], NOW - 60)

    def test_same_shape_is_one_row_and_counts_runs(self):
        app.store(self.con, [row("198.51.100.20", "cmd", "s1", "ping -c 4 203.0.113.1", ago=10)])
        app.store(self.con, [row("198.51.100.21", "cmd", "s2", "ping -c 9 203.0.113.2", ago=5)])
        got = self.seen("cmd")
        self.assertEqual(len(got), 1)
        self.assertEqual(next(iter(got.values()))["n"], 2)

    def test_no_rows_from_unfinished_sessions(self):
        app.store(self.con, [row("198.51.100.20", "connect", "s1", "ssh", "2225", ago=10), row("198.51.100.20", "cmd", "s1", "id", ago=9)])
        self.assertEqual(self.seen("script"), {})
        app.store(self.con, [row("198.51.100.20", "closed", "s1", "4.0", ago=5)])
        self.assertEqual(len(self.seen("script")), 1)

    def test_new_rows_found_even_if_rowids_are_reused(self):
        app.store(self.con, [row("198.51.100.20", "cmd", "s1", "uname -a", ago=5)])
        with self.con:
            self.con.execute("DELETE FROM events")                 # retention took everything: the next rowid starts over
        app.store(self.con, [row("198.51.100.21", "cmd", "s2", "cat /proc/version", ago=1)])
        self.assertIn("cat /proc/version", self.seen("cmd"))

    def test_backfill_keeps_the_earliest_sighting(self):
        with self.con:
            self.con.execute("INSERT INTO events(h,ts,ip,src,kind,session,a,b) VALUES('a',?, '198.51.100.20','cowrie','cmd','s1','id',NULL)", (NOW - 100,))
            self.con.execute("INSERT INTO events(h,ts,ip,src,kind,session,a,b) VALUES('b',?, '198.51.100.21','cowrie','cmd','s2','id',NULL)", (NOW - 900,))
        app.note_seen(self.con, 0)
        r = self.seen("cmd")["id"]
        self.assertEqual((r["observed"], r["ip"], r["n"]), (NOW - 900, "198.51.100.21", 2))

    def test_scripts_differing_only_in_random_parts_are_one(self):
        for s, mark in (("s1", "1f3a5b7c9d"), ("s2", "aa11bb22cc")):
            app.store(self.con, [row("198.51.100.20", "connect", s, "ssh", "2225", ago=10), row("198.51.100.20", "cmd", s, "echo check_" + mark, ago=9),
                                 row("198.51.100.20", "closed", s, "4.0", ago=5)])
        got = self.seen("script")
        self.assertEqual(len(got), 1)
        self.assertEqual(next(iter(got.values()))["n"], 2)

    def test_a_failure_does_not_stop_collecting(self):
        real = app.note_seen
        app.note_seen = lambda con, after: 1 / 0
        try:
            self.assertEqual(app.store(self.con, [row("198.51.100.20", "cmd", "s1", "id", ago=1)]), 1)
        finally:
            app.note_seen = real
        self.assertIn("division", app.get_meta(self.con, "last_seen_error"))


class Review(unittest.TestCase):
    def setUp(self):
        self.con = app.connect()
        with self.con:
            self.con.execute("DELETE FROM seen")
            self.con.execute("DELETE FROM meta WHERE k IN ('review_at','review_prev')")
            for i, t in enumerate((NOW - 300, NOW - 200, NOW - 100)):
                self.con.execute("INSERT INTO seen(kind,key,observed,ex,n) VALUES('cmd',?,?,?,1)", ("k%d" % i, t, "x"))

    def fresh(self):
        return self.con.execute("SELECT COUNT(*) FROM seen WHERE observed>?", (app.review_since(self.con),)).fetchone()[0]

    def test_marks_up_to_what_was_on_the_page(self):
        app.mark_reviewed(self.con, NOW - 200)
        self.assertEqual(self.fresh(), 1)

    def test_nothing_left_after_marking_all(self):
        app.mark_reviewed(self.con, NOW - 100)
        self.assertEqual(self.fresh(), 0)

    def test_old_tab_cannot_move_back(self):
        app.mark_reviewed(self.con, NOW - 100)
        app.mark_reviewed(self.con, NOW - 300)
        self.assertEqual(app.review_at(self.con), NOW - 100)

    def test_future_or_nonsense_is_refused(self):
        for v in (NOW + 999, float("nan"), float("inf"), -5.0):
            app.mark_reviewed(self.con, v)
            self.assertEqual(app.review_at(self.con), 0, v)

    def test_double_click_keeps_undo_useful(self):
        app.mark_reviewed(self.con, NOW - 200)
        app.mark_reviewed(self.con, NOW - 200)
        self.assertEqual(app.get_meta(self.con, "review_prev"), "")

    def test_undo_back_to_never_reviewed(self):
        app.mark_reviewed(self.con, NOW - 200)
        app.undo_review(self.con)
        self.assertEqual(app.review_at(self.con), 0)
        self.assertIsNone(app.get_meta(self.con, "review_prev"))

    def test_undo_to_earlier_review(self):
        app.mark_reviewed(self.con, NOW - 300)
        app.mark_reviewed(self.con, NOW - 100)
        app.undo_review(self.con)
        self.assertEqual(app.review_at(self.con), NOW - 300)


class Pages(unittest.TestCase):
    def setUp(self):
        app._local.h12 = False
        self.con = app.connect()
        with self.con:
            self.con.execute("DELETE FROM seen")
            self.con.execute("DELETE FROM meta WHERE k IN ('review_at','review_prev')")

    def add(self, kind, key, ex="x", n=1, ago=5):
        with self.con:
            self.con.execute("INSERT INTO seen(kind,key,observed,ip,session,ex,n) VALUES(?,?,?,?,?,?,?)",
                             (kind, key, time.time() - ago, "198.51.100.30", "s<1", ex, n))

    def test_log_data_is_escaped(self):
        self.add("cmd", "c", "<img src=x onerror=alert(1)>")
        self.add("pw", "<b>", "<script>1</script>")
        self.add("hassh", "<i>", "<u>x</u>")
        html = app.v_new({})
        for bad in ("<img src=x", "<script>1", "<u>x", "<b></td>", 's<1"'):
            self.assertNotIn(bad, html)
        self.assertNotRegex(html, r"\sstyle=")

    def test_hidden_rows_can_be_opened(self):
        for i in range(app.NEW_ROWS + 5):
            self.add("cmd", "k%d" % i)
        self.assertIn("Show all %d" % (app.NEW_ROWS + 5), app.v_new({}))
        html = app.v_new({"all": "1"})
        self.assertEqual(html.count("<td class='mono wrap'>"), app.NEW_ROWS + 5)
        self.assertNotIn("Show all", html)

    def test_button_counts_everything(self):
        self.add("cmd", "a")
        self.add("pw", "Aa")
        app.DEMO, demo = False, app.DEMO         # the static demo has no buttons
        try:
            self.assertIn("Mark all 2 reviewed", app.v_new({}))
        finally:
            app.DEMO = demo

    def test_empty(self):
        self.assertIn("Nothing new", app.v_new({}))

    def test_ioc_cell(self):
        self.assertNotIn("<details", app.ioc_cell(["a", "b"]))
        self.assertIn("Show 3 more", app.ioc_cell(list("abcde")))

    def test_bars_mark_only_today(self):
        html = app.bars([5, 6, 1], ["a", "b", "c"], partial_last=True)
        self.assertEqual(html.count(" partial"), 1)
        self.assertIn("c: 1 so far", html)
        self.assertNotIn("partial", app.bars([5, 6], ["a", "b"]))


class Score(unittest.TestCase):
    def test_parts_match_the_rules(self):
        parts = dict(app.score_parts(40, 3, 9, 7, 1, 0, 0, ["ftp", "redis"], took=True))
        self.assertEqual(parts, {"seen": 1, "took bait": 20, "login attempts": 2, "brute force": 2, "commands": 3, "files": 15,
                                 "decoy services": 6, "repeat visits": 2})
        score, _ = app.score_and_tags(40, 3, 9, 7, 1, 0, 0, ["ftp", "redis"], 0, ["ssh"], took=True)
        self.assertEqual(score, sum(parts.values()))

    def ip(self, score):
        return {"sessions": 1, "logins_ok": 0, "logins_fail": 1, "cmds": 0, "files": 0, "tcpip": 0, "exploits": 0, "canary_svcs": "", "tags": "", "score": score}

    def test_bar_when_it_adds_up(self):
        self.assertIn('class="sbar"', app.score_html(self.ip(3)))

    def test_says_so_when_it_does_not(self):
        html = app.score_html(self.ip(99))
        self.assertIn("Breakdown unavailable", html)
        self.assertNotIn("sbar", html)
