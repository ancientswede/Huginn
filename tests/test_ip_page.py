# Script campaigns by shape, the attacker page summary and related list, and sync gaps.
import time, unittest
from datetime import datetime

from tests.helpers import app

NOW = time.time()
IP = "198.51.100.40"


def row(ip, kind, session, a=None, b=None, ago=5):
    ts = NOW - ago
    return ("ip|%s|%s|%s|%s|%s" % (ip, kind, session, a, b), ts, ip, "cowrie", kind, session, a, b)


def clear(con):
    with con:
        for t in ("events", "sessions", "ips", "seen", "gaps"):
            con.execute("DELETE FROM %s" % t)
        con.execute("DELETE FROM meta WHERE k IN ('seen_done','last_success','cmdhash_shapes')")


class Campaigns(unittest.TestCase):
    def setUp(self):
        self.con = app.connect()
        clear(self.con)

    def run_script(self, ip, sid, mark):
        app.store(self.con, [row(ip, "connect", sid, "ssh", "2225", ago=10), row(ip, "cmd", sid, "echo check_" + mark, ago=9), row(ip, "closed", sid, "4.0", ago=5)])

    def hashes(self):
        return {r[0] for r in self.con.execute("SELECT cmdhash FROM sessions WHERE cmdhash IS NOT NULL")}

    def test_random_markers_make_one_campaign(self):
        self.run_script("198.51.100.41", "a1", "1f3a5b7c9d")
        self.run_script("198.51.100.42", "a2", "aa11bb22cc")
        self.assertEqual(len(self.hashes()), 1)

    def test_seen_key_is_the_campaign(self):
        self.run_script("198.51.100.41", "a1", "1f3a5b7c9d")
        self.assertEqual({r[0] for r in self.con.execute("SELECT key FROM seen WHERE kind='script'")}, self.hashes())

    def test_no_commands_no_campaign(self):
        self.assertIsNone(app.script_hash([]))
        self.assertIsNone(app.script_hash(["", ""]))

    def test_migration_rewrites_old_hashes_and_nothing_else(self):
        self.run_script("198.51.100.41", "a1", "1f3a5b7c9d")
        want = self.con.execute("SELECT cmdhash, duration, cmds FROM sessions WHERE session='a1'").fetchone()[:]
        with self.con:
            self.con.execute("UPDATE sessions SET cmdhash='0123456789abcdef'")
            self.con.execute("DELETE FROM meta WHERE k='cmdhash_shapes'")
        app.init_db()
        self.assertEqual(self.con.execute("SELECT cmdhash, duration, cmds FROM sessions WHERE session='a1'").fetchone()[:], want)
        self.assertEqual(app.get_meta(self.con, "cmdhash_shapes"), "1")

    def test_migration_runs_once(self):
        self.run_script("198.51.100.41", "a1", "1f3a5b7c9d")
        app.init_db()
        with self.con:
            self.con.execute("UPDATE sessions SET cmdhash='0123456789abcdef'")
        app.init_db()
        self.assertEqual(self.hashes(), {"0123456789abcdef"})


class NewLinks(unittest.TestCase):
    def test_no_link_to_a_campaign_that_is_gone(self):
        con = app.connect()
        clear(con)
        with con:
            con.execute("INSERT INTO seen(kind,key,observed,ip,session,ex,n) VALUES('script','abcdef0123456789',?,?,'s','id',1)", (time.time(), IP))
        app._local.h12 = False
        self.assertNotIn("/campaign/script/abcdef0123456789", app.v_new({}))


class Story(unittest.TestCase):
    def setUp(self):
        self.con = app.connect()
        clear(self.con)

    def ip(self):
        return self.con.execute("SELECT * FROM ips WHERE ip=?", (IP,)).fetchone()

    def test_full(self):
        app.store(self.con, [row(IP, "connect", "s", "ssh", "2225", ago=9), row(IP, "login_fail", "s", "root", "a", ago=8), row(IP, "login_ok", "s", "root", "b", ago=7),
                             row(IP, "cmd", "s", "id", ago=6), row(IP, "file", "s", "/tmp/x", "ab" * 32, ago=5), row(IP, "closed", "s", "4.0", ago=4)])
        self.assertEqual(app.ip_story(self.con, self.ip()), "Tried 2 logins, 1 accepted, ran 1 command, left 1 file.")

    def test_blocked_download_is_not_a_file_left(self):
        app.store(self.con, [row(IP, "connect", "s", "ssh", "2225", ago=9), row(IP, "file_fail", "s", "http://203.0.113.9/x", ago=5)])
        story = app.ip_story(self.con, self.ip())
        self.assertIn("failed to fetch 1 file", story.lower())
        self.assertNotIn("left", story)

    def test_connect_only(self):
        app.store(self.con, [row(IP, "connect", "s", "ssh", "2225", ago=9)])
        self.assertEqual(app.ip_story(self.con, self.ip()), "Connected, nothing more.")


class Related(unittest.TestCase):
    def test_count_is_real_and_latest_come_first(self):
        con = app.connect()
        clear(con)
        rows = []
        for i in range(1, 60):
            rows += [row("198.51.100.%d" % i, "connect", "r%d" % i, "ssh", "2225", ago=1000 - i), row("198.51.100.%d" % i, "hassh", "r%d" % i, "ab" * 16, ago=1000 - i)]
        app.store(con, rows)
        app._local.h12 = False
        html = app.v_ip("198.51.100.1")
        self.assertIn('Same SSH client (HASSH) <span class=muted>58</span>', html)
        self.assertIn("Show 53 more", html)
        self.assertLess(html.index('/ip/198.51.100.59"'), html.index('/ip/198.51.100.54"'))
        self.assertNotRegex(html, r"\sstyle=")


class Gaps(unittest.TestCase):
    def setUp(self):
        self.con = app.connect()
        clear(self.con)

    def gaps(self):
        return self.con.execute("SELECT COUNT(*) FROM gaps").fetchone()[0]

    def test_first_sync_is_no_gap(self):
        app.note_sync(self.con, time.time())
        self.assertEqual(self.gaps(), 0)

    def test_short_pause_is_no_gap(self):
        app.set_meta(self.con, "last_success", time.time() - 300)
        app.note_sync(self.con, time.time())
        self.assertEqual(self.gaps(), 0)

    def test_long_pause_is_one_gap(self):
        t = time.time()
        app.set_meta(self.con, "last_success", t - 7200)
        app.note_sync(self.con, t)
        self.assertEqual(self.con.execute("SELECT end-start FROM gaps").fetchone()[0], 7200)

    def test_ongoing_gap_is_counted_once(self):
        app.set_meta(self.con, "last_success", time.time() - 7200)
        self.assertEqual(len(app.gap_spans(self.con, 0)), 1)
        app.note_sync(self.con, time.time())
        self.assertEqual(len(app.gap_spans(self.con, 0)), 1)

    def test_split_at_local_midnight(self):
        day1, day2 = "2026-10-30", "2026-10-31"
        mid = datetime.strptime(day2, "%Y-%m-%d").replace(tzinfo=app.TZ).timestamp()
        with self.con:
            self.con.execute("INSERT INTO gaps VALUES(?,?)", (mid - 600, mid + 1200))
        got = app.gap_days(self.con, [day1, day2])
        self.assertEqual((got[day1], got[day2]), (600, 1200))

    def test_days_outside_are_left_alone(self):
        with self.con:
            self.con.execute("INSERT INTO gaps VALUES(?,?)", (1000, 2000))
        self.assertEqual(app.gap_days(self.con, ["2026-10-30"]), {})

    def test_summary(self):
        self.assertEqual(app.gap_summary(self.con), "none in 30 days")
        t = time.time()
        with self.con:
            self.con.execute("INSERT INTO gaps VALUES(?,?)", (t - 7800, t - 600))
        self.assertIn("1 in 30 days", app.gap_summary(self.con))

    def test_stored_gap_and_recent_success(self):
        t = time.time()
        with self.con:
            self.con.execute("INSERT INTO gaps VALUES(?,?)", (t - 9000, t - 3000))
        app.set_meta(self.con, "last_success", t - 30)
        self.assertEqual(app.gap_spans(self.con, 0), [(t - 9000, t - 3000)])

    def test_marked_on_the_bar_with_words(self):
        html = app.bars([3, 4], ["a", "b"], gaps={"b": 7200})
        self.assertEqual(html.count("gapd"), 1)
        self.assertIn("no sync for 2h 0m", html)
        self.assertIn("No sync", app.gap_note({"b": 7200}))
        self.assertEqual(app.gap_note({}), "")
