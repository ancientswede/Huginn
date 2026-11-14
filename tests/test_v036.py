# 0.36 Fixes from the deep review (Codex, huginn-djupdyk-035): each test fails on 0.35.0 and passes now.
import hashlib, io, json, time, unittest, urllib.error, urllib.request
from unittest import mock

from tests.helpers import app
from tests.test_v033 import Fake

IP = "198.51.100.231"
NOW = time.time() - 60


def ev(name, ts, svc="http", body="GET / (200)", kind="canary", sid=None, ip=IP, src="canary"):
    return (name, ts, ip, src, kind, sid, svc, body)


class Base(unittest.TestCase):
    def setUp(self):
        self.con = app.connect()
        self.clean()

    def tearDown(self):
        self.clean()

    def clean(self):
        with self.con:
            for t in ("events", "sessions", "ips", "enrich", "capped", "capped_seen", "webhits", "mails", "files", "vt", "greynoise", "seen"):
                self.con.execute("DELETE FROM %s" % t)
            for k in ("health_limits", "health_alerted", "health_now", "last_success", "mb_wait_until", "mb_error", "gn_wait_until", "gn_error", "gn_day"):
                self.con.execute("DELETE FROM meta WHERE k=?", (k,))
        app._eng_cache.clear()


class Regex(unittest.TestCase):
    def test_chmod_near_miss_is_fast(self):
        cmd = "chmod " + "1" * 3980 + "Z"
        t = time.perf_counter()
        app.attack_ids([cmd])
        self.assertLess(time.perf_counter() - t, 0.02)
        self.assertEqual(app.attack_ids(["chmod 0755 x"]), ["T1222.002"])
        self.assertEqual(app.attack_ids(["chmod 644 x"]), [])

    def test_total_budget(self):
        t = time.perf_counter()
        app.attack_ids(["chmod " + "1" * 3980 + "Z"] * 2000)
        self.assertLess(time.perf_counter() - t, 0.5)


class DecoyCap(Base):
    def test_attacks_and_bait_kept_over_cap(self):
        rows = [ev("plain", NOW - 3), ev("exploit", NOW - 2, body="GET /vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php (404)"),
                ev("bait", NOW - 1, body="GET /x (404)  [reply env]"), ev("flood", NOW, body="GET /?a=1 (200)")]
        with mock.patch.object(app, "DECOY_CAP", 1):
            app.store(self.con, rows)
        kept = {r[0] for r in self.con.execute("SELECT h FROM events")}
        self.assertEqual(kept, {"plain", "exploit", "bait"})
        self.assertEqual(self.con.execute("SELECT dropped FROM capped").fetchone()[0], 1)

    def test_equal_and_out_of_order_times(self):
        rows = [ev("b", NOW), ev("a", NOW), ev("c", NOW - 10)]
        with mock.patch.object(app, "DECOY_CAP", 2000):
            app.store(self.con, rows)
            app.store(self.con, rows)                     # sent again by the next export: nothing counted twice
        self.assertEqual(self.con.execute("SELECT COUNT(*) FROM events").fetchone()[0], 3)
        self.assertEqual(tuple(self.con.execute("SELECT kept, dropped FROM capped").fetchone()), (3, 0))

    def test_dropped_rows_not_counted_twice(self):
        rows = [ev("r%d" % i, NOW - 10 + i, body="GET /?%d (200)" % i) for i in range(5)]
        with mock.patch.object(app, "DECOY_CAP", 2):
            app.store(self.con, rows)
            app.store(self.con, rows)
        self.assertEqual(tuple(self.con.execute("SELECT kept, dropped FROM capped").fetchone()), (2, 3))

    def test_trim_keeps_classified_attacks(self):
        with mock.patch.object(app, "DECOY_CAP", 0):
            app.store(self.con, [ev("first", NOW - 1), ev("bad", NOW, body="GET /x (404)")])
        with self.con:
            self.con.execute("INSERT INTO webhits VALUES('bad',?,?,'exploit','test','CVE-2021-41773',9,'x',0,'')", (IP, NOW))
        with mock.patch.object(app, "DECOY_CAP", 1):
            app.trim_decoys(self.con)
        self.assertIsNotNone(self.con.execute("SELECT 1 FROM events WHERE h='bad'").fetchone())
        self.assertEqual(self.con.execute("SELECT COUNT(*) FROM webhits").fetchone()[0], 1)

    def test_retention_covers_counters(self):
        old = NOW - 40 * 86400
        with mock.patch.object(app, "DECOY_CAP", 1):
            app.store(self.con, [ev("o1", old), ev("o2", old + 1, body="GET /?2 (200)"), ev("n1", NOW)])
        with mock.patch.object(app, "RETENTION_DAYS", 30):
            app.retention(self.con)
        self.assertEqual(self.con.execute("SELECT canary FROM ips WHERE ip=?", (IP,)).fetchone()[0], 1)


class Health(Base):
    def test_dead_source_keeps_alerting(self):
        now = time.time()
        app.set_meta(self.con, "last_success", now)
        app.set_meta(self.con, "health_limits", json.dumps({"day": time.strftime("%Y-%m-%d", time.gmtime()), "lim": {"traps": 7200}}))
        with self.con:
            self.con.execute("INSERT INTO events VALUES('t1',?,?,'traps','canary',NULL,'smtp','x')", (now - 49 * 3600, IP))
        self.assertIn("traps", app.health_check(self.con, now))

    def test_hits_over_cap_are_activity(self):
        now = time.time()
        with self.con:
            self.con.execute("INSERT INTO events VALUES('c1',?,?,'canary','canary',NULL,'vnc','x')", (now - 5 * 3600, IP))
            self.con.execute("INSERT INTO capped(ip, svc, day, kept, dropped, upto, src) VALUES(?,?,?,?,?,?,?)",
                             (IP, "vnc", app.utc_day(now), 2000, 50, now - 60, "canary"))
        self.assertGreater(app.health_sources(self.con, now)["canary"], now - 120)

    def test_limits_survive_a_short_week(self):
        app.set_meta(self.con, "health_limits", json.dumps({"day": "2000-01-01", "lim": {"cowrie:2225": 9000}}))
        self.assertEqual(app.health_limits(self.con).get("cowrie:2225"), 9000)


class Research(Base):
    def gn(self, answer):
        with mock.patch.object(app, "sendable_ip", lambda ip: True), mock.patch.object(app, "GN_DAILY", 100), \
                mock.patch.object(app.time, "sleep", lambda s: None), mock.patch.object(app, "api_urlopen", Fake({IP: answer})):
            return app.gn_lookup(self.con, limit=1)

    def setUp(self):
        super().setUp()
        with self.con:
            self.con.execute("INSERT INTO ips(ip, first, last, score, sessions, logins_ok, logins_fail, cmds, files, tcpip, exploits, tags) "
                             "VALUES(?,?,?,?,0,0,0,0,0,0,0,'')", (IP, NOW, NOW, 10))
            self.con.execute("INSERT INTO enrich(ip, fetched, ok, research) VALUES(?,?,1,0)", (IP, NOW))

    def research(self):
        return self.con.execute("SELECT research FROM enrich WHERE ip=?", (IP,)).fetchone()[0]

    def test_changed_answer_clears_flag(self):
        self.gn({"ip": IP, "noise": True, "classification": "benign"})
        self.assertEqual(self.research(), 1)
        with self.con:
            self.con.execute("UPDATE greynoise SET checked=0")
        self.gn({"ip": IP, "noise": True, "classification": "malicious"})
        self.assertEqual(self.research(), 0)

    def test_enrich_keeps_benign_answer(self):
        self.gn({"ip": IP, "noise": True, "classification": "benign"})
        self.assertEqual(app.research_now(self.con, IP, 0), 1)

    def test_strict_answers(self):
        self.assertFalse(app.gn_parse({"noise": "false", "riot": "false", "classification": "benign"}, IP)["seen"])
        self.assertFalse(app.gn_parse({"ip": "203.0.113.9", "noise": True, "classification": "benign"}, IP)["seen"])
        self.assertTrue(app.gn_parse({"ip": IP, "noise": True, "classification": "benign"}, IP)["seen"])

    def test_web_exploit_overrides_research(self):
        with self.con:
            self.con.execute("UPDATE enrich SET research=1")
            self.con.execute("UPDATE ips SET tags='web-exploit'")
        self.assertIn(IP, app.blocklist_ips(self.con, 0, 30, False, True))
        with self.con:
            self.con.execute("UPDATE ips SET tags=''")
        self.assertNotIn(IP, app.blocklist_ips(self.con, 0, 30, False, True))


class Outbound(Base):
    def test_no_redirects_and_https_only(self):
        req = urllib.request.Request("https://service.invalid/api", headers={"x-apikey": "marker"})
        self.assertIsNone(app._NoRedirect().redirect_request(req, None, 302, "x", {}, "http://other.invalid/"))
        with self.assertRaises(ValueError):
            app.api_urlopen(urllib.request.Request("http://example.invalid/"))

    def test_mb_odd_answer_marks_one_file(self):
        shas = ["d" * 64, "e" * 64]
        with self.con:
            for i, sha in enumerate(shas):
                self.con.execute("INSERT INTO files(sha, mtime) VALUES(?,?)", (sha, NOW + i))
        with mock.patch.object(app, "MB_KEY", "k" * 32), mock.patch.object(app, "api_urlopen", Fake({"mb-api": {"query_status": "ok", "data": [None]}})):
            n = app.mb_lookup(self.con)
        self.assertEqual(n, 2, "one odd answer does not stop the rest")
        self.assertIn("unexpected", app.get_meta(self.con, "mb_error"))
        self.assertEqual(self.con.execute("SELECT COUNT(*) FROM files WHERE mb_checked IS NOT NULL").fetchone()[0], 2)

    def test_mb_refused_key_pauses(self):
        with self.con:
            self.con.execute("INSERT INTO files(sha, mtime) VALUES(?,?)", ("f" * 64, NOW))
        with mock.patch.object(app, "MB_KEY", "k" * 32), mock.patch.object(app, "api_urlopen", Fake({"mb-api": 401})):
            app.mb_lookup(self.con)
        self.assertGreater(float(app.get_meta(self.con, "mb_wait_until")), time.time() + 3600)


class Pages(Base):
    def test_files_uses_loaded_vt_answers(self):
        with self.con:
            for i in range(20):
                sha = hashlib.sha256(str(i).encode()).hexdigest()
                self.con.execute("INSERT INTO files(sha, mtime, size, type, arch, packed, src) VALUES(?,?,1024,'ELF','arm',0,'dl')", (sha, NOW))
                self.con.execute("INSERT INTO vt VALUES(?,?,?)", (sha, NOW, json.dumps({"found": True, "mal": 3, "total": 60, "label": "trojan.mirai/x"})))
        with mock.patch.object(app, "vt_get", side_effect=AssertionError("no query per file")):
            html = app.v_files({})
        self.assertIn("Mirai", html)

    def test_timeline_keeps_latest(self):
        start = NOW - 20 * 86400
        with self.con:
            self.con.executemany("INSERT INTO sessions(session, ip, start, end, proto, duration, logins_ok, logins_fail, cmds, files, tcpip) "
                                 "VALUES(?,?,?,?,'ssh',1,0,1,0,0,0)", [("old%d" % i, IP, start + i, start + i + 1) for i in range(5001)])
            self.con.execute("INSERT INTO sessions(session, ip, start, end, proto, duration, logins_ok, logins_fail, cmds, files, tcpip) "
                             "VALUES('new',?,?,?,'ssh',5,1,0,1,0,0)", (IP, NOW, NOW + 5))
            self.con.execute("INSERT INTO events VALUES('cmdnew',?,?,'cowrie','cmd','new','id',NULL)", (NOW + 1, IP))
        html = app.ip_timeline(self.con, IP)
        self.assertIn("Commands", html, "the newest session, the only one with commands, is on the timeline")

    def test_engagement_late_commands_and_median(self):
        start = NOW - 5 * 86400
        with self.con:
            self.con.execute("INSERT INTO ips(ip, first, last) VALUES(?,?,?)", (IP, start, NOW))
            self.con.execute("INSERT INTO sessions(session, ip, start, end, proto, duration, logins_ok, cmds) VALUES('long',?,?,?,'ssh',?,1,1)",
                             (IP, start, start + 4 * 86400, 4 * 86400.0))
            self.con.execute("INSERT INTO events VALUES('late',?,?,'cowrie','cmd','long','id',NULL)", (start + 4 * 86400 - 10, IP))
        rows = app.eng_sessions(self.con, start - 1, start + 1)
        self.assertEqual(rows[0]["kind"], "cmds")
        self.assertEqual(app.eng_summary([{"ip": "a", "new": False, "human": False, "kind": "left", "dur": 10.0, "cmds": 0},
                                          {"ip": "b", "new": False, "human": False, "kind": "left", "dur": 100.0, "cmds": 0}])["median"], 55.0)


if __name__ == "__main__":
    unittest.main()
