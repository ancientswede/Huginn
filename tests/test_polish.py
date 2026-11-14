# 0.28 Polish and growth: web exploit alerts, scoring text, empty states, sort arrow, chart labels, Files/Campaigns filters,
# the decoy cap (repeated tries counted, not stored) and the disk growth forecast.
import hashlib, json, time, unittest
from unittest import mock

from tests.helpers import app

NOW = time.time()
A, B = "198.51.100.161", "198.51.100.162"


def row(ip, ts, svc="vnc", b=" / password", kind="canary"):
    r = (ts, ip, "canary", kind, None, svc, b)
    return (hashlib.sha1(repr(r).encode()).hexdigest(),) + r


class Base(unittest.TestCase):
    def setUp(self):
        self.con = app.connect()
        self.clean()

    def tearDown(self):
        self.clean()

    def clean(self):
        with self.con:
            for t in ("events", "sessions", "ips", "seen", "webhits", "capped", "files"):
                self.con.execute("DELETE FROM %s" % t)
            self.con.execute("DELETE FROM meta WHERE k IN ('settings','data_sizes')")
        app._board_cache.clear()


class Scoring(Base):
    def test_help_names_every_part(self):
        parts = app.score_parts(100, 5, 20, 40, 1, 1, 1, ["vnc", "http"], True, True, True, "exploit robots")
        words = {"seen": "seen", "SSHole probe": "SSHole", "took bait": "took bait", "read bait": "read bait", "web exploit": "web exploit",
                 "robots.txt trap": "robots", "login attempts": "login attempts", "brute force": "brute force", "commands": "per command",
                 "files": "files", "proxy": "proxy", "exploit": "exploit", "decoy services": "decoy service", "repeat visits": "repeat visits"}
        for label, _v in parts:
            self.assertIn(words[label], app.SCORE_HELP, label)
        self.assertIn("web probe", app.SCORE_HELP)
        page = app.v_blocklist(type("H", (), {"headers": {"Host": "huginn.test"}, "client_address": ("127.0.0.1", 1)})(), {})
        self.assertIn(app.SCORE_HELP.replace("½", "½")[:40], page)


class Alerts(Base):
    def test_web_exploit_alert_with_cve(self):
        with self.con:
            self.con.execute("INSERT INTO webhits VALUES('x1',?,?,'exploit','cve_2021_36260','CVE-2021-36260',9,'r',0,'')", (A, NOW - 60))
            self.con.execute("INSERT INTO webhits VALUES('x2',?,?,'exploit','x','<b>not a cve</b>',9,'r',0,'')", (B, NOW - 60))
            app.set_meta(self.con, "ntfy_last", NOW - 7200)
        with mock.patch.object(app, "NTFY_URL", "http://ntfy.invalid/x"), mock.patch.object(app, "ntfy_post") as post:
            app.notify(self.con)
        self.assertIn("Web exploits from 2 IP(s): CVE-2021-36260", post.call_args[0][0])
        self.assertNotIn("<b>", post.call_args[0][0])


class Pages(Base):
    def test_overview_empty_and_labels(self):
        page = app.v_overview({})
        for t in ("No attackers in the last 7 days", "No shell sessions yet", "No SSH/Telnet logins in the last 7 days", "Top credentials, SSH/Telnet"):
            self.assertIn(t, page)
        self.assertIn('class="grid ov"', page)

    def test_sort_arrow_and_chart_label(self):
        page = app.v_ips({"sort": "score"})
        self.assertIn('aria-sort="descending"', page)
        self.assertEqual(page.count('aria-sort="descending"'), 1)
        self.assertIn("Score ↓", page)
        html = app.bars([1, 5, 2], ["2026-11-01", "2026-11-02", "2026-11-03"])
        self.assertIn('aria-label="Bar chart, 2026-11-01 to 2026-11-03, highest 5 on 2026-11-02"', html)

    def test_files_family_chips(self):
        with self.con:
            for sha, fam in (("a" * 64, "Mirai"), ("b" * 64, "Mirai"), ("c" * 64, "")):
                self.con.execute("INSERT INTO files(sha, size, type, arch, packed, src, mtime, iocs, family) VALUES(?,?,?,?,?,?,?,?,?)",
                                 (sha, 100, "ELF", "arm", 0, "dl", NOW, "[]", fam))
        with mock.patch.object(app, "file_family", lambda f, names, sha=None: ((f["family"] or "") if f else "", "rule")):
            all_ = app.v_files({})
            self.assertIn("Mirai <span class=muted>2</span>", all_)
            self.assertIn("Unknown <span class=muted>1</span>", all_)
            only = app.v_files({"fam": "Mirai"})
            self.assertIn("a" * 16, only)
            self.assertNotIn("c" * 16, only)
            unk = app.v_files({"fam": "unknown"})
            self.assertIn("c" * 16, unk)
            self.assertNotIn("a" * 16, unk)
            self.assertIn("a" * 16, app.v_files({"fam": "<script>"}))          # an unknown family shows everything

    def test_campaigns_active_filter(self):
        with self.con:
            for sid, ip, start in (("s-old", A, NOW - 40 * 86400), ("s-new", B, NOW - 3600)):
                self.con.execute("INSERT INTO sessions(session, ip, start, end, proto, cmds, cmdhash) VALUES(?,?,?,?,?,?,?)",
                                 (sid, ip, start, start + 5, "ssh", 2, "f" * 16 if sid == "s-old" else "e" * 16))
        all_ = app.v_campaigns({})
        self.assertIn("IPs 7d", all_)
        self.assertIn("ffffffffffffffff", all_)
        active = app.v_campaigns({"active": "1"})
        self.assertIn("eeeeeeeeeeeeeeee", active)
        self.assertNotIn("ffffffffffffffff", active)


class DecoyCap(Base):
    def test_cap_resend_and_counts(self):
        with mock.patch.object(app, "DECOY_CAP", 5):
            day = (int(NOW // 86400) - 1) * 86400 + 3600
            first = [row(A, day + i) for i in range(8)]
            app.store(self.con, first)
            n = lambda: self.con.execute("SELECT COUNT(*) FROM events WHERE ip=?", (A,)).fetchone()[0]
            cap = lambda: tuple(self.con.execute("SELECT kept, dropped FROM capped WHERE ip=?", (A,)).fetchone())
            self.assertEqual((n(), cap()), (5, (5, 3)))
            app.store(self.con, first)                                   # the export sends the same lines again
            self.assertEqual((n(), cap()), (5, (5, 3)))
            app.store(self.con, first + [row(A, day + 100), row(A, day + 101)])
            self.assertEqual((n(), cap()), (5, (5, 5)))
            ip = self.con.execute("SELECT canary, last FROM ips WHERE ip=?", (A,)).fetchone()
            self.assertEqual(ip[0], 10)                                     # all tries count
            self.assertEqual(ip[1], day + 101)                              # last seen includes the dropped ones
            self.assertIn("+5 repeated tries counted, not stored", app.v_ip(A))
            self.assertIn("5 counted but not stored, from 1 IPs", app.capped_note(self.con))
            app.store(self.con, [row(A, day + 200, svc="http", b="GET /x")])  # another service has its own budget
            self.assertEqual(n(), 6)

    def test_trim_existing_history(self):
        with mock.patch.object(app, "DECOY_CAP", 0):
            day = (int(NOW // 86400) - 2) * 86400
            rows = [row(B, day + i, svc="http", b="GET /%d" % i) for i in range(8)]
            app.store(self.con, rows)
        with self.con:
            self.con.execute("INSERT INTO webhits VALUES(?,?,?,'probe','x','',1,'r',0,'')", (rows[7][0], B, day + 7))
            self.con.execute("INSERT INTO webhits VALUES(?,?,?,'probe','x','',1,'r',0,'')", (rows[0][0], B, day))
        with mock.patch.object(app, "DECOY_CAP", 5):
            self.assertEqual(app.trim_decoys(self.con), 1)
            kept = [r[0] for r in self.con.execute("SELECT ts FROM events WHERE ip=? ORDER BY ts", (B,))]
            self.assertEqual(kept, [day + i for i in range(5)])            # the first ones of the day stay
            self.assertEqual([r[0] for r in self.con.execute("SELECT h FROM webhits")], [rows[0][0]])
            self.assertEqual(self.con.execute("SELECT canary FROM ips WHERE ip=?", (B,)).fetchone()[0], 8)
            app.store(self.con, rows)                                       # resent after the trim: nothing comes back
            self.assertEqual(self.con.execute("SELECT COUNT(*) FROM events WHERE ip=?", (B,)).fetchone()[0], 5)


class Growth(Base):
    def test_forecast(self):
        self.assertIn("a forecast after three days", app.growth_note(self.con))
        with self.con:
            app.set_meta(self.con, "data_sizes", json.dumps([["2026-11-01", 100 << 20], ["2026-11-05", 140 << 20], ["2026-11-11", 200 << 20]]))
        note = app.growth_note(self.con)
        self.assertIn("grows about 10.0 MB a day", note)
        self.assertIn("full in about", note)
        with self.con:
            app.set_meta(self.con, "data_sizes", "not json")
        app.note_size(self.con)
        hist = json.loads(app.get_meta(self.con, "data_sizes"))
        self.assertEqual(len(hist), 1)
        app.note_size(self.con)                                             # once a day
        self.assertEqual(len(json.loads(app.get_meta(self.con, "data_sizes"))), 1)


if __name__ == "__main__":
    unittest.main()
