# SSHole (CVE-2026-123158) probes: SSH logins with a password of 257-1024 bytes.
import time, unittest
from unittest import mock

from tests import test_web
from tests.helpers import app

NOW = time.time()


def session(ip, sid, proto, password, kind="login_fail", user="root"):
    ts = NOW - 3600
    return [
        ("sshole|%s|connect" % sid, ts, ip, "cowrie", "connect", sid, proto, "2225"),
        ("sshole|%s|login" % sid, ts + 1, ip, "cowrie", kind, sid, user, password),
    ]


class Detection(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.con = app.connect()
        rows = []
        for ip, sid, proto, pw in (
            ("198.51.100.50", "sh256", "ssh", "A" * 256),
            ("198.51.100.51", "sh257", "ssh", "A" * 257),
            ("198.51.100.52", "sh1024", "ssh", "A" * 1024),
            ("198.51.100.53", "sh1025", "ssh", "A" * 1025),
            ("198.51.100.54", "shtel", "telnet", "A" * 300),
            ("198.51.100.55", "shutf", "ssh", "å" * 129),  # 129 characters, 258 bytes
            ("198.51.100.56", "shnone", "ssh", None),
        ):
            rows += session(ip, sid, proto, pw)
        app.store(cls.con, rows)

    def tags(self, ip):
        return (self.con.execute("SELECT tags FROM ips WHERE ip=?", (ip,)).fetchone()[0] or "").split(",")

    def test_length_limits(self):
        self.assertNotIn("sshole-probe", self.tags("198.51.100.50"))
        self.assertIn("sshole-probe", self.tags("198.51.100.51"))
        self.assertIn("sshole-probe", self.tags("198.51.100.52"))
        self.assertNotIn("sshole-probe", self.tags("198.51.100.53"))

    def test_telnet_is_not_a_probe(self):
        self.assertNotIn("sshole-probe", self.tags("198.51.100.54"))

    def test_counts_bytes_not_characters(self):
        self.assertIn("sshole-probe", self.tags("198.51.100.55"))

    def test_no_password(self):
        self.assertNotIn("sshole-probe", self.tags("198.51.100.56"))

    def test_score(self):
        score = lambda ip: self.con.execute("SELECT score FROM ips WHERE ip=?", (ip,)).fetchone()[0]
        self.assertEqual(score("198.51.100.51") - score("198.51.100.50"), 10)

    def test_python_and_sql_agree(self):
        for n, want in ((256, False), (257, True), (1024, True), (1025, False)):
            self.assertEqual(app.sshole_password("ssh", "A" * n), want)
        self.assertFalse(app.sshole_password("telnet", "A" * 300))
        self.assertFalse(app.sshole_password("ssh", None))

    def test_backfill_runs_once(self):
        ip = "198.51.100.51"
        with self.con:
            self.con.execute("UPDATE ips SET tags='' WHERE ip=?", (ip,))
            self.con.execute("DELETE FROM meta WHERE k='sshole_backfilled'")
        app.init_db()
        self.assertIn("sshole-probe", self.tags(ip))
        with self.con:
            self.con.execute("UPDATE ips SET tags='' WHERE ip=?", (ip,))
        app.init_db()
        self.assertEqual(self.tags(ip), [""])
        app.recompute_ip(self.con, ip)
        self.con.commit()

    def test_notify(self):
        with self.con:
            app.set_meta(self.con, "ntfy_last", NOW - 7200)
        with mock.patch.object(app, "NTFY_URL", "http://ntfy.invalid/x"), mock.patch.object(app, "ntfy_post") as post:
            app.notify(self.con)
        self.assertRegex(post.call_args[0][0], r"SSHole probes from \d+ IP\(s\)")
        with self.con:
            app.set_meta(self.con, "ntfy_last", NOW - 7200)
        with mock.patch.object(app, "NTFY_URL", "http://ntfy.invalid/x"), mock.patch.object(app, "ntfy_post") as post, \
                mock.patch.object(app, "settings", lambda con=None: {"notify": True, "notify_events": ["bait"]}):
            app.notify(self.con)
        self.assertFalse(any("SSHole" in str(c) for c in post.call_args_list))


class Page(unittest.TestCase):
    IP = "198.51.100.57"

    @classmethod
    def setUpClass(cls):
        cls.web = test_web.Web
        cls.web.setUpClass()
        con = app.connect()
        app.store(con, session(cls.IP, "shpage", "ssh", "<script>alert(1)</script>" + "A" * 300, user="alpine"))
        app.store(con, session("198.51.100.58", "shok", "ssh", "B" * 257, kind="login_ok"))

    @classmethod
    def tearDownClass(cls):
        cls.web.tearDownClass()

    def get(self, path):
        return self.web.req("GET", path, headers={"Cookie": self.web.cookie})

    def test_session_log(self):
        r, body = self.get("/ip/" + self.IP)
        self.assertEqual(r.status, 200)
        self.assertIn('class="pr">sshole<', body)
        self.assertIn("325 bytes, refused", body)
        self.assertIn("sshole-probe", body)
        self.assertNotIn("<script>alert(1)", body)
        self.assertIn("257 bytes, accepted", self.get("/ip/198.51.100.58")[1])

    def test_attacker_filter(self):
        r, body = self.get("/ips?tag=sshole-probe&days=all")
        self.assertEqual(r.status, 200)
        self.assertIn(self.IP, body)
        self.assertNotIn("198.51.100.50", body)


if __name__ == "__main__":
    unittest.main()
