# From parsed rows to scores, tags, bait detection, blocklists and exports.
import ipaddress, json, time, unittest

from tests.helpers import app, BAIT

NOW = time.time()


def row(ip, src, kind, session=None, a=None, b=None, dt=0.0):
    ts = NOW - 3600 + dt
    h = "%s|%s|%s|%s|%s|%s" % (ts, ip, kind, session, a, b)
    return (h, ts, ip, src, kind, session, a, b)


class Pipeline(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.con = app.connect()
        rows = [
            # A shell attacker who read and then used the bait.
            row("198.51.100.10", "cowrie", "connect", "s1", "ssh", "2225"),
            row("198.51.100.10", "cowrie", "login_ok", "s1", "root", "123456", 1),
            row("198.51.100.10", "cowrie", "cmd", "s1", "cat ~/.my.cnf", None, 2),
            row("198.51.100.10", "cowrie", "cmd", "s1", "mysql -u backup -p'%s'" % BAIT["mysql_backup"], None, 3),
            row("198.51.100.10", "cowrie", "closed", "s1", "4.0", None, 4),
            # Someone who only knocked once on a decoy service.
            row("192.0.2.20", "canary", "canary", None, "redis", "{}"),
            # A dropper.
            row("203.0.113.30", "cowrie", "connect", "s3", "telnet", "2323"),
            row("203.0.113.30", "cowrie", "login_ok", "s3", "admin", "admin", 1),
            row("203.0.113.30", "cowrie", "file", "s3", "http://192.0.2.99/bins/x86", "ef" * 32, 2),
            row("203.0.113.30", "cowrie", "closed", "s3", "3.0", None, 3),
            # An IPv6 brute forcer.
            row("2001:db8::7", "cowrie", "login_fail", "s4", "root", "x"),
        ]
        cls.inserted = app.store(cls.con, rows)
        cls.again = app.store(cls.con, rows)

    def ip(self, a):
        return self.con.execute("SELECT * FROM ips WHERE ip=?", (a,)).fetchone()

    def test_dedupe(self):
        self.assertEqual(self.inserted, 11)
        self.assertEqual(self.again, 0)

    def test_bait_tags(self):
        tags = self.ip("198.51.100.10")["tags"].split(",")
        self.assertIn("took-bait", tags)
        self.assertIn("read-bait", tags)
        self.assertNotIn("took-bait", (self.ip("192.0.2.20")["tags"] or "").split(","))

    def test_scores_order(self):
        self.assertGreater(self.ip("198.51.100.10")["score"], self.ip("192.0.2.20")["score"])
        self.assertGreater(self.ip("203.0.113.30")["score"], self.ip("192.0.2.20")["score"])
        self.assertIn("dropper", self.ip("203.0.113.30")["tags"])

    def test_blocklist(self):
        ips = app.blocklist_ips(self.con, 3, 30, False, True)
        self.assertIn("198.51.100.10", ips)
        self.assertIn("203.0.113.30", ips)
        self.assertEqual(self.ip("192.0.2.20")["score"], 4)   # 1 for showing up + 3 per decoy service
        self.assertNotIn("192.0.2.20", app.blocklist_ips(self.con, 5, 30, False, True))
        self.assertNotIn("2001:db8::7", app.blocklist_ips(self.con, 1, 30, False, False))
        self.assertEqual(ips, sorted(ips, key=lambda a: (ipaddress.ip_address(a).version, int(ipaddress.ip_address(a)))))

    def test_manual_flags(self):
        with self.con:
            self.con.execute("INSERT OR REPLACE INTO flags(ip, flag, note) VALUES('192.0.2.20','block','')")
            self.con.execute("INSERT OR REPLACE INTO flags(ip, flag, note) VALUES('203.0.113.30','allow','')")
        try:
            ips = app.blocklist_ips(self.con, 3, 30, False, True)
            self.assertIn("192.0.2.20", ips)
            self.assertNotIn("203.0.113.30", ips)
        finally:
            with self.con:
                self.con.execute("DELETE FROM flags")

    def test_feeds(self):
        ips = ["192.0.2.1", "2001:db8::1"]
        txt, ctype = app.render_feed("txt", ips)
        self.assertEqual(ctype, "text/plain")
        self.assertEqual([l for l in txt.splitlines() if not l.startswith("#")], ips)
        nft, _ = app.render_feed("nft", ips)
        self.assertIn("elements = { 192.0.2.1 }", nft)
        self.assertIn("elements = { 2001:db8::1 }", nft)
        ipset, _ = app.render_feed("ipset", ips)
        self.assertIn("add huginn4 192.0.2.1 -exist", ipset)
        mk, _ = app.render_feed("mikrotik", ips)
        self.assertIn("/ipv6 firewall address-list add list=huginn address=2001:db8::1", mk)
        self.assertEqual(app.render_feed("nope", ips), (None, None))

    def test_c2_list(self):
        self.assertNotIn("192.0.2.99", app.c2_list(self.con))              # one attacker is not enough
        app.store(self.con, [row("203.0.113.31", "cowrie", "file", "s6", "http://192.0.2.99/bins/x86", "ef" * 32, 2)])
        self.assertIn("192.0.2.99", app.c2_list(self.con))

    def test_export_and_csv_injection(self):
        data = app.export_ip("198.51.100.10")
        self.assertEqual(data["ip"], "198.51.100.10")
        self.assertEqual(data["sessions"][0]["persona"], "server")
        data["events"].append({"time": "x", "source": "cowrie", "kind": "cmd", "session": "s1", "a": "=HYPERLINK(\"http://x\")", "b": "+1"})
        csv = app.export_csv(data)
        self.assertIn("'=HYPERLINK", csv)
        self.assertIn(",'+1", csv)
        json.dumps(data)


class Helpers(unittest.TestCase):
    def test_esc(self):
        self.assertEqual(app.esc("<script>\"'&"), "&lt;script&gt;&quot;&#x27;&amp;")

    def test_trunc(self):
        self.assertEqual(app.trunc("a" * 10, 5), "aaaaa…")
        self.assertIsNone(app.trunc(None))

    def test_vtuple(self):
        self.assertGreater(app.vtuple("0.10.0"), app.vtuple("0.9.1"))
        self.assertEqual(app.vtuple("v1.2.3"), app.vtuple("1.2.3"))

    def test_password_hash(self):
        h = app.hash_pw("correct horse battery")
        self.assertTrue(app.check_pw("correct horse battery", h))
        self.assertFalse(app.check_pw("wrong", h))
        self.assertNotEqual(h, app.hash_pw("correct horse battery"))   # salted

    def test_tty_frames_tolerate_garbage(self):
        app.tty_frames(b"\x00\x01garbage")


if __name__ == "__main__":
    unittest.main()
