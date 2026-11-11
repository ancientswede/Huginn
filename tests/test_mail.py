# 0.24.1 Relay trap: recipients, HELO name, size and the start of the message are kept; HELO names group on Campaigns.
import json, time, unittest

from tests.helpers import app

IP = "198.51.100.91"
IP2 = "198.51.100.92"


def ts(off=0):
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(time.time() - 600 + off)) + ".000000Z"


def trap(ip=IP, off=0, **kw):
    ev = {"ts": ts(off), "src_ip": ip, "src_port": 40000, "service": "smtp"}
    ev.update(kw)
    return json.dumps(ev)


MAIL = dict(event="mail", mail_from="bot@example.net", rcpts=["check@example.org", "<img src=x onerror=alert(1)>@x"],
            rcpt_count=2, subject="Relay test <b>", size=2048, helo="WIN-ABC", sample="Subject: Relay test\r\n\r\n<script>alert(1)</script> body")


class Mail(unittest.TestCase):
    def setUp(self):
        self.con = app.connect()
        self.clean()

    def tearDown(self):
        self.clean()

    def clean(self):
        with self.con:
            for t in ("events", "sessions", "ips", "seen", "mails"):
                self.con.execute("DELETE FROM %s" % t)

    def ingest(self, lines):
        rows, _ = app.parse_export("##TRAPS\n" + "\n".join(lines), set())
        app.store(self.con, rows)
        app.store_mails(self.con, app.parse_export.mails)
        return rows

    def test_summary_names_the_recipients(self):
        b = app.p_traps(trap(**MAIL))[6]
        self.assertTrue(b.startswith("relay: bot@example.net -> check@example.org, "))
        self.assertFalse(app.canary_is_login("smtp", b))
        many = dict(MAIL, rcpts=["r%d@x" % i for i in range(20)], rcpt_count=40)
        self.assertIn("+35 more", app.p_traps(trap(**many))[6])
        self.assertIn("-> ?", app.p_traps(trap(event="mail", rcpts="not a list"))[6])

    def test_mail_is_kept_and_escaped(self):
        self.ingest([trap(**MAIL)])
        m = self.con.execute("SELECT * FROM mails").fetchone()
        self.assertEqual(json.loads(m["rcpts"])[0], "check@example.org")
        self.assertEqual((m["helo"], m["size"], m["mail_from"]), ("WIN-ABC", 2048, "bot@example.net"))
        html = app.v_ip(IP)
        self.assertIn("Mail to the relay trap", html)
        self.assertIn("check@example.org", html)
        self.assertIn("2.0 KB", html)
        self.assertNotIn("<script>alert(1)", html)
        self.assertNotIn("<img src=x", html)
        self.assertIn("&lt;script&gt;", html)

    def test_old_relay_line_is_rewritten(self):
        line = trap(**MAIL)
        h = __import__("hashlib").sha1(line.encode()).hexdigest()
        app.store(self.con, [(h,) + app.p_traps(line)[:6] + ("relay: bot@example.net -> 2 recipient(s): Relay test",)])
        self.ingest([line])
        self.assertIn("check@example.org", self.con.execute("SELECT b FROM events WHERE h=?", (h,)).fetchone()[0])
        self.assertEqual(self.con.execute("SELECT COUNT(*) FROM mails").fetchone()[0], 1)

    def test_helo_groups_on_campaigns(self):
        self.ingest([trap(event="helo", helo="WIN-ABC", off=1), trap(IP2, event="helo", helo="win-abc", off=2),
                     trap(event="helo", helo="", off=3), trap(event="helo", helo="<x>", off=4)])
        n = self.con.execute("SELECT COUNT(*) FROM events WHERE b LIKE 'HELO %'").fetchone()[0]
        self.assertEqual(n, 3)                                   # an empty name is not stored
        html = app.v_campaigns()
        self.assertIn("Mail clients (HELO)", html)
        row = html.split("win-abc</a>")[1]
        self.assertIn("<td class=num>2</td>", row[:60])           # same name, two IPs, case ignored
        self.assertIn("&lt;x&gt;", html)
        self.assertNotIn("<x>", html)


if __name__ == "__main__":
    unittest.main()
