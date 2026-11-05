# Parsing of the hp-export stream: Cowrie, OpenCanary, endlessh and hp-traps lines.
import json, unittest

from tests.helpers import app

A = "198.51.100.23"


def cowrie(eventid, **kw):
    ev = {"eventid": eventid, "src_ip": A, "session": "abc123", "timestamp": "2026-11-01T10:00:00.000000Z"}
    ev.update(kw)
    return json.dumps(ev)


class Cowrie(unittest.TestCase):
    def test_login_and_command(self):
        r = app.p_cowrie(cowrie("cowrie.login.success", username="root", password="admin"))
        self.assertEqual(r[1:6], (A, "cowrie", "login_ok", "abc123", "root"))
        self.assertEqual(r[6], "admin")
        r = app.p_cowrie(cowrie("cowrie.command.input", input="uname -a"))
        self.assertEqual((r[3], r[5]), ("cmd", "uname -a"))

    def test_timestamp(self):
        r = app.p_cowrie(cowrie("cowrie.session.connect", protocol="ssh", dst_port=2225))
        self.assertEqual(r[0], 1793527200.0)  # 2026-11-01 10:00:00 UTC
        self.assertEqual((r[3], r[5], r[6]), ("connect", "ssh", "2225"))

    def test_file_download(self):
        r = app.p_cowrie(cowrie("cowrie.session.file_download", url="http://192.0.2.9/x.sh", shasum="ab" * 32))
        self.assertEqual((r[3], r[5], r[6]), ("file", "http://192.0.2.9/x.sh", "ab" * 32))

    def test_session_closed_duration(self):
        self.assertEqual(app.p_cowrie(cowrie("cowrie.session.closed", duration_ms=1500))[5], "1.5")
        self.assertEqual(app.p_cowrie(cowrie("cowrie.session.closed", duration=2.0))[5], "2.0")

    def test_ignored(self):
        self.assertIsNone(app.p_cowrie(cowrie("cowrie.something.unknown")))
        self.assertIsNone(app.p_cowrie("not json"))
        self.assertIsNone(app.p_cowrie(cowrie("cowrie.log.closed", shasum="", size=0)))

    def test_private_and_mapped_addresses(self):
        self.assertIsNone(app.p_cowrie(cowrie("cowrie.command.input", input="id", src_ip="192.168.1.5")))
        self.assertIsNone(app.p_cowrie(cowrie("cowrie.command.input", input="id", src_ip="127.0.0.1")))
        self.assertEqual(app.p_cowrie(cowrie("cowrie.command.input", input="id", src_ip="::ffff:" + A))[1], A)

    def test_mask_own_address(self):
        r = app.p_cowrie(cowrie("cowrie.command.input", input="ping 203.0.113.250; curl victim.example"))
        self.assertEqual(r[5], "ping [self]; curl [self]")


class Canary(unittest.TestCase):
    def ev(self, port, logdata):
        return json.dumps({"src_host": A, "utc_time": "2026-11-01 10:00:00.000000", "dst_port": port, "logdata": logdata})

    def test_login(self):
        r = app.p_canary(self.ev(3306, {"USERNAME": "root", "PASSWORD": "toor"}))
        self.assertEqual((r[2], r[3], r[5], r[6]), ("canary", "canary", "mysql", "root / toor"))

    def test_http_path_and_hostname_dropped(self):
        r = app.p_canary(self.ev(8080, {"PATH": "/.env", "METHOD": "GET", "STATUS": 404, "USERAGENT": "zgrab", "HOSTNAME": "203.0.113.250"}))
        self.assertEqual(r[5], "http")
        self.assertIn("GET /.env (404)", r[6])
        self.assertNotIn("203.0.113.250", r[6])

    def test_missing_source(self):
        self.assertIsNone(app.p_canary(json.dumps({"utc_time": "2026-11-01 10:00:00.000000", "dst_port": 21})))


class Endlessh(unittest.TestCase):
    def test_close_and_accept(self):
        r = app.p_endlessh("2026-11-01T10:00:00.000Z CLOSE host=::ffff:%s port=51234 fd=4 time=812.345 bytes=1234" % A)
        self.assertEqual((r[1], r[3], r[5], r[6]), (A, "tarpit", "812.345", "51234"))
        r = app.p_endlessh("2026-11-01T10:00:00.000Z ACCEPT host=%s port=51234 fd=4 n=1/4096" % A)
        self.assertEqual(r[3], "tarpit_open")
        self.assertIsNone(app.p_endlessh("garbage"))


class Traps(unittest.TestCase):
    def ev(self, **kw):
        d = {"ts": "2026-11-01T10:00:00.000000Z", "src_ip": A, "service": "smtp"}
        d.update(kw)
        return json.dumps(d)

    def test_events(self):
        self.assertEqual(app.p_traps(self.ev(event="login", service="postgres", username="postgres", password="pw", database="prod"))[6],
                         "postgres / pw  (db prod)")
        self.assertIn("relay: a@example.com -> 3", app.p_traps(self.ev(event="mail", mail_from="a@example.com", rcpt_count=3, subject="hi"))[6])
        self.assertEqual(app.p_traps(self.ev(event="proxy", service="socks5", target="192.0.2.1:443"))[6], "proxy -> 192.0.2.1:443")
        self.assertIsNone(app.p_traps(self.ev(event="unknown")))


class Export(unittest.TestCase):
    def test_sections_dedupe_and_files(self):
        line = cowrie("cowrie.command.input", input="id")
        text = "\n".join(["##COWRIE", line, "##CANARY", "{broken json", "##FILES",
                          json.dumps({"sha": "cd" * 32, "size": 10}), "##NFT", "dport 22 counter packets 5", "##END"])
        rows, hashes = app.parse_export(text, set())
        self.assertEqual(len(rows), 1)
        self.assertEqual(len(app.parse_export.files), 1)
        rows2, _ = app.parse_export(text, hashes)
        self.assertEqual(rows2, [])


if __name__ == "__main__":
    unittest.main()
