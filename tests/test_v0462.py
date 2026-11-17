# 0.46.2 Fixes from the Codex review of 0.45-0.46.1 (huginn-granskning-046): presence days, return alerts, DNS client, Settings JS.
import json, struct, unittest
from unittest import mock

from tests.helpers import app
from tests.test_v045 import Base, A, NOW, DAY
from tests.test_v0461 import FakeServer, dns_reply


class Presence(Base):
    def test_commands_every_day_are_not_a_return(self):
        # M1: one long session with commands every day, then a new session: never quiet, so not "returned".
        with self.con:
            self.sess("long", A, NOW - 10 * DAY, lo=1, cmds=10)
            self.con.execute("UPDATE sessions SET end=? WHERE session=?", (NOW, "long"))
            for d in range(11):
                self.con.execute("INSERT INTO events(h,ts,ip,src,kind,session,a) VALUES(?,?,?,?,?,?,?)",
                                 ("daily%d" % d, NOW - d * DAY, A, "cowrie", "cmd", "long", "id"))
            self.sess("new", A, NOW)
        self.assertIsNone(app.return_info(self.con, A))
        self.assertNotIn("returned", self.ip(A)["tags"])

    def test_open_session_counts_as_present(self):
        with self.con:
            self.sess("open", A, NOW - 10 * DAY)
            self.con.execute("UPDATE sessions SET end=? WHERE session=?", (NOW - 1 * DAY, "open"))
            self.sess("new", A, NOW)
        self.assertIsNone(app.return_info(self.con, A))

    def test_real_return_still_found(self):
        with self.con:
            self.sess("before", A, NOW - 9 * DAY)
            self.sess("after", A, NOW)
        self.assertEqual(app.return_info(self.con, A)[0], 8)

    def test_told_ones_do_not_hide_a_new_return(self):
        # L1: 200 already-told higher scores must not push a new stepped-up address out.
        with self.con:
            self.sess("before", A, NOW - 20 * DAY)
            self.sess("after", A, NOW, cmds=1)
            app.recompute_ip(self.con, A)
            orig = self.con.execute("SELECT * FROM ips WHERE ip=?", (A,)).fetchone()
            told = {}
            for i in range(200):
                ip = "198.18.%d.%d" % (i // 250, i % 250 + 1)
                vals = list(orig)
                vals[0], vals[-2] = ip, orig["score"] + 10
                self.con.execute("INSERT INTO ips VALUES(%s)" % ",".join("?" * len(vals)), vals)
                told[ip] = NOW // DAY * DAY
            app.set_meta(self.con, "ntfy_returned", json.dumps(told))
        self.assertEqual([x[0] for x in app.returned_news(self.con, NOW - DAY)], [A])
        with self.con:
            self.con.execute("DELETE FROM ips WHERE ip LIKE '198.18.%'")


class StrictDns(unittest.TestCase):
    def ask(self, handler):
        srv = FakeServer(handler)
        try:
            return app.dns_a("127.0.0.1", "abc.example", timeout=0.3, port=srv.port)
        finally:
            srv.close()

    def test_other_owner_is_not_an_answer(self):
        def reply(q):
            r = dns_reply(q, [127, 0, 99, 4])
            n = len(q[12:])
            return [r[:12 + n] + b"\x04evil\x07example\x00" + r[12 + n + 2:]]
        self.assertIsNone(self.ask(reply))

    def test_pointer_loop_and_truncation_rejected(self):
        def loop(q):
            r = bytearray(dns_reply(q, [127, 0, 99, 4]))
            r[len(q):len(q) + 2] = struct.pack(">H", 0xC000 | len(q))
            return [bytes(r)]

        def tc(q):
            r = bytearray(dns_reply(q, [127, 0, 99, 4]))
            r[2] |= 2
            return [bytes(r)]
        for h in (loop, tc):
            with self.assertRaises(OSError):
                self.ask(h)

    def test_rdlen_outside_rejected(self):
        def reply(q):
            r = bytearray(dns_reply(q, [127, 0, 99, 4]))
            r[-6:-4] = b"\xff\xff"
            return [bytes(r)]
        with self.assertRaises(OSError):
            self.ask(reply)

    def test_cname_chain_followed(self):
        def reply(q):
            n = len(q[12:])
            hdr = q[:2] + struct.pack(">HHHHH", 0x8180, 1, 2, 0, 0)
            target = b"\x01x\x07example\x00"
            cname = b"\xc0\x0c" + struct.pack(">HHIH", 5, 1, 60, len(target)) + target
            a = target + struct.pack(">HHIH", 1, 1, 60, 4) + bytes([127, 0, 9, 2])
            return [hdr + q[12:12 + n] + cname + a]
        self.assertEqual(self.ask(reply), [127, 0, 9, 2])

    def test_wrong_question_and_short_packet_ignored(self):
        def reply(q):
            wrong = bytearray(dns_reply(q, [127, 0, 99, 4]))
            wrong[13] ^= 1
            return [b"x", bytes(wrong), dns_reply(q, [127, 1, 2, 3])]
        self.assertEqual(self.ask(reply), [127, 1, 2, 3])


class Guards(unittest.TestCase):
    def test_dns_server_choices(self):
        for v in ("system", "1.1.1.1", "127.0.0.53", "192.168.1.1"):
            self.assertTrue(app.hb_dns_ok(v), v)
        for v in ("224.0.0.251", "0.0.0.0", "255.255.255.255", "240.0.0.1", "1.1.1", "::1", "x"):
            self.assertFalse(app.hb_dns_ok(v), v)

    def test_key_never_in_error(self):
        con = app.connect()
        app.set_meta(con, "hb_key", "abcdefghijkl")
        app.set_meta(con, "hb_wait_until", "0")
        with con:
            con.execute("DELETE FROM httpbl")
            con.execute("INSERT OR REPLACE INTO ips(ip, first, last, score, sessions, logins_ok, logins_fail, cmds, files, tcpip, exploits, tags) "
                        "VALUES('203.0.113.90',?,?,99,0,0,0,0,0,0,0,'')", (app.time.time(), app.time.time()))
        boom = OSError("lookup of abcdefghijkl.90.113.0.203.dnsbl.httpbl.org failed")
        with mock.patch.object(app, "hb_query", side_effect=boom), mock.patch.object(app, "sendable_ip", lambda ip: True):
            app.hb_lookup(con)
        err = app.get_meta(con, "hb_error", "")
        self.assertIn("<key>", err)
        self.assertNotIn("abcdefghijkl", err)
        with con:
            con.execute("DELETE FROM ips WHERE ip='203.0.113.90'")
            for k in ("hb_key", "hb_error", "hb_wait_until", "hb_day"):
                con.execute("DELETE FROM meta WHERE k=?", (k,))

    def test_js_never_resubmits(self):
        self.assertNotIn("f.submit()", app.JS.split("// Settings: save a form")[1])
        self.assertIn("No answer from Huginn", app.JS)


if __name__ == "__main__":
    unittest.main()
