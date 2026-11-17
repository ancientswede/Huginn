# 0.46.1 Own DNS server for http:BL (Pi-hole drops 127.x answers) and Settings forms saved in the background.
import socket, struct, threading, unittest, urllib.parse
from unittest import mock

from tests.helpers import app
from tests.test_v046 import KEY, SettingsKey, clean


def dns_reply(query, answer=None, rcode=0, tid=None, compress=True):
    # A reply to `query`: the same question, optionally one A record (as a compression pointer to the question name).
    q = query[12:]
    flags = 0x8180 | rcode
    hdr = (tid or query[:2]) + struct.pack(">HHHHH", flags, 1, 1 if answer else 0, 0, 0)
    body = q
    if answer:
        name = b"\xc0\x0c" if compress else q[:-4]
        body += name + struct.pack(">HHIH", 1, 1, 300, 4) + bytes(answer)
    return hdr + body


class FakeServer:
    def __init__(self, handler):
        self.sk = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sk.bind(("127.0.0.1", 0))
        self.port = self.sk.getsockname()[1]
        self.handler, self.names = handler, []
        threading.Thread(target=self.run, daemon=True).start()

    def run(self):
        while True:
            try:
                data, addr = self.sk.recvfrom(1500)
            except OSError:
                return
            i, labels = 12, []
            while data[i]:
                labels.append(data[i + 1:i + 1 + data[i]].decode())
                i += 1 + data[i]
            self.names.append(".".join(labels))
            for out in self.handler(data):
                self.sk.sendto(out, addr)

    def close(self):
        self.sk.close()


class DnsClient(unittest.TestCase):
    def ask(self, handler, timeout=1):
        srv = FakeServer(handler)
        try:
            return app.dns_a("127.0.0.1", "abc.example", timeout=timeout, port=srv.port), srv.names
        finally:
            srv.close()

    def test_answer(self):
        self.assertEqual(self.ask(lambda q: [dns_reply(q, [127, 1, 1, 1])])[0], [127, 1, 1, 1])
        self.assertEqual(self.ask(lambda q: [dns_reply(q, [127, 2, 3, 4], compress=False)])[0], [127, 2, 3, 4])

    def test_nxdomain_and_empty(self):
        self.assertIsNone(self.ask(lambda q: [dns_reply(q, rcode=3)])[0])
        self.assertIsNone(self.ask(lambda q: [dns_reply(q)])[0])

    def test_wrong_id_ignored(self):
        # A reply with another id is skipped; the real one after it counts.
        self.assertEqual(self.ask(lambda q: [dns_reply(q, [10, 0, 0, 1], tid=b"\xff\xff" if q[:2] != b"\xff\xff" else b"\x00\x00"),
                                             dns_reply(q, [127, 0, 5, 2])])[0], [127, 0, 5, 2])

    def test_server_error_and_silence(self):
        with self.assertRaises(OSError):
            self.ask(lambda q: [dns_reply(q, rcode=2)])
        with self.assertRaises(OSError):
            self.ask(lambda q: [], timeout=0.2)

    def test_query_goes_to_chosen_server(self):
        with mock.patch.object(app, "dns_a", return_value=[127, 1, 1, 1]) as d:
            self.assertEqual(app.hb_test(KEY, "9.9.9.9"), "ok")
        d.assert_called_once_with("9.9.9.9", KEY + ".1.1.1.127.dnsbl.httpbl.org")


class DnsSetting(unittest.TestCase):
    def test_choice_and_fallback(self):
        con = app.connect()
        clean(con)
        with mock.patch.object(app, "HB_DNS", ""):
            self.assertEqual(app.hb_dns(con), "system")
        with mock.patch.object(app, "HB_DNS", "1.1.1.1"):
            self.assertEqual(app.hb_dns(con), "1.1.1.1")
            app.set_meta(con, "hb_dns", "system")
            self.assertEqual(app.hb_dns(con), "system")      # Settings wins over the start value
        app.set_meta(con, "hb_dns", "not-an-ip")
        self.assertEqual(app.hb_dns(con), "system")
        with con:
            con.execute("DELETE FROM meta WHERE k='hb_dns'")


class SettingsDns(SettingsKey):
    def post(self, fields, dns_answer):
        with mock.patch.object(app, "dns_a", return_value=dns_answer) as d:
            r = self.req("POST", "/settings/httpbl", urllib.parse.urlencode(fields), self.hdr({"Cookie": self.cookie}))
        return r, d

    def test_public_dns_saved_and_used(self):
        con = app.connect()
        (r, _), d = self.post({"key": KEY, "dns": "1.1.1.1"}, [127, 1, 1, 1])
        self.assertEqual(r.status, 303)
        self.assertEqual(app.get_meta(con, "hb_dns"), "1.1.1.1")
        self.assertEqual(d.call_args[0][0], "1.1.1.1")
        # Empty key keeps the saved one, so only the server changes.
        (r, _), d = self.post({"key": "", "dns": "9.9.9.9"}, [127, 1, 1, 1])
        self.assertEqual(r.status, 303)
        self.assertEqual((app.get_meta(con, "hb_key"), app.get_meta(con, "hb_dns")), (KEY, "9.9.9.9"))
        _r, html = self.req("GET", "/settings", headers={"Cookie": self.cookie})
        self.assertIn('<option value="9.9.9.9" selected>', html)
        self.assertNotIn(KEY, html)
        with con:
            con.execute("DELETE FROM meta WHERE k='hb_dns'")
        app.set_meta(con, "hb_key", "")

    def test_bad_server_and_no_answer(self):
        con = app.connect()
        app.set_meta(con, "hb_key", "")
        (r, _), _d = self.post({"key": KEY, "dns": "evil;rm"}, [127, 1, 1, 1])
        self.assertEqual(r.status, 400)
        (r, html), _d = self.post({"key": KEY, "dns": "8.8.8.8"}, None)
        self.assertEqual(r.status, 400)
        self.assertIn("No answer from Project Honey Pot through Google (8.8.8.8)", html)
        (r, html), _d = self.post({"key": "", "dns": "8.8.8.8"}, [127, 1, 1, 1])
        self.assertEqual(r.status, 400)
        self.assertIn("Paste the access key", html)
        self.assertEqual(app.get_meta(con, "hb_key"), "")


class BackgroundSave(unittest.TestCase):
    def test_script_and_no_inline_style(self):
        self.assertIn("box.innerHTML=fresh.innerHTML", app.JS)
        self.assertIn("value==='appearance'", app.JS)
        form = app.hb_form(app.connect(), False)
        self.assertNotIn("style=", form)            # the CSP blocks inline styles


del SettingsKey      # imported only as a base class: do not run its tests twice

if __name__ == "__main__":
    unittest.main()
