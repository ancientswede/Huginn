# 0.26 Fake SSH proxy: Cowrie answers a plain HTTP proxy check with an empty 200 page and holds TLS, never forwards.
import json, os, tempfile, time, unittest

from tests.helpers import app, ROOT

import importlib.util
_spec = importlib.util.spec_from_file_location("hp_patches", os.path.join(ROOT, "honeypot", "patches.py"))
patches = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(patches)

IP = "198.51.100.131"

# The shape of Cowrie's FakeForwardingChannel.dataReceived around the patched lines (upstream text in FWD_OLD).
FIXTURE = '''class FakeForwardingChannel:
    def dataReceived(self, data):
        events = self.conn.transport.events
        if events:
            events.dispatch(
                "cowrie.direct-tcpip.data",
                "discarded",
                dst_ip=self.hostport[0],
                dst_port=self.hostport[1],
''' + patches.FWD_OLD + "\n"


class Events:
    def __init__(self):
        self.sent = []

    def dispatch(self, eventid, fmt, **kw):
        self.sent.append(dict(kw, eventid=eventid))


class Chan:
    def __init__(self, port):
        self.hostport = ("93.184.216.34", port)
        self.id = 1
        self.events = Events()
        self.conn = type("C", (), {"transport": type("T", (), {"events": self.events})()})()
        self.out, self.lost, self.refused = b"", False, None

    def write(self, b):
        self.out += b

    def loseConnection(self):
        self.lost = True

    def _close(self, reason):
        self.refused = reason


class Patch(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "forwarding.py")
        open(self.path, "w").write(FIXTURE)

    def load(self):
        ns = {}
        exec(compile(open(self.path).read(), self.path, "exec"), ns)
        held = []
        ns["hp_hold"] = held.append                   # no Twisted here: record instead of scheduling
        return ns, held

    def test_patch_once_and_keeps_original(self):
        self.assertEqual(patches.cowrie_forward(self.path), 0)
        self.assertEqual(patches.cowrie_forward(self.path), 3)
        self.assertEqual(open(self.path + ".orig").read(), FIXTURE)
        other = os.path.join(self.dir, "other.py")
        open(other, "w").write("x = 1\n")
        self.assertEqual(patches.cowrie_forward(other), 1)
        self.assertEqual(open(other).read(), "x = 1\n")

    def test_http_check_is_answered(self):
        patches.cowrie_forward(self.path)
        ns, _held = self.load()
        ch = Chan(80)
        ns["FakeForwardingChannel"].dataReceived(ch, b"GET / HTTP/1.1\r\nHost: yahoo.com\r\nUser-Agent: x\r\n\r\n")
        head, body = ch.out.split(b"\r\n\r\n", 1)
        self.assertTrue(head.startswith(b"HTTP/1.1 200 OK"))
        self.assertIn(b"Content-Length: %d" % len(body), head)
        self.assertIn(b"<title>yahoo.com</title>", body)
        self.assertTrue(ch.lost)
        self.assertIsNone(ch.refused)
        rep = [e for e in ch.events.sent if e["eventid"] == "cowrie.direct-tcpip.hp-reply"][0]
        self.assertEqual((rep["hp_reply"], rep["hp_request"]), ("http200", "GET yahoo.com/"))
        # More data on the same channel is not answered twice.
        ns["FakeForwardingChannel"].dataReceived(ch, b"GET / HTTP/1.1\r\n\r\n")
        self.assertEqual(ch.out.count(b"HTTP/1.1 200"), 1)

    def test_tls_is_held_and_other_refused(self):
        patches.cowrie_forward(self.path)
        ns, held = self.load()
        ch = Chan(443)
        ns["FakeForwardingChannel"].dataReceived(ch, b"\x16\x03\x01\x02\x00\x01" + b"\x00" * 40)
        self.assertEqual(held, [ch])
        self.assertEqual((ch.out, ch.lost, ch.refused), (b"", False, None))
        for port, data in [(53, b"\x00\x1c"), (80, b"\x16\x03\x01"), (80, b"CONNECT a:443 HTTP/1.1\r\n\r\n"), (2535, b"GET / HTTP/1.1\r\n")]:
            ch = Chan(port)
            ns["FakeForwardingChannel"].dataReceived(ch, data)
            self.assertEqual(ch.refused, "Connection refused")
            self.assertEqual(ch.out, b"")

    def test_reply_details(self):
        ns = {}
        exec(patches.FWD_HELPER, ns)
        r = ns["hp_proxy_reply"]
        kind, raw, req = r(80, b"HEAD /x HTTP/1.0\r\nhost: Example.ORG:80\r\n\r\n")
        self.assertTrue(raw.endswith(b"\r\n\r\n"))                       # HEAD: headers only
        self.assertEqual(req, "HEAD example.org/x")
        self.assertEqual(r(80, b"GET http://ya.ru/?q=1 HTTP/1.1\r\n\r\n")[2], "GET ya.ru/?q=1")
        bad = r(80, b"POST /bot/statistic HTTP/1.1\r\nHost: <script>alert(1)</script>\r\n\r\n")
        self.assertNotIn(b"<script>", bad[1])                              # only a plain host name ever reaches the page
        self.assertEqual(bad[2], "POST ?/bot/statistic")
        ns["HP_HOLDS"][0] = ns["HP_HOLD_MAX"]
        self.assertIsNone(r(443, b"\x16\x03\x01"))                        # cap reached: refuse as before
        ns["HP_HOLDS"][0] = 0
        self.assertEqual(len(r(80, b"GET / HTTP/1.1\r\n" + b"A" * 90000)[1]) < 1024, True)   # reply size never follows the input
        self.assertEqual(r(80, b"GET / HTTP/1.1\r\n\r\n")[2], "GET ?/")


class Huginn(unittest.TestCase):
    def setUp(self):
        self.con = app.connect()
        self.clean()

    def tearDown(self):
        self.clean()

    def clean(self):
        with self.con:
            for t in ("events", "sessions", "ips", "seen"):
                self.con.execute("DELETE FROM %s" % t)

    def ev(self, eventid, off=0, **kw):
        e = {"eventid": eventid, "src_ip": IP, "session": "abcd1234", "timestamp":
             time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(time.time() - 600 + off)) + ".000000Z"}
        e.update(kw)
        return json.dumps(e)

    def test_parse_store_and_pages(self):
        lines = [self.ev("cowrie.session.connect", 0, protocol="ssh", dst_port=22),
                 self.ev("cowrie.login.success", 1, username="root", password="x"),
                 self.ev("cowrie.direct-tcpip.request", 2, dst_ip="98.137.11.163", dst_port=80),
                 self.ev("cowrie.direct-tcpip.hp-reply", 3, hp_reply="http200", hp_request="GET yahoo.com/<b>x</b>"),
                 self.ev("cowrie.direct-tcpip.hp-reply", 4, hp_reply="evil", hp_request="GET a/"),
                 self.ev("cowrie.session.closed", 5, duration=5)]
        rows = [r for r in (app.p_cowrie(l) for l in lines) if r]
        self.assertEqual(sum(1 for r in rows if r[3] == "proxy_reply"), 1)  # unknown reply kinds are dropped
        import hashlib
        app.store(self.con, [(hashlib.sha1(repr(r).encode()).hexdigest(),) + r for r in rows])
        s = self.con.execute("SELECT tcpip FROM sessions").fetchone()
        self.assertEqual(s[0], 1)                                          # the answer is not a second proxy attempt
        ip = app.v_ip(IP)
        self.assertIn("answered 200", ip)
        self.assertNotIn("<b>x</b>", ip)
        camp = app.v_campaigns()
        self.assertIn("Proxy use", camp)
        self.assertIn("GET yahoo.com/&lt;b&gt;x&lt;/b&gt;", camp)
        self.assertIn("1 answered by the honeypot", camp)


if __name__ == "__main__":
    unittest.main()
