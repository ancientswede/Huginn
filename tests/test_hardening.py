# Regression tests for the 0.16.1 security review: export parsing, bad stored values and HTTP handling.
import base64, http.client, importlib.util, json, os, socket, tempfile, threading, time, unittest
from datetime import datetime, timezone
from unittest import mock

from tests.helpers import ROOT, app

LS = " "
NOW = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
A = "198.51.100.70"
VICTIM = "192.0.2.77"


def traps_line(password, ensure_ascii=False):
    # What an older hp-traps wrote: other honeypots may not be updated yet, so Huginn has to cope by itself.
    return json.dumps({"ts": NOW, "src_ip": A, "src_port": 4444, "service": "pop3", "event": "login",
                       "username": "u", "password": password}, ensure_ascii=ensure_ascii)


def export(traps):
    return "##COWRIE\n##CANARY\n##ENDLESSH\n##NFT\n##TRAPS\n%s\n##FILES\n##END\n" % traps


class Injection(unittest.TestCase):
    def test_line_separators_do_not_split_a_record(self):
        for sep in (LS, " ", "\x85"):
            pw = sep + "##ENDLESSH" + sep + NOW + " CLOSE host=%s port=22 fd=1 time=30.0" % VICTIM + sep + "##TRAPS" + sep
            rows, _ = app.parse_export(export(traps_line(pw)), set())
            self.assertEqual([r[2] for r in rows], [A])
            self.assertEqual(rows[0][4], "canary")

    def test_cannot_hide_later_events(self):
        text = export(traps_line(LS + "##NFT" + LS) + "\n" + traps_line("later"))
        rows, _ = app.parse_export(text, set())
        self.assertEqual(len(rows), 2)

    def test_section_names_in_logged_text_announce_nothing(self):
        app.parse_export(export(traps_line("##PERSONAS ##BAIT")), set())
        self.assertFalse(app.parse_export.meta["has_personas"])
        self.assertFalse(app.parse_export.meta["has_bait"])
        app.parse_export("##PERSONAS\n2225=server\n##BAIT\n{}\n##END\n", set())
        self.assertTrue(app.parse_export.meta["has_personas"])
        self.assertTrue(app.parse_export.meta["has_bait"])

    def test_end_marker_must_be_the_last_line(self):
        cowrie = json.dumps({"eventid": "cowrie.login.failed", "src_ip": A, "timestamp": NOW, "username": "##END"})
        with mock.patch.object(app, "HP_HOST", "hp.invalid"), mock.patch.object(app, "run_capped", return_value=(0, ("##COWRIE\n%s\n" % cowrie).encode(), b"")):
            with self.assertRaises(RuntimeError):
                app.fetch_export()
        with mock.patch.object(app, "HP_HOST", "hp.invalid"), mock.patch.object(app, "run_capped", return_value=(0, b"##COWRIE\n##END\n", b"")):
            self.assertIn("##END", app.fetch_export())

    def test_hp_traps_writes_ascii(self):
        spec = importlib.util.spec_from_file_location("hp_traps", os.path.join(ROOT, "honeypot", "hp-traps.py"))
        traps = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(traps)
        with tempfile.TemporaryDirectory() as d:
            traps.LOGDIR = d
            traps.log((A, 1), "pop3", "login", username="å" + LS, password=base64.b64decode("4oCo").decode())
            raw = open(os.path.join(d, os.listdir(d)[0]), "rb").read()
        self.assertTrue(raw.isascii())
        self.assertEqual(json.loads(raw)["username"], "å" + LS)


class BadValues(unittest.TestCase):
    def closed(self, **kw):
        ev = {"eventid": "cowrie.session.closed", "src_ip": A, "timestamp": NOW, "session": "abc"}
        ev.update(kw)
        return app.p_cowrie(json.dumps(ev))

    def rows(self, line, section="ENDLESSH"):
        return app.parse_export("##%s\n%s\n##END\n" % (section, line), set())[0]

    def test_times_out_of_range(self):
        for ts in ("9999-12-31T23:59:59Z", "0001-01-01T00:00:00Z", "2099-01-01T00:00:00Z"):
            self.assertEqual(self.rows("%s CLOSE host=%s port=22 fd=1 time=30.0" % (ts, VICTIM)), [])
        self.assertEqual(len(self.rows("%s CLOSE host=%s port=22 fd=1 time=30.0" % (NOW, VICTIM))), 1)

    def test_tarpit_time(self):
        self.assertEqual(self.rows("%s CLOSE host=%s port=22 fd=1 time=%s" % (NOW, VICTIM, "9" * 400)), [])
        self.assertEqual(len(self.rows("%s CLOSE host=%s port=51234 fd=4 time=812.345 bytes=1" % (NOW, VICTIM))), 1)

    def test_durations(self):
        for bad in ("inf", "-inf", "nan", "-1", "1e300", {"x": 1}):
            self.assertIsNone(self.closed(duration=bad)[5], bad)
        self.assertEqual(self.closed(duration="12.5")[5], "12.5")
        self.assertEqual(self.closed(duration_ms=2500)[5], "2.5")

    def test_session_must_be_a_plain_id(self):
        ev = {"eventid": "cowrie.login.failed", "src_ip": A, "timestamp": NOW, "username": "u", "password": "p"}
        for bad in ({"x": 1}, "a b", "x" * 65):
            self.assertEqual(self.rows(json.dumps(dict(ev, session=bad)), "COWRIE"), [])

    def test_old_bad_rows_do_not_break_pages(self):
        # Stored before this version, so never checked on the way in.
        self.assertEqual(app.dur(float("inf")), "–")
        self.assertEqual(app.dur(float("nan")), "–")
        self.assertEqual(app.fmt_ts(1e30), "–")
        self.assertEqual(app.fmt_tss(1e30), "–")
        con = app.connect()
        ts = time.time() - 60
        app.store(con, [("hard-inf", ts, "192.0.2.78", "endlessh", "tarpit", None, "9" * 400, "22")])
        try:
            self.assertIn("192.0.2.78", app.v_ip("192.0.2.78"))
            self.assertIn("Overview", app.v_overview())
        finally:
            with con:
                con.execute("DELETE FROM events WHERE ip='192.0.2.78'")
            app.recompute_ip(con, "192.0.2.78")
            con.commit()


class Http(unittest.TestCase):
    PW = "hardening-password-1"

    @classmethod
    def setUpClass(cls):
        app.set_meta(app.connect(), "pw", app.hash_pw(cls.PW))
        cls.srv = app.HuginnServer(("127.0.0.1", 0), app.Handler)
        cls.port = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()
        app._fails.clear()

    def setUp(self):
        app._fails.clear()

    def login(self, pw, out=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=60)
        c.request("POST", "/login", "password=" + pw, {"Host": "x", "Origin": "http://x", "Content-Type": "application/x-www-form-urlencoded"})
        status = c.getresponse().status
        c.close()
        if out is not None:
            out.append(status)
        return status

    def raw(self, data, port=None):
        s = socket.create_connection(("127.0.0.1", port or self.port))
        s.settimeout(5)
        s.sendall(data)
        got = b""
        try:
            while True:
                b = s.recv(65536)
                if not b:
                    return got, True
                got += b
        except socket.timeout:
            return got, False
        finally:
            s.close()

    def test_login_limit_holds_in_parallel(self):
        calls, real = [], app.check_pw
        def counted(p, s):
            calls.append(1)
            return real(p, s)
        codes = []
        with mock.patch.object(app, "check_pw", counted):
            ts = [threading.Thread(target=self.login, args=("wrong", codes)) for _ in range(12)]
            [t.start() for t in ts]
            [t.join() for t in ts]
        self.assertEqual(len(calls), 5)
        self.assertEqual(codes.count(401), 5)
        self.assertEqual(codes.count(429), 7)

    def test_right_password_does_not_use_up_the_limit(self):
        for _ in range(8):
            self.assertEqual(self.login(self.PW), 303)
        self.assertEqual(self.login("wrong"), 401)

    def test_unread_body_is_not_a_second_request(self):
        for head in (b"POST /nope HTTP/1.1\r\nHost: x\r\n", b"POST /nope HTTP/1.1\r\nHost: x\r\nOrigin: http://x\r\n", b"GET /healthz HTTP/1.1\r\nHost: x\r\n"):
            body = b"GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n"
            got, closed = self.raw(head + b"Content-Length: %d\r\n\r\n" % len(body) + body)
            self.assertEqual(got.count(b"HTTP/1.1 "), 1, head)
            self.assertTrue(closed, head)

    def test_chunked_body_and_double_length_close(self):
        got, closed = self.raw(b"POST /nope HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /healthz HTTP/1.1\r\nHost: x\r\n\r\n")
        self.assertEqual((got.count(b"HTTP/1.1 "), closed), (1, True))
        got, closed = self.raw(b"POST /login HTTP/1.1\r\nHost: x\r\nOrigin: http://x\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\nx")
        self.assertEqual((got.count(b"HTTP/1.1 "), closed), (1, True))

    def test_keep_alive_still_works(self):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        for _ in range(2):
            c.request("GET", "/login", headers={"Host": "x"})
            self.assertEqual(c.getresponse().read().count(b"<form"), 1)
        c.close()

    def test_stalled_client_times_out(self):
        class Quick(app.Handler):
            timeout = 1
        srv = app.HuginnServer(("127.0.0.1", 0), Quick)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            t0 = time.time()
            s = socket.create_connection(("127.0.0.1", srv.server_address[1]))
            s.settimeout(5)
            s.sendall(b"POST /login HTTP/1.1\r\nHost: x\r\nOrigin: http://x\r\nContent-Length: 20000\r\n\r\n")
            while s.recv(4096):
                pass
            s.close()
            self.assertLess(time.time() - t0, 4)
        finally:
            srv.shutdown()
            srv.server_close()

    def test_connection_cap(self):
        class Small(app.HuginnServer):
            max_clients = 2
        srv = Small(("127.0.0.1", 0), app.Handler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        held = []
        try:
            held = [socket.create_connection(("127.0.0.1", srv.server_address[1])) for _ in range(2)]
            time.sleep(0.2)
            got, closed = self.raw(b"GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n", srv.server_address[1])
            self.assertEqual((got, closed), (b"", True))
            [s.close() for s in held]
            held = []
            deadline = time.time() + 5
            while time.time() < deadline:
                got, _ = self.raw(b"GET /healthz HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n", srv.server_address[1])
                if got:
                    break
                time.sleep(0.1)
            self.assertIn(b"HTTP/1.1", got)           # slots come back
        finally:
            [s.close() for s in held]
            srv.shutdown()
            srv.server_close()


if __name__ == "__main__":
    unittest.main()
