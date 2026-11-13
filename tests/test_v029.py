# 0.29 Honeypot realism and collection health: wget prints what the persona's own wget prints, an uploaded program for the
# right CPU "runs" silently (simulated, logged), and Huginn alerts when data stops coming in.
import hashlib, json, os, shutil, tempfile, time, unittest
from unittest import mock

from tests.helpers import app, ROOT

import importlib.machinery, importlib.util

_spec = importlib.util.spec_from_loader("hp_patches_029", importlib.machinery.SourceFileLoader("hp_patches_029", os.path.join(ROOT, "honeypot", "patches.py")))
patches = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(patches)

IP = "198.51.100.171"


def wget_ns():
    ns = {}
    exec(patches.WGET_HELPER, ns)
    return ns


class Cmd:
    def __init__(self, arch, host="77.239.124.124", port=8085, quiet=False):
        self.protocol = type("P", (), {"user": type("U", (), {"server": type("S", (), {"arch": arch})()})()})()
        self.host, self.port, self.quiet = host, port, quiet


def run(ns, cmd, pieces):
    return "".join(x for p in pieces for x in ns["hp_wget_text"](cmd, p))


TIMEOUT = ["--2026-11-13 10:00:00--  http://77.239.124.124:8085/x\n", "Connecting to 77.239.124.124:8085... connected.\n",
           "HTTP request sent, awaiting response... ", "cancel failed: Operation timed out.\n"]


class Wget(unittest.TestCase):
    def test_busybox_camera(self):
        ns = wget_ns()
        out = run(ns, Cmd("linux-arm-lsb"), TIMEOUT)
        self.assertEqual(out, "Connecting to 77.239.124.124:8085 (77.239.124.124:8085)\n"
                              "wget: can't connect to remote host (77.239.124.124): Connection timed out\n")
        dns = run(ns, Cmd("linux-mips-msb", host="evil.example"), ["--2026-11-13 10:00:00--  http://evil.example/x\n",
              "Resolving evil.example (evil.example)... failed: Temporary failure in name resolution.\n",
              "wget: unable to resolve host address ‘evil.example’\n"])
        self.assertEqual(dns, "wget: bad address 'evil.example'\n")
        quiet = run(ns, Cmd("linux-arm-lsb", quiet=True), ["failed: Connection timed out.\n"])
        self.assertEqual(quiet, "wget: can't connect to remote host (77.239.124.124): Connection timed out\n")   # BusyBox -q still says why

    def test_gnu_server(self):
        ns = wget_ns()
        out = run(ns, Cmd("linux-x64-lsb"), TIMEOUT)
        self.assertEqual(out, "--2026-11-13 10:00:00--  http://77.239.124.124:8085/x\nConnecting to 77.239.124.124:8085... failed: Connection timed out.\n")
        self.assertNotIn("connected", out)                                   # no "connected" before a failure
        ok = run(ns, Cmd("linux-x64-lsb"), TIMEOUT[:3] + ["200 OK\n"])
        self.assertIn("connected.\nHTTP request sent, awaiting response... 200 OK\n", ok)   # a real answer: the held lines come out
        self.assertEqual(run(ns, Cmd("linux-x64-lsb", quiet=True), ["failed: Connection timed out.\n"]), "")   # GNU -q is silent

    def test_ip_is_never_resolved(self):
        ns = wget_ns()
        pieces = ["Resolving 198.51.100.7 (198.51.100.7)... failed: Temporary failure in name resolution.\n",
                  "wget: unable to resolve host address ‘198.51.100.7’\n"]
        self.assertEqual(run(ns, Cmd("linux-x64-lsb", host="198.51.100.7", port=80), pieces),
                         "Connecting to 198.51.100.7:80... failed: Connection refused.\n")
        self.assertEqual(run(ns, Cmd("linux-arm-lsb", host="198.51.100.7", port=80), pieces),
                         "Connecting to 198.51.100.7:80 (198.51.100.7:80)\nwget: can't connect to remote host (198.51.100.7): Connection refused\n")


class Exec(unittest.TestCase):
    def setUp(self):
        self.ns = {}
        exec(patches.EXEC_HELPER, self.ns)
        self.sent = []

    def cmd(self, arch, data):
        sent = self.sent
        ev = type("E", (), {"dispatch": lambda self, eid, fmt, **kw: sent.append(dict(kw, eventid=eid))})()
        c = type("C", (), {})()
        c.fs = type("F", (), {"file_contents": lambda self, p: data})()
        c.protocol = type("P", (), {"events": ev, "user": type("U", (), {"server": type("S", (), {"arch": arch})()})()})()
        c.args, c.exit_code = ["1.2.3.4", "-p", "443"], 126
        return c

    @staticmethod
    def elf(machine, little=True):
        return b"\x7fELF" + bytes([2 if machine in (62, 183) else 1, 1 if little else 2]) + b"\x00" * 12 + machine.to_bytes(2, "little" if little else "big") + b"\x00" * 40

    def test_right_cpu_runs_silently(self):
        data = self.elf(62)
        c = self.cmd("linux-x64-lsb", data)
        self.assertTrue(self.ns["hp_exec_sim"](c, "/tmp/.x", "./.x"))
        self.assertEqual(c.exit_code, 0)
        self.assertEqual(self.sent[0]["eventid"], "cowrie.session.hp-exec")
        self.assertEqual((self.sent[0]["path"], self.sent[0]["args"], self.sent[0]["shasum"]), ("/tmp/.x", "1.2.3.4 -p 443", hashlib.sha256(data).hexdigest()))
        self.assertTrue(self.ns["hp_exec_sim"](self.cmd("linux-arm-lsb", self.elf(40)), "/tmp/a", "a"))
        self.assertTrue(self.ns["hp_exec_sim"](self.cmd("linux-mips-msb", self.elf(8, little=False)), "/tmp/m", "m"))

    def test_wrong_cpu_or_not_a_program(self):
        for arch, data in (("linux-x64-lsb", self.elf(40)), ("linux-arm-lsb", self.elf(62)), ("linux-x64-lsb", b"#!/bin/sh\necho hi\n"),
                           ("linux-x64-lsb", b"\x7fELF"), ("", self.elf(62))):
            c = self.cmd(arch, data)
            self.assertFalse(self.ns["hp_exec_sim"](c, "/tmp/x", "x"))
            self.assertEqual(c.exit_code, 126)
        self.assertEqual(self.sent, [])


class Anchors(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir)

    def test_patch_and_idempotent(self):
        for fn, old, marker in ((patches.cowrie_wget, patches.WGET_OLD, "Huginn wget v1"), (patches.cowrie_exec, patches.EXEC_OLD, "Huginn exec v1")):
            p = os.path.join(self.dir, "f.py")
            body = "class HoneyPotCommand:\n    pass\n\ndef x(self, path, name, prefix):\n    if True:\n        if True:\n            if True:\n                if True:\n" + old + "                    self, path)\n"
            if fn is patches.cowrie_wget:
                body = "class HoneyPotCommand:\n    def errorWrite(self, d):\n        pass\n\n" + old + "    pass\n"
            open(p, "w").write(body)
            self.assertEqual(fn(p), 0)
            self.assertIn(marker, open(p).read())
            self.assertEqual(fn(p), 3)
            self.assertEqual(open(p + ".orig").read(), body)
            open(p, "w").write("x = 1\n")
            self.assertEqual(fn(p), 1)


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
            self.con.execute("DELETE FROM meta WHERE k IN ('health_alerted','health_now','health_limits','last_success','last_error')")

    def test_exec_event_parsed_and_shown(self):
        ts = time.strftime("%Y-%m-%dT%H:%M:%S.000000Z", time.gmtime(time.time() - 600))
        sha = "ab" * 32
        line = lambda **kw: json.dumps(dict({"src_ip": IP, "session": "exec0001", "timestamp": ts}, **kw))
        rows = [app.p_cowrie(line(eventid="cowrie.session.connect", protocol="ssh", dst_port=2225)),
                app.p_cowrie(line(eventid="cowrie.session.hp-exec", path="/tmp/.x", args="<b>1.2.3.4</b>", shasum=sha)),
                app.p_cowrie(line(eventid="cowrie.session.hp-exec", path="/tmp/.y", args="", shasum="not-a-hash"))]
        self.assertIsNone(rows[2])
        self.assertEqual((rows[1][3], rows[1][5], rows[1][6]), ("exec_sim", "/tmp/.x <b>1.2.3.4</b>", sha))
        app.store(self.con, [(hashlib.sha1(repr(r).encode()).hexdigest(),) + r for r in rows[:2]])
        page = app.v_ip(IP)
        self.assertIn("(simulated, nothing ran)", page)
        self.assertIn("/campaign/file/" + sha, page)
        self.assertNotIn("<b>1.2.3.4</b>", page)
        self.assertEqual(app.board_text("exec_sim", "/tmp/.x 1.2.3.4", sha), "ran an uploaded program (simulated): /tmp/.x 1.2.3.4")
        with self.con:
            app.set_meta(self.con, "ntfy_last", time.time() - 7200)
        with mock.patch.object(app, "NTFY_URL", "http://ntfy.invalid/x"), mock.patch.object(app, "ntfy_post") as post:
            app.notify(self.con)
        self.assertIn("Uploaded programs run (simulated) by 1 IP(s)", post.call_args[0][0])

    def test_health_sync_and_quiet_source(self):
        now = time.time()
        sent = []
        post = lambda body, title, prio=3: sent.append((title, body, prio))
        with self.con:
            app.set_meta(self.con, "last_success", repr(now - 3600))
            app.set_meta(self.con, "last_error", "export failed (rc=255): Connection refused")
        with mock.patch.object(app, "NTFY_URL", "http://ntfy.invalid/x"), mock.patch.object(app, "ntfy_post", post):
            issues = app.health_check(self.con, now)
            self.assertEqual(list(issues), ["sync"])
            self.assertIn("No data from the honeypot for 1h", issues["sync"])
            app.health_check(self.con, now + 60)                          # still broken: no second alert
            self.assertEqual(len(sent), 1)
            with self.con:
                app.set_meta(self.con, "last_success", repr(now))
            app.health_check(self.con, now + 120)
            self.assertEqual(sent[-1][0], "Huginn: collection is back")
            self.assertIn("Honeypot sync", sent[-1][1])
            # A source silent for longer than its own limit (limits are cached per day; set them directly here).
            app.store(self.con, [(hashlib.sha1(b"t1").hexdigest(), now - 5 * 3600, IP, "traps", "canary", None, "smtp", "")])
            with self.con:
                app.set_meta(self.con, "health_limits", json.dumps({"day": time.strftime("%Y-%m-%d", time.gmtime()), "lim": {"traps": 7200}}))
            issues = app.health_check(self.con, now + 180)
            self.assertEqual(list(issues), ["traps"])
            self.assertIn("hp-traps quiet for 5h", issues["traps"])
        self.assertIn("hp-traps quiet for", app.health_note(self.con))
        self.assertEqual(sent[-1][0], "Huginn: collection problem")

    def test_limits_from_last_week(self):
        now = time.time()
        rows = [(hashlib.sha1(("e%d" % i).encode()).hexdigest(), now - 86400 + i * 600 + (36000 if i >= 15 else 0), IP, "endlessh", "tarpit", None, "5", "22")
                for i in range(30)]
        app.store(self.con, rows)
        lim = app.health_limits(self.con)
        self.assertAlmostEqual(lim["endlessh"], 2.5 * (36000 + 600), delta=1)   # 2.5 x the longest silence
        self.assertNotIn("traps", lim)                                           # too little data for a limit


if __name__ == "__main__":
    unittest.main()
