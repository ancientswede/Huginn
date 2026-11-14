# 0.40 Optional goodbye note: a real login that types exit/logout gets a short note (off unless /etc/huginn-goodbye exists).
import hashlib, json, os, shutil, tempfile, time, unittest
from unittest import mock

from tests.helpers import app, ROOT

import importlib.machinery, importlib.util

_spec = importlib.util.spec_from_loader("hp_patches_040", importlib.machinery.SourceFileLoader("hp_patches_040", os.path.join(ROOT, "honeypot", "patches.py")))
patches = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(patches)

IP = "198.51.100.140"


class Note(unittest.TestCase):
    def setUp(self):
        self.ns = {}
        exec(patches.GOODBYE_HELPER, self.ns)
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir)
        self.flag = os.path.join(self.dir, "goodbye")
        self.ns["HP_GOODBYE_FLAG"] = self.flag
        self.sent, self.out = [], []

    def cmd(self, interactive=True, top=True, history=4, login_ago=252):
        sent, out = self.sent, self.out
        shell = type("Sh", (), {"interactive": interactive})()
        other = type("Sh", (), {"interactive": True})()
        proto = type("P", (), {})()
        proto.cmdstack = [shell] if top else [other, shell]
        proto.logintime = time.time() - login_ago
        proto.historyLines = [b"x"] * history
        proto.realClientIP = "203.0.113.7"
        proto.events = type("E", (), {"dispatch": lambda self, eid, fmt, **kw: sent.append(dict(kw, eventid=eid))})()
        c = type("C", (), {"protocol": proto, "write": lambda self, s: out.append(s)})()
        return c, shell

    def test_off_without_flag(self):
        self.ns["hp_goodbye"](*self.cmd())
        self.assertEqual((self.out, self.sent), ([], []))

    def test_on_for_real_logout(self):
        open(self.flag, "w").close()
        self.ns["hp_goodbye"](*self.cmd())
        text = "".join(self.out)
        self.assertIn("Thanks for the 4 min 12 s, 203.0.113.7.", text)
        self.assertIn("You typed 3 lines. All of it is logged, along with your address.", text)   # the exit line is not counted
        self.assertTrue(any(x in text for x in self.ns["HP_GOODBYE_LAST"]))
        self.assertEqual(self.sent[0]["eventid"], "cowrie.session.hp-goodbye")
        self.assertEqual(self.sent[0]["commands"], 3)

    def test_never_for_scripts_or_nested_shells(self):
        open(self.flag, "w").close()
        self.ns["hp_goodbye"](*self.cmd(interactive=False))     # sh -c / exec / scripts
        self.ns["hp_goodbye"](*self.cmd(top=False))             # exit from a nested shell: the session goes on
        self.assertEqual((self.out, self.sent), ([], []))

    def test_never_breaks_exit(self):
        open(self.flag, "w").close()
        c, shell = self.cmd()
        c.protocol.events = None                                # dispatch fails: exit must still work
        self.ns["hp_goodbye"](c, shell)
        bad = type("C", (), {})()                               # no protocol at all
        self.ns["hp_goodbye"](bad, shell)

    def test_counts_lines_from_nested_shells(self):
        open(self.flag, "w").close()
        c, shell = self.cmd(history=2)          # top-shell history only saw 2 lines ...
        c.protocol.hp_lines = 5                 # ... but 5 were typed (sh, echo, exit, echo, exit)
        self.ns["hp_goodbye"](c, shell)
        self.assertIn("You typed 4 lines.", "".join(self.out))

    def test_times_and_one_command(self):
        t = self.ns["hp_goodbye_text"]
        self.assertIn("for the 9 s.", t(9, 1, "", "x"))
        self.assertIn("You typed 1 line.", t(9, 1, "", "x"))
        self.assertIn("for the 2 h 5 min", t(7500, 0, "", "x"))


class Anchor(unittest.TestCase):
    def test_patch_both_files_or_none(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        os.makedirs(os.path.join(d, "commands")); os.makedirs(os.path.join(d, "shell"))
        bash, proto = os.path.join(d, "commands", "bash.py"), os.path.join(d, "shell", "protocol.py")
        bash_body = "class Command_exit:\n    def call(self):\n        shell = None\n        code = 0\n" + patches.GOODBYE_OLD
        proto_body = "class P:\n" + patches.GOODBYE_COUNT_OLD + "            pass\n"
        write = lambda p, t: open(p, "w").write(t)
        read = lambda p: open(p).read()
        write(bash, bash_body); write(proto, "class P:\n    pass\n")      # protocol.py changed upstream: nothing is patched
        self.assertEqual(patches.cowrie_goodbye(d), 1)
        self.assertEqual(read(bash), bash_body)
        write(proto, proto_body)
        self.assertEqual(patches.cowrie_goodbye(d), 0)
        self.assertIn("hp_goodbye(self, shell)\n        shell.exit_shell(code)", read(bash))
        self.assertIn("Huginn goodbye count v1", read(proto))
        self.assertEqual(patches.cowrie_goodbye(d), 3)


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
            self.con.execute("DELETE FROM meta WHERE k='hp_status'")

    def test_event_parsed_and_shown(self):
        ts = time.strftime("%Y-%m-%dT%H:%M:%S.000000Z", time.gmtime(time.time() - 600))
        line = lambda **kw: json.dumps(dict({"src_ip": IP, "session": "bye00001", "timestamp": ts}, **kw))
        rows = [app.p_cowrie(line(eventid="cowrie.session.connect", protocol="ssh", dst_port=2225)),
                app.p_cowrie(line(eventid="cowrie.login.success", username="root", password="x")),
                app.p_cowrie(line(eventid="cowrie.session.hp-goodbye", secs=252, commands=3)),
                app.p_cowrie(line(eventid="cowrie.session.hp-goodbye", secs="<b>", commands=1))]
        self.assertIsNone(rows[3])
        self.assertEqual((rows[2][3], rows[2][5]), ("goodbye", "252 s, 3 lines typed"))
        app.store(self.con, [(hashlib.sha1(repr(r).encode()).hexdigest(),) + r for r in rows[:3]])
        self.assertIn("got the goodbye note on logout (252 s, 3 lines typed)", app.v_ip(IP))
        self.assertEqual(app.board_text("goodbye", "252 s, 3 lines typed", None), "logged out and got the goodbye note (252 s, 3 lines typed)")

    def test_status_option_never_alerts(self):
        items = app.parse_status(["patch:goodbye ok", "option:goodbye missing", "sandbox:cowrie ok"])
        self.assertEqual(items, {"patch:goodbye": True, "option:goodbye": False, "sandbox:cowrie": True})
        with self.con:
            app.set_meta(self.con, "hp_status", json.dumps({"at": time.time(), "items": items}))
        self.assertEqual(app.protection_missing(self.con), [])
        self.assertIn("logout note off", app.protection_note(self.con))
        items["option:goodbye"] = True
        with self.con:
            app.set_meta(self.con, "hp_status", json.dumps({"at": time.time(), "items": items}))
        self.assertIn("logout note on", app.protection_note(self.con))


if __name__ == "__main__":
    unittest.main()


class ReviewFixes(unittest.TestCase):
    # Codex review before 0.40: H1 speed, L1 grouping by shape, L2 no false "ends after".
    def test_grouped_by_shape(self):
        d = app.script_diffs([["ping 192.0.2.1", "ls", "id"], ["ping 192.0.2.2", "ls", "whoami"]])
        self.assertEqual(d, [("at", 3, "id"), ("at", 3, "whoami")])

    def test_equal_rows_are_not_ends(self):
        d = app.script_diffs([["w", "ls", "ping 192.0.2.1"], ["w", "ls", "ping 192.0.2.2"]])
        self.assertEqual(d, [None, None])
        d = app.script_diffs([["w", "ls"], ["w", "ls"], ["w", "ls", "id"]])
        self.assertEqual(d, [("ends", 2, None), ("ends", 2, None), ("at", 3, "id")])

    def test_long_alike_scripts_are_fast(self):
        words = ["alpha", "beta", "gamma", "delta", "kappa", "omega", "sigma"]
        base = ["w", "ls"] + ["echo same"] * 900
        lists = [base + [words[i % 7], "id"] + ["echo extra"] * (i // 7) for i in range(60)]   # 60 different rows
        t = time.time()
        d = app.script_diffs(lists)
        self.assertLess(time.time() - t, 1.5)
        self.assertEqual(d[0], ("ends", 904, None))             # alpha+id, and longer alpha rows go on
        self.assertEqual(d[59], ("at", 905 + 7, "echo extra"))   # the longest row parts where the others stop
        # Longer than DIFF_MAX: compared only within the first DIFF_MAX commands, never slow.
        huge = [["w", "ls"] + ["echo same"] * 20000 + [w] for w in words]
        t = time.time()
        self.assertEqual(app.script_diffs(huge), [None] * 7)
        self.assertLess(time.time() - t, 1.5)


class Counter(unittest.TestCase):
    # L3: only lines typed at a shell prompt count (not passwords, program input or blank lines).
    def setUp(self):
        src = "class HoneyPotShell:\n    pass\n\n\nclass Cmd:\n    pass\n\n\nclass P:\n" + patches.GOODBYE_COUNT_NEW + "            pass\n"
        self.ns = {}
        exec(src, self.ns)

    def press(self, p, line, top=None, password=False):
        p.cmdstack = [self.ns["HoneyPotShell"]()] if top is None else top
        p.password_input = password
        p.lineBuffer = [bytes([c]) for c in line.encode()]
        p.handle_RETURN()

    def test_counts_prompt_lines_only(self):
        p = self.ns["P"]()
        self.press(p, "uname -a")
        self.press(p, "   ")                                             # blank: not counted
        self.press(p, "secret", password=True)                          # a password prompt: not counted
        self.press(p, "hello", top=[self.ns["HoneyPotShell"](), self.ns["Cmd"]()])   # input to a running program
        self.press(p, "exit")
        self.assertEqual(p.hp_lines, 2)
