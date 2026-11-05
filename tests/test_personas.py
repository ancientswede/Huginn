# Ready-made personas: realistic, consistent, unique per install, with the bait really planted.
import configparser, json, os, pickle, shutil, tempfile, unittest

from tests.helpers import app

import personas  # noqa: E402  (honeypot/ is on sys.path)


def tiny_fs():
    # The smallest Cowrie-like filesystem pickle: / with etc/passwd and Cowrie's example user /home/phil.
    f = lambda name, data: [name, personas.T_FILE, 0, 0, len(data), 0o100644, 0, data, None, None]
    d = lambda name, kids: [name, personas.T_DIR, 0, 0, 4096, 0o40755, 0, kids, None, None]
    return d("", [d("etc", [f("passwd", b"root:x:0:0::/root:/bin/bash\nphil:x:1000:1000::/home/phil:/bin/bash\n")]),
                  d("home", [d("phil", [])]), d("root", [])])


def node(fs, path):
    n = fs
    for part in path.strip("/").split("/"):
        n = next(c for c in n[personas.A_CONTENTS] if c[personas.A_NAME] == part)
    return n


class Personas(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.d)

    def make(self, name, sub="p"):
        out = os.path.join(self.d, sub)
        return out, personas.make(name, out)

    def test_bait_is_planted_and_detected(self):
        for name in personas.MAKERS:
            out, info = self.make(name, name)
            text = ""
            for root, _d, files in os.walk(os.path.join(out, "honeyfs")):
                for fn in files:
                    with open(os.path.join(root, fn)) as fh:
                        text += fh.read()
            values = app.bait_values(info["bait"])
            self.assertEqual(len(values), len(info["bait"]), name)          # all values long enough to be watched
            for k, v in info["bait"].items():
                self.assertIn(v, text, "%s: %s is not planted" % (name, k))
            # Every bait file is one Huginn recognises as "reading the bait".
            for root, _d, files in os.walk(os.path.join(out, "honeyfs")):
                for fn in files:
                    p = os.path.join(root, fn)
                    with open(p) as fh:
                        if any(v in fh.read() for v in info["bait"].values()):
                            self.assertRegex("cat /" + os.path.relpath(p, os.path.join(out, "honeyfs")), app.BAIT_FILES_RE, p)

    def test_unique_per_install(self):
        _, a = self.make("server", "a")
        _, b = self.make("server", "b")
        self.assertFalse(set(a["bait"].values()) & set(b["bait"].values()))

    def test_secrets_are_private(self):
        out, _ = self.make("server")
        self.assertEqual(os.stat(os.path.join(out, "honeyfs", "root", ".my.cnf")).st_mode & 0o777, 0o600)
        self.assertEqual(os.stat(os.path.join(out, "honeyfs", "etc", "shadow")).st_mode & 0o777, 0o600)
        self.assertEqual(os.stat(os.path.join(out, "persona.json")).st_mode & 0o777, 0o600)

    def test_consistent_hardware(self):
        out, info = self.make("server")
        with open(os.path.join(out, "honeyfs", "proc", "cpuinfo")) as fh:
            self.assertEqual(fh.read().count("processor\t:"), info["cpus"])
        with open(os.path.join(out, "honeyfs", "etc", "hostname")) as fh:
            self.assertEqual(fh.read().strip(), info["hostname"])
        with open(os.path.join(out, "honeyfs", "etc", "passwd")) as fh:
            pw = fh.read()
        for u in info["users"]:
            self.assertIn("/home/%s:" % u, pw)

    def test_pickle(self):
        out, info = self.make("server")
        src, dst = os.path.join(self.d, "fs.pickle"), os.path.join(self.d, "fs-server.pickle")
        with open(src, "wb") as fh:
            pickle.dump(tiny_fs(), fh)
        added, replaced = personas.add_to_pickle(src, dst, os.path.join(out, "honeyfs"), info["users"])
        self.assertGreater(added, 5)
        self.assertEqual(replaced, 1)                                     # etc/passwd
        with open(dst, "rb") as fh:
            fs = pickle.load(fh)
        cnf = node(fs, "/root/.my.cnf")
        self.assertIn(info["bait"]["mysql_backup"].encode(), cnf[personas.A_CONTENTS])
        self.assertEqual(cnf[personas.A_SIZE], len(cnf[personas.A_CONTENTS]))
        homes = [c[personas.A_NAME] for c in node(fs, "/home")[personas.A_CONTENTS]]
        self.assertEqual(sorted(homes), sorted(info["users"]))             # Cowrie's "phil" is gone
        self.assertIn(b"root:x:0:0:root", node(fs, "/etc/passwd")[personas.A_CONTENTS])

    def test_cowrie_cfg(self):
        out, info = self.make("camera")
        os.makedirs(os.path.join(self.d, "cowrie", "etc"))
        personas.cowrie_cfg(out, os.path.join(self.d, "cowrie"), telnet=2323, shared="/home/cowrie/cowrie/var/lib/cowrie")
        c = configparser.ConfigParser()
        c.read(os.path.join(self.d, "cowrie", "etc", "cowrie.cfg"))
        self.assertEqual(c["honeypot"]["hostname"], info["hostname"])
        self.assertEqual(c["honeypot"]["download_path"], "/home/cowrie/cowrie/var/lib/cowrie/downloads")
        self.assertEqual(c["shell"]["arch"], "linux-arm-lsb")
        self.assertEqual(c["ssh"]["enabled"], "false")
        self.assertEqual(c["telnet"]["listen_endpoints"], "tcp:2323:interface=0.0.0.0")


class Announced(unittest.TestCase):
    # The honeypot announces personas and bait in its export; Huginn treats both as untrusted data.
    def test_meta_sections(self):
        text = "\n".join(["##PERSONAS", "2225=server", "2323=camera", "bad line; rm -rf /", "99999999=x",
                          "##BAIT", json.dumps({"a": "Long-Enough-Bait-1", "b": "short", "c": 5, "d": "x" * 500}), "##END"])
        app.parse_export(text, set())
        m = app.parse_export.meta
        self.assertEqual(m["personas"], {2225: "server", 2323: "camera"})
        self.assertEqual(m["bait"], ["Long-Enough-Bait-1"])

    def test_apply_and_env_wins(self):
        con = app.connect()
        app.parse_export("##PERSONAS\n2225=nas\n##BAIT\n" + json.dumps({"x": "Announced-Bait-Value-7"}) + "\n", set())
        app.apply_honeypot_meta(con, app.parse_export.meta)
        try:
            self.assertIn("Announced-Bait-Value-7", app.BAIT)
            self.assertIn("Test-Bait-Value-0001", app.BAIT)                 # bait.json next to app.py still counts
            self.assertEqual(app.PERSONA[2225], "server")                  # HUGINN_PERSONAS in the environment wins
        finally:
            app.set_meta(con, "hp_bait", "[]")
            app.set_meta(con, "hp_personas", "{}")
            app.load_honeypot_meta(con)

    def test_no_sections_keeps_old(self):
        con = app.connect()
        app.set_meta(con, "hp_bait", json.dumps(["Kept-Bait-Value-123"]))
        app.parse_export("##COWRIE\n##END\n", set())
        app.apply_honeypot_meta(con, app.parse_export.meta)
        try:
            self.assertIn("Kept-Bait-Value-123", app.BAIT)
        finally:
            app.set_meta(con, "hp_bait", "[]")
            app.load_honeypot_meta(con)


if __name__ == "__main__":
    unittest.main()
