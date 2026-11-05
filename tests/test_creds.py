# "Is my password in here?", the credential search and the word-list exports.
import hashlib, json, re, shutil, subprocess, time, unittest

from tests.helpers import app

NOW = time.time()
SECRET = "My-Own-Password-1"


def row(ip, src, kind, session=None, a=None, b=None, dt=0.0):
    ts = NOW - 7200 + dt
    return ("cr|%s|%s|%s|%s|%s|%s" % (ts, ip, kind, session, a, b), ts, ip, src, kind, session, a, b)


class Creds(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.con = app.connect()
        app.store(cls.con, [
            row("198.51.100.40", "cowrie", "connect", "c1", "ssh", "2225"),
            row("198.51.100.40", "cowrie", "login_fail", "c1", "root", SECRET, 1),
            row("198.51.100.40", "cowrie", "login_ok", "c1", "admin", SECRET, 2),
            row("198.51.100.41", "canary", "canary", None, "ftp", "backup / " + SECRET, 3),
            row("198.51.100.42", "traps", "canary", None, "postgres", "postgres / pgpass99  (db prod)", 4),
            row("198.51.100.43", "cowrie", "login_fail", "c4", "=cmd|calc", "+danger\nline", 5),
        ])

    def bucket(self, pw):
        h = hashlib.sha256(pw.encode()).hexdigest()
        return h[app.CRED_PREFIX:], app.cred_check(self.con, h[:app.CRED_PREFIX])

    def test_found_across_services(self):
        suf, d = self.bucket(SECRET)
        hit = [m for m in d["matches"] if m["s"] == suf][0]
        self.assertEqual((hit["tries"], hit["accepted"], hit["ips"]), (3, 1, 2))
        self.assertEqual(set(hit["services"]), {"ssh", "ftp"})
        self.assertEqual({u for u, _ in hit["users"]}, {"root", "admin", "backup"})

    def test_not_found_and_only_prefix_needed(self):
        suf, d = self.bucket("never-tried-by-anyone-42")
        self.assertFalse([m for m in d["matches"] if m["s"] == suf])
        self.assertGreaterEqual(d["distinct"], 3)

    def test_traps_db_suffix_stripped(self):
        suf, d = self.bucket("pgpass99")
        self.assertTrue([m for m in d["matches"] if m["s"] == suf])

    def test_cache_refreshes_on_new_data(self):
        app.cred_index(self.con)
        app.store(self.con, [row("198.51.100.44", "cowrie", "login_fail", "c5", "root", "brand-new-pw-77", 6)])
        suf, d = self.bucket("brand-new-pw-77")
        self.assertTrue([m for m in d["matches"] if m["s"] == suf])

    def test_exports(self):
        words, ctype = app.cred_export(self.con, "passwords", "all")
        self.assertEqual(ctype, "text/plain")
        lines = words.splitlines()
        self.assertEqual(lines[0], SECRET)                         # most tried first
        self.assertNotIn("+danger", words)                         # entries with line breaks are left out
        users, _ = app.cred_export(self.con, "usernames", "all")
        self.assertIn("backup", users.splitlines())
        csv, ctype = app.cred_export(self.con, "csv", "all")
        self.assertEqual(ctype, "text/csv")
        self.assertIn("'=cmd|calc", csv)                           # CSV injection is neutralised
        self.assertIn("'+danger", csv)

    def test_search(self):
        found, total = app.cred_search(self.con, "own-pass")
        self.assertEqual(total, 3)
        self.assertEqual(sum(d["n"] for _, d in found), 3)


@unittest.skipUnless(shutil.which("node"), "node is not installed")
class BrowserHash(unittest.TestCase):
    # The page hashes in the browser; its SHA-256 must agree with Python's for any input.
    def test_sha256_matches_python(self):
        m = re.search(r"function sha256\(str\)\{.*?\n(?=window\.huginnSha256)", app.JS, re.S)
        self.assertIsNotNone(m)
        samples = ["", "abc", "lösenord€✓", "a" * 55, "b" * 56, "c" * 64, "d" * 119, "x" * 1000, SECRET]
        js = m.group(0) + "\nconsole.log(JSON.stringify(%s.map(sha256)))" % json.dumps(samples)
        out = subprocess.run(["node", "-e", js], capture_output=True, text=True, timeout=20, check=True).stdout
        self.assertEqual(json.loads(out), [hashlib.sha256(x.encode()).hexdigest() for x in samples])


if __name__ == "__main__":
    unittest.main()
