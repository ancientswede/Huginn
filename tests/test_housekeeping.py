# Disk housekeeping: the honeypot keeps a short history, Huginn keeps everything (recordings included).
import gzip, os, shutil, subprocess, tempfile, time, unittest

from tests.helpers import ROOT, app


class LogClean(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.logs = os.path.join(self.d, "cowrie", "var", "log", "cowrie")
        self.tty = os.path.join(self.d, "cowrie", "var", "lib", "cowrie", "tty")
        os.makedirs(self.logs)
        os.makedirs(self.tty)

    def tearDown(self):
        shutil.rmtree(self.d)

    def make(self, path, days_old, text="x\n"):
        with open(path, "w") as fh:
            fh.write(text)
        t = time.time() - days_old * 86400
        os.utime(path, (t, t))

    def run_clean(self, *args):
        env = dict(os.environ, COWRIE_DIRS=os.path.join(self.d, "cowrie"), HP_EXPORT_CONF="/nonexistent",
                   LOG_KEEP_DAYS="30", TTY_KEEP_DAYS="30")
        return subprocess.run(["bash", os.path.join(ROOT, "honeypot", "hp-logclean")] + list(args), env=env,
                              capture_output=True, text=True, timeout=30, check=True).stdout

    def test_compress_and_expire(self):
        j = lambda n: os.path.join(self.logs, n)
        self.make(j("cowrie.json"), 0)                  # today's live log
        self.make(j("cowrie.json.2026-11-04"), 0.5)     # yesterday: hp-export still reads it
        self.make(j("cowrie.json.2026-11-02"), 3)       # old: compressed
        self.make(j("cowrie.log.2026-11-02"), 3)
        self.make(j("cowrie.json.2026-09-01.gz"), 60)   # very old: deleted
        self.make(os.path.join(self.tty, "a" * 64), 40)
        self.make(os.path.join(self.tty, "b" * 64), 2)
        dry = self.run_clean("-n")
        self.assertIn("would: gzip", dry)
        self.assertTrue(os.path.exists(j("cowrie.json.2026-11-02")))   # dry run changes nothing
        self.run_clean()
        left = sorted(os.listdir(self.logs))
        self.assertEqual(left, ["cowrie.json", "cowrie.json.2026-11-02.gz", "cowrie.json.2026-11-04", "cowrie.log.2026-11-02.gz"])
        self.assertEqual(os.listdir(self.tty), ["b" * 64])


class Recordings(unittest.TestCase):
    def test_cached_compressed_and_prefetched_in_batches(self):
        con = app.connect()
        shas = ["%064x" % (0xabc000 + i) for i in range(3)]
        with con:
            for i, sha in enumerate(shas):
                con.execute("INSERT OR REPLACE INTO sessions(session, ip, start, end, proto, port, tty) VALUES(?,?,?,?,?,?,?)",
                            ("rec%d" % i, "198.51.100.60", time.time() - i, time.time(), "ssh", 2225, sha))
        calls = []
        import base64

        def fake(cmd, timeout, limit):
            calls.append(cmd[-1])
            asked = cmd[-1].split()[1:]
            lines = ["%s %s" % (s, base64.b64encode(b"rec-" + s.encode()).decode()) if s != shas[2] else s + " -" for s in asked]
            return 0, ("\n".join(lines) + "\n").encode(), b""          # like run_capped: bytes

        orig = app.run_capped
        app.run_capped = fake
        try:
            n = app.prefetch_tty(con)
        finally:
            app.run_capped = orig
        self.assertEqual(n, 2)
        self.assertEqual(len(calls), 1)                               # one SSH call for all of them
        self.assertTrue(os.path.exists(app.tty_path(shas[0])))
        with gzip.open(app.tty_path(shas[0]), "rb") as fh:
            self.assertEqual(fh.read(), b"rec-" + shas[0].encode())
        self.assertEqual(app.fetch_tty(shas[0]), b"rec-" + shas[0].encode())   # replay reads the cache
        self.assertIn(shas[2], app._tty_missing)                      # gone on the honeypot: not asked again today

    def test_keep_forever(self):
        orig = app.RETENTION_DAYS
        con = app.connect()
        with con:
            con.execute("INSERT OR REPLACE INTO events(h,ts,ip,src,kind,session,a,b) VALUES('ancient',1000,'198.51.100.61','cowrie','cmd',NULL,'id',NULL)")
        try:
            app.RETENTION_DAYS = 0
            app.retention(con)
            self.assertTrue(con.execute("SELECT 1 FROM events WHERE h='ancient'").fetchone())
            app.RETENTION_DAYS = 180
            app.retention(con)
            self.assertFalse(con.execute("SELECT 1 FROM events WHERE h='ancient'").fetchone())
        finally:
            app.RETENTION_DAYS = orig


if __name__ == "__main__":
    unittest.main()
