# Automatic database backups: a damaged database never pushes out good copies, and a copy can be brought back.
import gzip, json, os, shutil, sqlite3, stat, subprocess, sys, tempfile, time, unittest
from unittest import mock

from tests.helpers import HOME, ROOT, app


class Backups(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(dir=HOME)
        self.dir = mock.patch.object(app, "BACKUP_DIR", self.d)
        self.dir.start()
        self.con = app.connect()
        with self.con:
            self.con.execute("DELETE FROM meta WHERE k IN ('backup_last','backup_tried','backup_error')")

    def tearDown(self):
        self.dir.stop()
        shutil.rmtree(self.d, ignore_errors=True)

    def make(self, stamp):
        p = os.path.join(self.d, "huginn-%s.db.gz" % stamp)
        with gzip.open(p, "wb") as fh:
            fh.write(b"old")
        return p

    def test_copy_is_a_private_good_database(self):
        p = app.backup_db()
        self.assertRegex(os.path.basename(p), app.BACKUP_RE)
        self.assertEqual(stat.S_IMODE(os.stat(p).st_mode), 0o600)
        out = os.path.join(self.d, "x.db")
        with gzip.open(p, "rb") as g, open(out, "wb") as fh:
            shutil.copyfileobj(g, fh)
        self.assertEqual(app.check_copy(out), "ok")
        self.assertIsNotNone(sqlite3.connect(out).execute("SELECT 1 FROM sqlite_master WHERE name='events'").fetchone())
        self.assertEqual([n for n in os.listdir(self.d) if n.startswith(".tmp-")], [])

    def test_keeps_only_the_newest(self):
        for stamp in ("20200101-000000", "20200102-000000", "20200103-000000", "20200104-000000"):
            self.make(stamp)
        other = os.path.join(self.d, "my-own-file.db.gz")
        open(other, "w").close()
        new = app.backup_db()
        names = [f[0] for f in app.backup_files()]
        self.assertEqual(len(names), 3)
        self.assertEqual(names[0], os.path.basename(new))
        self.assertEqual(names[1:], ["huginn-20200104-000000.db.gz", "huginn-20200103-000000.db.gz"])
        self.assertTrue(os.path.exists(other))

    def test_damaged_database_keeps_the_good_copies(self):
        old = [self.make(s) for s in ("20200101-000000", "20200102-000000", "20200103-000000")]
        with mock.patch.object(app, "check_copy", return_value="*** in database main ***"):
            with self.assertRaises(app.DatabaseDamaged):
                app.backup_db()
        self.assertTrue(all(os.path.exists(p) for p in old))
        self.assertEqual(len(app.backup_files()), 3)
        self.assertEqual([n for n in os.listdir(self.d) if n.startswith(".tmp-")], [])

    def test_really_damaged_file_is_found(self):
        good = app.backup_db()
        out = os.path.join(self.d, "bad.db")
        with gzip.open(good, "rb") as g, open(out, "wb") as fh:
            shutil.copyfileobj(g, fh)
        size = os.path.getsize(out)
        self.assertGreater(size, 16384)
        with open(out, "r+b") as fh:                      # overwrite everything after the first page
            fh.seek(4096)
            fh.write(b"\xff" * (size - 4096))
        try:
            result = app.check_copy(out)
        except sqlite3.DatabaseError:
            result = "error"
        self.assertNotEqual(result, "ok")

    def test_failure_is_shown_and_sent_once(self):
        with mock.patch.object(app, "backup_db", side_effect=RuntimeError("disk full")), \
                mock.patch.object(app, "NTFY_URL", "http://ntfy.invalid/x"), mock.patch.object(app, "ntfy_post") as post:
            self.assertFalse(app.backup_once(self.con))
        self.assertEqual(post.call_count, 1)
        self.assertIn("disk full", post.call_args[0][0])
        self.assertIn("disk full", app.get_meta(self.con, "backup_error"))
        self.assertIn("disk full", app.v_account(None))
        app.backup_once(self.con)
        self.assertEqual(app.get_meta(self.con, "backup_error"), "")

    def test_schedule(self):
        now = time.time()
        self.assertTrue(app.backup_due(self.con, now))
        app.set_meta(self.con, "backup_tried", now)
        self.assertFalse(app.backup_due(self.con, now + 60))              # a failure waits before the next try
        self.assertTrue(app.backup_due(self.con, now + app.BACKUP_RETRY + 1))
        app.set_meta(self.con, "backup_last", now)
        self.assertFalse(app.backup_due(self.con, now + app.BACKUP_RETRY + 1))
        self.assertTrue(app.backup_due(self.con, now + app.BACKUP_HOURS * 3600 + 1))
        with mock.patch.object(app, "BACKUP_KEEP", 0):
            self.assertFalse(app.backup_due(self.con, now + 10 ** 7))
            self.assertIn("turned off", app.backup_note(self.con))

    def test_too_little_disk(self):
        class Full:
            f_bavail, f_frsize = 1, 1
        with mock.patch.object(app.os, "statvfs", return_value=Full):
            with self.assertRaises(RuntimeError):
                app.backup_db()


class Restore(unittest.TestCase):
    # As a real command, with its own Huginn home.
    def setUp(self):
        self.home = tempfile.mkdtemp(dir=HOME)
        self.data = os.path.join(self.home, "data")
        os.makedirs(self.data)
        self.env = dict(os.environ, HUGINN_BASE=self.home, HUGINN_ENRICH="0", HUGINN_UPDATE_CHECK="0", PYTHONDONTWRITEBYTECODE="1")
        self.db = os.path.join(self.data, "huginn.db")

    def tearDown(self):
        shutil.rmtree(self.home, ignore_errors=True)

    def run_app(self, *args):
        # The check for root is tested separately, so the tests also run as root in a container.
        code = ("import os, sys, runpy; os.getuid = lambda: 1000; sys.argv = %r; runpy.run_path(%r, run_name='__main__')"
                % (["app.py"] + list(args), os.path.join(ROOT, "app.py")))
        return subprocess.run([sys.executable, "-c", code], env=self.env, capture_output=True, text=True, timeout=60)

    def mark(self, value):
        c = sqlite3.connect(self.db)
        with c:
            c.execute("INSERT OR REPLACE INTO meta(k,v) VALUES('mark',?)", (value,))
        c.close()

    def read(self):
        c = sqlite3.connect(self.db)
        try:
            return c.execute("SELECT v FROM meta WHERE k='mark'").fetchone()[0]
        finally:
            c.close()

    def test_bring_back(self):
        r = self.run_app("backup")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.mark("good")
        r = self.run_app("backup")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.mark("broken-by-update")
        time.sleep(0)
        name = sorted(os.listdir(os.path.join(self.data, "backups")))[-1]
        self.assertIn(name, self.run_app("backups").stdout)
        r = self.run_app("restore-db", name)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.read(), "good")
        kept = [n for n in os.listdir(self.data) if n.startswith("huginn.db.before-restore-") and not n.endswith(("-wal", "-shm"))]
        self.assertEqual(len(kept), 1)
        c = sqlite3.connect(os.path.join(self.data, kept[0]))
        self.assertEqual(c.execute("SELECT v FROM meta WHERE k='mark'").fetchone()[0], "broken-by-update")
        c.close()

    def test_bad_backup_changes_nothing(self):
        self.run_app("backup")
        self.mark("current")
        bd = os.path.join(self.data, "backups")
        with open(os.path.join(bd, "huginn-20200101-000000.db.gz"), "wb") as fh:
            fh.write(b"not gzip")
        with gzip.open(os.path.join(bd, "huginn-20200102-000000.db.gz"), "wb") as fh:
            fh.write(b"not a database" * 1000)
        for name in ("huginn-20200101-000000.db.gz", "huginn-20200102-000000.db.gz", "huginn-nothing.db.gz"):
            r = self.run_app("restore-db", name)
            self.assertNotEqual(r.returncode, 0, name)
            self.assertEqual(self.read(), "current")
        self.assertEqual([n for n in os.listdir(self.data) if "before-restore" in n or n.startswith(".restore")], [])

    def test_refuses_while_running(self):
        self.run_app("backup")
        name = os.listdir(os.path.join(self.data, "backups"))[0]
        import fcntl
        with open(os.path.join(self.data, ".running"), "w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            r = self.run_app("restore-db", name)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("running", r.stderr)

    def test_refuses_root(self):
        with mock.patch.object(app.os, "getuid", return_value=0):
            with self.assertRaises(SystemExit):
                app.restore_db("x")


if __name__ == "__main__":
    unittest.main()
