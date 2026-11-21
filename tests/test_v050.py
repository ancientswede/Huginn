# 0.50.0 round 2 of the Codex review of 0.25-0.49: honeypot reads as the service user (H1), logs read from the end (M20),
# one bad export field cannot stop a batch (M19), caches that survive a sync (M13), and script-level checks for the IDS
# switch (M9), Suricata config staging (M17), restore (M15), upgrades (M16) and the key helper (L6).
import json, os, shutil, sqlite3, subprocess, tempfile, time, unittest
from unittest.mock import patch

from tests.helpers import ROOT, app
from tests.test_v0491 import IP, Mem, event

READLOGS = os.path.join(ROOT, "honeypot", "hp-readlogs")


def readlogs(pattern, lines=0, budget=0, user=None):
    return subprocess.run(["python3", "-I", READLOGS, pattern, str(lines), str(budget)],
                          capture_output=True, text=True, timeout=20)


def src(name):
    with open(os.path.join(ROOT, name)) as fh:
        return fh.read()


class ReadLogs(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="hprl-")
        self.addCleanup(shutil.rmtree, self.d, True)

    def write(self, name, lines, age):
        p = os.path.join(self.d, name)
        with open(p, "w") as fh:
            fh.write("".join("%s\n" % x for x in lines))
        t = time.time() - age
        os.utime(p, (t, t))

    def test_newest_lines_oldest_first(self):
        self.write("log.2", range(1, 101), 300)
        self.write("log.1", range(101, 201), 200)
        self.write("log", range(201, 211), 100)
        self.write("log.3.gz", ["never"], 50)
        out = readlogs(self.d + "/log*", 15).stdout.split()
        self.assertEqual(out, [str(x) for x in range(196, 211)])
        self.assertEqual(len(readlogs(self.d + "/log*", 0).stdout.split()), 210)

    def test_byte_budget_stops_early(self):
        self.write("big", ["x" * 99] * 5000, 10)              # 500 KB
        out = readlogs(self.d + "/big", 0, 10000).stdout.split()
        self.assertLessEqual(len(out), 101)
        self.assertGreater(len(out), 90)

    def test_hard_link_and_symlink_skipped(self):
        secret = os.path.join(self.d, "secret")
        with open(secret, "w") as fh:
            fh.write("TOP-SECRET\n")
        os.symlink(secret, os.path.join(self.d, "log.9"))
        self.write("log", ["REAL"], 10)
        out = readlogs(self.d + "/log*").stdout
        self.assertIn("REAL", out)
        self.assertNotIn("TOP-SECRET", out)

    @unittest.skipUnless(os.geteuid() == 0, "needs root to drop to another user")
    def test_drops_to_owner_and_refuses_redirect(self):
        svc = os.path.join(self.d, "svc")
        os.makedirs(os.path.join(svc, "logs"))
        with open(os.path.join(svc, "logs", "a.log"), "w") as fh:
            fh.write("svc-line\n")
        os.chmod(self.d, 0o755)
        root_dir = tempfile.mkdtemp(prefix="hprl-root-")
        self.addCleanup(shutil.rmtree, root_dir, True)
        with open(os.path.join(root_dir, "x.log"), "w") as fh:
            fh.write("ROOT-ONLY\n")
        os.symlink(root_dir, os.path.join(svc, "evil"))
        for p in (svc, os.path.join(svc, "logs"), os.path.join(svc, "logs", "a.log")):
            os.chown(p, 65534, 65534)
        os.lchown(os.path.join(svc, "evil"), 65534, 65534)
        self.assertEqual(readlogs(svc + "/logs/*.log").stdout, "svc-line\n")
        r = readlogs(svc + "/evil/*.log")
        self.assertNotIn("ROOT-ONLY", r.stdout)
        self.assertIn("changed owner", r.stderr)


class Robust(Mem):
    def test_m19_lone_surrogate_does_not_stop_the_batch(self):
        bad = json.dumps({"eventid": "cowrie.login.failed", "src_ip": IP, "timestamp": "2026-11-18T10:00:00.000000Z",
                          "session": "s1", "username": "root", "password": "\ud800x"})
        good = json.dumps({"eventid": "cowrie.login.failed", "src_ip": IP, "timestamp": "2026-11-18T10:00:01.000000Z",
                           "session": "s1", "username": "root", "password": "fine"})
        deep = '{"x": ' + "[" * 300000 + "]" * 300000 + "}"           # deeper than the JSON decoder can go
        text = "##COWRIE\n%s\n%s\n##FILES\n%s\n##END\n" % (bad, good, deep)
        rows, _h = app.parse_export(text, set())
        with patch.object(app, "RETENTION_DAYS", 0):
            n = app.store(self.con, rows)
        self.assertEqual(n, 2)
        self.assertEqual(len(app.parse_export.files), 0)

    def test_m13_board_cache_survives_a_sync(self):
        st = app.settings(self.con)
        calls = []
        app._board_cache.clear()
        app.set_meta(self.con, "last_ingest", "%d" % (app.BOARD_TTL * 1000 + 10))
        app.board_cached(self.con, st, ("t",), lambda: calls.append(1) or 1)
        app.set_meta(self.con, "last_ingest", "%d" % (app.BOARD_TTL * 1000 + 130))      # the next sync, same 5 minutes
        app.board_cached(self.con, st, ("t",), lambda: calls.append(1) or 1)
        self.assertEqual(len(calls), 1)
        app.set_meta(self.con, "last_ingest", "%d" % (app.BOARD_TTL * 1001 + 1))
        app.board_cached(self.con, st, ("t",), lambda: calls.append(1) or 1)
        self.assertEqual(len(calls), 2)


class Scripts(unittest.TestCase):
    def test_m9_ids_switch_locks_and_checks_all_three(self):
        s = src("honeypot/hp-export")
        self.assertEqual(s.count("flock -w 60 9"), 2)
        self.assertIn("systemctl is-active --quiet hp-suricata-rules.timer", s)
        self.assertIn("running:suricata-rules", s)

    def test_m17_new_config_is_tested_and_kept_back(self):
        s = src("honeypot/setup-suricata.sh")
        self.assertIn('suricata -T -c "$CONF.new"', s)
        self.assertIn("restore_prev", s)

    def test_m15_restore_checks_every_step(self):
        s = src("update-huginn.sh")
        self.assertIn('cmp -s "$1/app.py" "$DIR/app.py" || bad=1', s)

    def test_m16_upgrade_can_go_back(self):
        s = src("update-honeypot.sh")
        self.assertIn('git -C "$C" reset -q --hard "$BEFORE_FULL"', s)
        self.assertIn('pip" install -q "opencanary==$BEFORE"', s)

    def test_l6_key_conflict(self):
        self.assertIn("with other options (or more than once)", src("honeypot/hp-add-huginn-key"))
        # Codex rc2 M9: one file, installed by both the installer and the updater.
        for f in ("install-honeypot.sh", "update-honeypot.sh"):
            self.assertIn('install -m 755 "$HERE/honeypot/hp-add-huginn-key" /usr/local/sbin/hp-add-huginn-key', src(f), f)

    def test_purge_removes_traps_logs(self):
        self.assertIn("/var/log/private/hp-traps", src("uninstall-honeypot.sh"))

    def test_scripts_parse(self):
        for f in ("honeypot/hp-export", "honeypot/setup-suricata.sh", "update-huginn.sh", "update-honeypot.sh", "install-honeypot.sh"):
            self.assertEqual(subprocess.run(["bash", "-n", os.path.join(ROOT, f)]).returncode, 0, f)


class UpstreamFree(unittest.TestCase):
    def test_upstream_meminfo_counts_as_in_place(self):
        import importlib.machinery, importlib.util
        loader = importlib.machinery.SourceFileLoader("patches_050", os.path.join(ROOT, "honeypot", "patches.py"))
        spec = importlib.util.spec_from_loader(loader.name, loader)
        mod = importlib.util.module_from_spec(spec)
        loader.exec_module(mod)
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        f = os.path.join(d, "free.py")
        with open(f, "w") as fh:
            fh.write('meminfo = self.fs.file_contents("/proc/meminfo").decode(errors="replace")\n')
        self.assertEqual(mod.cowrie_free(f), 3)
        self.assertFalse(os.path.exists(f + ".orig"))           # nothing written
        self.assertIn('self.fs.file_contents("/proc/meminfo")', src("honeypot/hp-export"))


if __name__ == "__main__":
    unittest.main()
