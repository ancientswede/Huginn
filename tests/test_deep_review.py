# Regression tests for the 0.16.2 deep review: feeds, C2 list, sync robustness, HTTP limits and root-safe scripts.
import gzip, json, os, re, shutil, socket, struct, subprocess, sys, tempfile, threading, time, unittest
from datetime import datetime, timezone
from unittest import mock

from tests.helpers import ROOT, app

NOW = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def cowrie(**kw):
    ev = {"eventid": "cowrie.login.failed", "src_ip": "198.51.100.120", "timestamp": NOW, "session": "dr1", "username": "u", "password": "p"}
    ev.update(kw)
    return json.dumps(ev)


def parse(*lines):
    return app.parse_export("##COWRIE\n" + "\n".join(lines) + "\n##END\n", set())[0]


class Scope(unittest.TestCase):
    EVIL = "2a00:1450::1%x }; }\nflush ruleset\nMARKER"

    def test_refused_on_the_way_in(self):
        self.assertIsNone(app.norm_ip(self.EVIL))
        self.assertIsNone(app.norm_ip("2a00:1450::1%eth0"))
        self.assertEqual(app.norm_ip("2a00:1450::1"), "2a00:1450::1")
        self.assertEqual(parse(cowrie(src_ip=self.EVIL)), [])

    def test_old_rows_never_reach_a_feed(self):
        con = app.connect()
        with con:
            con.execute("INSERT INTO ips(ip,first,last,sessions,logins_ok,logins_fail,cmds,files,tcpip,exploits,canary,canary_svcs,tarpit_s,protos,score,tags) "
                        "VALUES(?,?,?,1,0,1,0,0,0,0,0,'',0,'ssh',50,'')", (self.EVIL, time.time(), time.time()))
        try:
            ips = app.blocklist_ips(con, 3, 30, False, True)
            self.assertFalse([i for i in ips if "%" in i])
            for fmt in ("txt", "nft", "ipset", "mikrotik", "csv"):
                self.assertNotIn("flush ruleset", app.render_feed(fmt, ips)[0])
        finally:
            with con:
                con.execute("DELETE FROM ips WHERE ip=?", (self.EVIL,))


class C2(unittest.TestCase):
    def setUp(self):
        self.con = app.connect()
        self.sha = "c2" * 32

    def tearDown(self):
        with self.con:
            self.con.execute("DELETE FROM files WHERE sha=?", (self.sha,))
            self.con.execute("DELETE FROM events WHERE h LIKE 'c2t|%'")

    def add(self, kind, ip, url, sha=None):
        ts = time.time() - 60
        app.store(self.con, [("c2t|%s|%s|%s" % (kind, ip, url), ts, ip, "cowrie", kind, None, url, sha)])

    def test_bad_url_in_a_file_breaks_nothing(self):
        app.store_files(self.con, [{"sha": self.sha, "size": 1, "type": "data", "iocs": ["http://[abcd/evil", "http://[::1/x"]}])
        app.c2_list(self.con)
        app.render_feed("c2", [])

    def test_failed_download_never_counts(self):
        self.add("file_fail", "198.51.100.121", "http://8.26.56.26/x")
        self.add("file_fail", "198.51.100.122", "http://8.26.56.26/x")
        self.assertNotIn("8.26.56.26", app.c2_list(self.con))

    def test_needs_two_attackers(self):
        self.add("file", "198.51.100.121", "http://8.20.247.20/x", "ab" * 32)
        self.assertNotIn("8.20.247.20", app.c2_list(self.con))
        self.add("file", "198.51.100.122", "http://8.20.247.20/x", "ab" * 32)
        self.assertIn("8.20.247.20", app.c2_list(self.con))
        with mock.patch.object(app, "C2_EXCLUDE", {"8.20.247.20"}):
            self.assertNotIn("8.20.247.20", app.c2_list(self.con))

    def test_embedded_address_needs_two_attackers(self):
        app.store_files(self.con, [{"sha": self.sha, "size": 1, "type": "data", "iocs": ["9.9.8.8", "http://9.9.8.9:80/a"]}])
        self.add("file", "198.51.100.121", "/tmp/x", self.sha)
        self.assertNotIn("9.9.8.8", app.c2_list(self.con))
        self.add("file", "198.51.100.122", "/tmp/y", self.sha)
        c2 = app.c2_list(self.con)
        self.assertIn("9.9.8.8", c2)
        self.assertIn("9.9.8.9", c2)


class Robust(unittest.TestCase):
    def test_tty_frames_broken_lengths(self):
        hs = struct.calcsize("<iLiiLL")
        done = []
        t = threading.Thread(target=lambda: done.append(app.tty_frames(struct.pack("<iLiiLL", 3, 0, -hs, 2, 1, 0))), daemon=True)
        t.start()
        t.join(3)
        self.assertEqual(done, [[]], "tty_frames hangs on a negative length")
        self.assertEqual(app.tty_frames(struct.pack("<iLiiLL", 3, 0, 1000, 2, 1, 0) + b"short"), [])
        good = struct.pack("<iLiiLL", 3, 0, 2, 2, 5, 0) + b"hi"
        self.assertEqual(app.tty_frames(good)[0][1], "hi")

    def test_bad_file_records_do_not_stop_the_good_one(self):
        con = app.connect()
        good = "fa" * 32
        bad = [{"sha": "f%d" % i * 32, "size": s, "mtime": m} for i, (s, m) in enumerate(((2 ** 100, 1), (-1, 1), (1, float("inf")), (1, float("nan")), (1, 1e300)))]
        app.store_files(con, bad + [{"sha": good, "size": 5, "mtime": 7}])
        self.assertIsNotNone(con.execute("SELECT 1 FROM files WHERE sha=?", (good,)).fetchone())
        self.assertIsNone(con.execute("SELECT 1 FROM files WHERE sha=?", ("f0" * 32,)).fetchone())
        self.assertIn("<h1>Files</h1>", app.v_files())

    def test_odd_port_stops_nothing(self):
        con = app.connect()
        for i, port in enumerate(("²", "9" * 5000, "٣")):
            app.store(con, [("p|%d" % i, time.time() - 60, "198.51.100.123", "cowrie", "connect", "dr-port-%d" % i, "ssh", port)])
            self.assertIsNone(con.execute("SELECT port FROM sessions WHERE session=?", ("dr-port-%d" % i,)).fetchone()[0])

    def test_one_bad_recompute_does_not_stop_the_rest(self):
        con = app.connect()
        real = app.recompute_session
        def flaky(c, sid):
            if sid == "dr-bad":
                raise ValueError("boom")
            return real(c, sid)
        ts = time.time() - 60
        with mock.patch.object(app, "recompute_session", flaky):
            app.store(con, [("b|1", ts, "198.51.100.124", "cowrie", "login_fail", "dr-bad", "u", "p"),
                            ("b|2", ts, "198.51.100.124", "cowrie", "login_fail", "dr-good", "u", "p")])
        self.assertIsNotNone(con.execute("SELECT 1 FROM sessions WHERE session='dr-good'").fetchone())

    def test_store_is_one_transaction(self):
        con = app.connect()
        with mock.patch.object(app, "recompute_ip", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                app.store(con, [("t|1", time.time() - 60, "198.51.100.125", "cowrie", "login_fail", "dr-tx", "u", "p")])
        self.assertIsNone(con.execute("SELECT 1 FROM events WHERE h='t|1'").fetchone())

    def test_run_capped_with_much_stderr(self):
        t = time.time()
        rc, out, err = app.run_capped([sys.executable, "-c", "import sys;sys.stderr.write('x'*2097152);print('done')"], 20, 1000)
        self.assertEqual((rc, out.strip()), (0, b"done"))
        self.assertEqual(len(err), 65536)
        self.assertLess(time.time() - t, 15)

    def test_bait_history_is_not_cut_at_100(self):
        con = app.connect()
        old = app.get_meta(con, "hp_bait", "[]")
        try:
            app.set_meta(con, "hp_bait", json.dumps(["bait-value-%04d" % i for i in range(150)]))
            app.load_honeypot_meta(con)
            self.assertIn("bait-value-0149", app.BAIT)
        finally:
            app.set_meta(con, "hp_bait", old)
            app.load_honeypot_meta(con)

    def test_retention_counts_sessions_again(self):
        con = app.connect()
        now = time.time()
        app.store(con, [("r|1", now - 200 * 86400, "198.51.100.126", "cowrie", "login_fail", "dr-ret", "u", "p"),
                        ("r|2", now - 60, "198.51.100.126", "cowrie", "cmd", "dr-ret", "id", None)])
        with mock.patch.object(app, "RETENTION_DAYS", 180):
            app.retention(con)
        s = con.execute("SELECT logins_fail, cmds FROM sessions WHERE session='dr-ret'").fetchone()
        self.assertEqual((s[0], s[1]), (0, 1))
        self.assertEqual(con.execute("SELECT logins_fail FROM ips WHERE ip='198.51.100.126'").fetchone()[0], 0)

    def test_two_writers_of_one_recording(self):
        sha = "ad" * 32
        errors, bar = [], threading.Barrier(8)
        def write():
            bar.wait()
            try:
                app.tty_store(sha, b"data" * 1000)
            except Exception as e:
                errors.append(e)
        ts = [threading.Thread(target=write) for _ in range(8)]
        [t.start() for t in ts]
        [t.join() for t in ts]
        self.assertEqual(errors, [])
        self.assertEqual(app.tty_cached(sha), b"data" * 1000)
        self.assertFalse([f for f in os.listdir(app.TTY_DIR) if f.endswith(".tmp")])

    def test_damaged_recording_is_fetched_again(self):
        sha = "ae" * 32
        with open(app.tty_path(sha), "wb") as fh:
            fh.write(b"not gzip")
        self.assertIsNone(app.tty_cached(sha))
        with open(app.tty_path(sha), "wb") as fh:
            fh.write(gzip.compress(b"x" * 100)[:20])
        self.assertIsNone(app.tty_cached(sha))

    def test_export_warnings(self):
        app.parse_export("##COWRIE\n##WARN fileinfo\n##WARN journal\n##END\n", set())
        self.assertEqual(app.parse_export.meta["warnings"], ["fileinfo", "journal"])
        self.assertEqual(parse(cowrie(username="##WARN x")) and app.parse_export.meta["warnings"], [])

    def test_very_long_line_is_skipped(self):
        self.assertEqual(parse(cowrie(password="x" * 70000)), [])
        self.assertEqual(len(parse(cowrie(password="x" * 1024))), 1)


class HttpLimits(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        class Small(app.HuginnServer):
            max_per_ip = 2
        cls.srv = Small(("127.0.0.1", 0), app.Handler)
        cls.port = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def get(self, host="x"):
        s = socket.create_connection(("127.0.0.1", self.port))
        s.settimeout(5)
        s.sendall(b"GET /login HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n" % host.encode())
        d = b""
        try:
            while True:
                b = s.recv(65536)
                if not b:
                    break
                d += b
        except OSError:
            pass
        s.close()
        return d

    def test_one_address_cannot_take_every_slot(self):
        deadline = time.time() + 5
        while self.srv._total and time.time() < deadline:   # the last test's connection may still be giving back its slot
            time.sleep(0.02)
        held = [socket.create_connection(("127.0.0.1", self.port)) for _ in range(2)]
        try:
            time.sleep(0.2)
            self.assertEqual(self.get(), b"")
        finally:
            [s.close() for s in held]
        deadline = time.time() + 5
        while time.time() < deadline and not self.get():
            time.sleep(0.1)
        self.assertIn(b"HTTP/1.1 ", self.get())

    def test_allowed_hosts(self):
        with mock.patch.object(app, "ALLOWED_HOSTS", {"huginn.lan:8095"}):
            self.assertIn(b"421", self.get("evil.example").split(b"\r\n")[0])
            self.assertNotIn(b"421", self.get("HUGINN.lan:8095").split(b"\r\n")[0])
        self.assertNotIn(b"421", self.get("anything").split(b"\r\n")[0])


class Scripts(unittest.TestCase):
    def read(self, name):
        with open(os.path.join(ROOT, name)) as fh:
            return fh.read()

    def test_hp_export_never_chowns(self):
        self.assertNotIn("chown", self.read("honeypot/hp-export"))

    def test_tty_is_read_as_the_cowrie_user(self):
        s = self.read("honeypot/hp-export")
        branch = s[s.index("tty\\ *)"):s.index("*) ;;  # any other")]
        self.assertIn("setpriv --reuid", branch)

    def test_root_never_patches_or_unpickles_in_their_folders(self):
        for name in ("install-honeypot.sh", "update-honeypot.sh"):
            s = self.read(name)
            self.assertNotIn('python3 "$HERE/honeypot/patches.py"', s, name)
            self.assertNotIn("$PY_P fs", s, name)
            self.assertNotIn("$PY_P cfg", s, name)
            self.assertNotIn("$PY_P txtcmds", s, name)
            self.assertNotIn("$PATCH", s, name)
            self.assertIn("setup-sandbox.sh", s, name)
        self.assertNotIn("chown", self.read("update-huginn.sh").replace('chown "$OWNER" "$T"', ""))

    def catfiles(self):
        s = self.read("honeypot/hp-export")
        return s[s.index("catfiles() {"):s.index("\n}\n", s.index("catfiles() {")) + 3]

    def test_catfiles_names_cannot_point_elsewhere(self):
        d = tempfile.mkdtemp()
        try:
            with open(os.path.join(d, "secret"), "w") as fh:
                fh.write("TOP-SECRET\n")
            with open(os.path.join(d, "log.json"), "w") as fh:
                fh.write("REAL\n")
            os.symlink(d, os.path.join(d, "log.json.dir"))            # a folder that matches the pattern
            os.mkdir(os.path.join(d, "log.json.x\nsecret"))           # a name with a line break
            with open(os.path.join(d, "log.json.y\nsecret"), "w") as fh:
                fh.write("ODD\n")
            out = subprocess.run(["bash", "-c", self.catfiles() + '\ncd "%s"\ncatfiles "%s/log.json*"' % (d, d)],
                                 capture_output=True, text=True, timeout=20).stdout
            self.assertIn("REAL", out)
            self.assertNotIn("TOP-SECRET", out)
        finally:
            shutil.rmtree(d)

    def test_keep_drops_long_lines(self):
        s = self.read("honeypot/hp-export")
        keep = re.search(r"^keep\(\) \{.*\}$", s, re.M).group(0)
        text = "short\n" + "x" * 20000 + "\nend\n"
        out = subprocess.run(["bash", "-c", keep + "\nkeep"], input=text, capture_output=True, text=True, timeout=20).stdout
        self.assertEqual(out, "short\nend\n")


if __name__ == "__main__":
    unittest.main()
