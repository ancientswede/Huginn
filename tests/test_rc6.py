# rc6: the fixes from the rc2 review that were left for later (M17, M18, M19, M21, M22, M24, M26) and the country
# fallback from the netblock lookup. Each test fails against 1.0.0-rc5.
import os, sqlite3, subprocess, sys, tempfile, time, unittest
from unittest import mock

from tests.helpers import ROOT, app


class RestorePlainCopy(unittest.TestCase):
    # M18: update-huginn.sh kept plain SQLite copies; restore-db only read gzip. Both work now.
    def test_plain_sqlite_copy_restores(self):
        with tempfile.TemporaryDirectory() as d:
            db, plain = os.path.join(d, "huginn.db"), os.path.join(d, "copy.db")
            for p, mark in ((db, "current"), (plain, "copy")):
                c = sqlite3.connect(p)
                c.executescript(app.SCHEMA)
                c.execute("INSERT INTO meta(k,v) VALUES('mark',?)", (mark,))
                c.commit()
                c.close()
            with mock.patch.object(app, "DB_PATH", db), mock.patch.object(app, "DATA", d), \
                    mock.patch.object(app, "need_service_user"), mock.patch("builtins.print"):
                app.restore_db(plain)
            c = sqlite3.connect(db)
            self.assertEqual(c.execute("SELECT v FROM meta WHERE k='mark'").fetchone()[0], "copy")
            c.close()


class UpdateScript(unittest.TestCase):
    def setUp(self):
        self.s = open(os.path.join(ROOT, "update-huginn.sh")).read()

    def test_failed_update_puts_the_database_back(self):            # M18
        tail = self.s[self.s.index("did not come up — rolling back"):]
        self.assertIn('restore_db "$B"', tail.split("die ")[0])
        self.assertIn('gzip -1 > "$B/huginn.db.gz"', self.s)
        self.assertIn("--with-db", self.s)

    def test_database_path_follows_huginn_base(self):               # M18
        self.assertIn('DB="$BASE/data/huginn.db"', self.s)
        self.assertNotIn('"$DIR/data/huginn.db"', self.s)

    def test_probe_uses_the_bind_address(self):                     # M19
        snippet = self.s[self.s.index("running_version() {"):]
        snippet = snippet[snippet.index("<<'PY'\n") + 7:snippet.index("\nPY\n")]
        import socket, threading
        from http.server import BaseHTTPRequestHandler, HTTPServer

        class H(BaseHTTPRequestHandler):
            def do_GET(self):
                body = b'{"ok": true, "version": "9.9.9"}' if self.headers.get("Host", "").startswith("localhost:") else b'{"ok": true}'
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass
        srv = HTTPServer(("127.0.0.2", 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            got = subprocess.run([sys.executable, "-c", snippet, str(srv.server_address[1]), "127.0.0.2"],
                                 capture_output=True, text=True, timeout=30).stdout.strip()
            self.assertEqual(got, "9.9.9")
        finally:
            srv.shutdown()
            srv.server_close()


class Metrics(unittest.TestCase):
    def test_service_labels_from_a_fixed_list(self):                # M24
        self.assertEqual(app.metric_svc("canary", "vnc"), "vnc")
        self.assertEqual(app.metric_svc("traps", "socks5"), "socks5")
        self.assertEqual(app.metric_svc("traps", "internalhost7"), "other")
        self.assertEqual(app.metric_svc("cowrie", "ssh"), "")


class CountryFallback(unittest.TestCase):
    def setUp(self):
        self.con = app.connect()
        for ip in ("198.51.100.61", "198.51.100.62", "198.51.100.63"):
            self.con.execute("INSERT OR REPLACE INTO ips(ip, first, last, score, tags) VALUES(?,?,?,1,'')", (ip, time.time(), time.time()))
            self.con.execute("DELETE FROM enrich WHERE ip=?", (ip,))
            self.con.execute("DELETE FROM netblock WHERE ip=?", (ip,))
        self.con.execute("INSERT INTO enrich(ip, fetched, ok, cc) VALUES('198.51.100.62', ?, 0, NULL)", (time.time(),))
        self.con.execute("INSERT INTO enrich(ip, fetched, ok, cc) VALUES('198.51.100.63', ?, 1, 'DE')", (time.time(),))
        self.con.commit()

    def test_netblock_country_fills_a_missing_one(self):
        parsed = {"prefix": "198.51.100.0/24", "asn": "64500", "cc": "SE", "registry": "ripencc", "allocated": "2020-01-01"}
        with mock.patch.object(app, "nb_parse", return_value=parsed), mock.patch.object(app, "dns_ask", return_value=[]), \
                mock.patch.object(app, "sendable_ip", return_value=True), mock.patch.object(app, "nb_server", return_value=("127.0.0.1", 53)), \
                mock.patch.object(app, "day_budget", return_value=(100, 0, 0)), mock.patch.object(app, "day_spend"), \
                mock.patch.object(app.time, "sleep"):
            app.nb_lookup(self.con, limit=100)
        cc = dict(self.con.execute("SELECT ip, cc FROM enrich WHERE ip LIKE '198.51.100.6_'").fetchall())
        self.assertEqual(cc["198.51.100.61"], "SE")     # no enrich row yet: one with the registry country, ipwho.is still asked
        self.assertEqual(cc["198.51.100.62"], "SE")     # ipwho.is gave none
        self.assertEqual(cc["198.51.100.63"], "DE")     # ipwho.is answered: kept
        self.assertEqual(self.con.execute("SELECT fetched FROM enrich WHERE ip='198.51.100.61'").fetchone()[0], 0)


class HoneypotTools(unittest.TestCase):
    def run_tool(self, name, *args, env=None):
        return subprocess.run([sys.executable, os.path.join(ROOT, "honeypot", name)] + list(args), capture_output=True,
                              text=True, timeout=60, env=dict(os.environ, **(env or {})))

    def test_same_name_new_file_gets_its_own_sha(self):             # M17
        import hashlib, json
        with tempfile.TemporaryDirectory() as d:
            dl, env = os.path.join(d, "dl"), {"HP_DOWNLOAD_DIRS": os.path.join(d, "dl"), "HP_FILEINFO_CACHE": os.path.join(d, "c.json")}
            os.mkdir(dl)
            p = os.path.join(dl, "tmp_abcdef")
            for body in (b"aaaaaa", b"bbbbbb"):
                st = os.stat(p) if os.path.exists(p) else None
                open(p, "wb").write(body)
                if st:
                    os.utime(p, ns=(st.st_atime_ns, st.st_mtime_ns - st.st_mtime_ns % 1_000_000_000 + 5))   # same second
                out = [json.loads(x) for x in self.run_tool("hp-fileinfo", env=env).stdout.splitlines()]
                self.assertEqual(out[0]["sha"], hashlib.sha256(body).hexdigest())
                self.assertNotIn("ident", out[0])

    def test_log_reader_takes_exactly_the_newest_lines(self):       # M21
        with tempfile.TemporaryDirectory() as d:
            old = os.path.join(d, "l.log.1")
            open(old, "w").write("".join("OLD %d\n" % i for i in range(50)))
            os.utime(old, (1, 1))
            open(os.path.join(d, "l.log"), "w").write("".join("NEW %04d %s\n" % (i, "x" * 1014) for i in range(1100)))
            out = self.run_tool("hp-readlogs", os.path.join(d, "l.log*"), "1024", "0").stdout.splitlines()
            self.assertEqual(len(out), 1024)
            self.assertFalse([x for x in out if x.startswith("OLD")])
            self.assertTrue(out[0].startswith("NEW 0076"))


class Docs(unittest.TestCase):
    def test_ipset_is_never_piped(self):                            # M26
        doc = open(os.path.join(ROOT, "docs", "blocklists.md")).read()
        self.assertNotIn("| ipset restore", doc)
        self.assertIn("ipset restore -exist < /tmp/huginn.ipset", doc)
        self.assertNotIn("curl -fsS URL | ipset", "".join(x[2] for x in app.FEEDS))


if __name__ == "__main__":
    unittest.main()


class UploadPatchUpstream(unittest.TestCase):
    # Cowrie took the per-connection file system and scp -t TARGET in on 2026-11-25/26: the upload patch must then
    # skip those parts, still add the name check and the fs/filetransfer fixes, and stay whole on older Cowrie.
    def make(self, d, upstream):
        import patches
        files = {}
        for rel, pairs in patches.UPLOAD.items():
            body = "".join(old for old, _new in pairs)
            if upstream and rel in patches.UPLOAD_UPSTREAM:
                sign, rest = patches.UPLOAD_UPSTREAM[rel]
                body = sign + "\n" + "".join(old for old, _new in rest)
            files[rel] = body          # just the anchors: compile() is mocked below
        for rel, body in files.items():
            p = os.path.join(d, rel)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            open(p, "w").write(body)

    def test_new_and_old_cowrie(self):
        import patches
        for upstream in (False, True):
            with tempfile.TemporaryDirectory() as d:
                self.make(d, upstream)
                with mock.patch.object(patches, "compile", create=True), mock.patch("builtins.compile"):
                    self.assertEqual(patches.cowrie_upload(d), 0, upstream)
                    self.assertEqual(patches.cowrie_upload(d), 3, upstream)
                server = open(os.path.join(d, "shell/server.py")).read()
                self.assertEqual("Huginn upload v1" in server, not upstream)
                scp = open(os.path.join(d, "commands/scp.py")).read()
                self.assertIn("unexpected filename", scp)
                self.assertEqual("hp_target" in scp, not upstream)
                self.assertIn("Huginn upload v1", open(os.path.join(d, "shell/fs.py")).read())

    def test_status_looks_where_every_cowrie_is_patched(self):
        self.assertIn('mark upload "$src/shell/fs.py"', open(os.path.join(ROOT, "honeypot", "hp-export")).read())
