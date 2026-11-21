# 1.0.0-rc2: fixes from the Codex review before 1.0 (huginn-totalgranskning-rc2).
import http.server, os, tempfile, threading, time, unittest
from unittest import mock

from tests.helpers import app
from tests.test_v0491 import Mem

GONE, KEPT = "198.51.100.140", "198.51.100.141"


class RetentionForgets(Mem):
    # H3: an attacker removed by retention leaves no lookups, examples or recordings behind.
    def setUp(self):
        super().setUp()
        self.tty = tempfile.mkdtemp()
        p = mock.patch.object(app, "TTY_DIR", self.tty)
        p.start()
        self.addCleanup(p.stop)

    def test_gone_attacker_is_gone_everywhere(self):
        now, old = time.time(), time.time() - 200 * 86400
        a, b = "a1" * 32, "b2" * 32
        app.store(self.con, [("g|1", old, GONE, "cowrie", "cmd", "s-gone", "uname -a", None),
                             ("k|1", now - 60, KEPT, "cowrie", "cmd", "s-kept", "id", None)])
        with self.con:
            self.con.execute("UPDATE sessions SET tty=? WHERE session='s-gone'", (a,))
            self.con.execute("UPDATE sessions SET tty=? WHERE session='s-kept'", (b,))
            for t in ("greynoise", "httpbl"):
                self.con.executemany("INSERT INTO %s(ip, checked, data) VALUES(?,?,'{}')" % t, [(GONE, now), (KEPT, now)])
            self.con.executemany("INSERT INTO enrich(ip, fetched, ok) VALUES(?,?,1)", [(GONE, now), (KEPT, now)])
            self.con.execute("INSERT OR REPLACE INTO seen(kind, key, observed, ip, session, ex) VALUES('cmd','shape-g',?,?,?,?)",
                             (old, GONE, "s-gone", "uname -a"))
        for sha in (a, b):
            app.tty_store(sha, b"rec")
        open(os.path.join(self.tty, "notes.txt"), "w").close()        # not Huginn's: never touched
        with mock.patch.object(app, "RETENTION_DAYS", 180):
            app.retention(self.con)
        for t in ("enrich", "greynoise", "httpbl"):
            self.assertEqual([r[0] for r in self.con.execute("SELECT ip FROM %s" % t)], [KEPT], t)
        row = self.con.execute("SELECT ip, session, ex FROM seen WHERE key='shape-g'").fetchone()
        self.assertEqual(tuple(row), (None, None, None))              # still counted as a first sighting
        self.assertEqual(sorted(os.listdir(self.tty)), sorted([b + ".gz", "notes.txt"]))

    def test_keep_everything_keeps_recordings(self):
        app.tty_store("c3" * 32, b"rec")
        with mock.patch.object(app, "RETENTION_DAYS", 0):
            app.retention(self.con)
        self.assertEqual(os.listdir(self.tty), ["c3" * 32 + ".gz"])


class NtfyNoRedirect(unittest.TestCase):
    # H1: a redirect from the ntfy server must not take the token to another host.
    def test_token_does_not_follow_a_redirect(self):
        got = []

        class Other(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                got.append(self.headers.get("Authorization"))
                self.send_response(200); self.end_headers()
            do_POST = do_GET

            def log_message(self, *a):
                pass

        other = http.server.HTTPServer(("127.0.0.1", 0), Other)

        class Ntfy(Other):
            def do_POST(self):
                self.rfile.read(int(self.headers.get("Content-Length") or 0))
                self.send_response(302)
                self.send_header("Location", "http://127.0.0.1:%d/stolen" % other.server_port)
                self.end_headers()

        ntfy = http.server.HTTPServer(("127.0.0.1", 0), Ntfy)
        for s in (other, ntfy):
            threading.Thread(target=s.serve_forever, daemon=True).start()
            self.addCleanup(s.server_close)
            self.addCleanup(s.shutdown)
        with mock.patch.object(app, "NTFY_URL", "http://127.0.0.1:%d/topic" % ntfy.server_port), \
                mock.patch.object(app, "NTFY_TOKEN", "tk_secret_123"):
            with self.assertRaises(Exception):
                app.ntfy_post("hello", "test")
        self.assertEqual(got, [])


if __name__ == "__main__":
    unittest.main()
