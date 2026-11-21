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


def _fake_http(ipwho):
    def fake(url):
        if "ipwho.is" in url:
            return ipwho(url)
        return {"ports": [22], "tags": [], "vulns": [], "hostnames": []}
    return fake


class CountryLookup(Mem):
    # Jonas 2026-11-21: 1 813 attackers without a country. ipwho.is answered 429, Shodan answered, and the row was
    # stored as done with no country for 14 days.
    def lookup(self, ipwho):
        with mock.patch.object(app, "http_json", _fake_http(ipwho)), \
                mock.patch.object(app.socket, "gethostbyaddr", side_effect=OSError):
            return app.enrich_ip("45.10.20.150")

    def test_shodan_alone_is_not_done(self):
        def down(url):
            raise OSError("timeout")
        d, ok, _ = self.lookup(down)
        self.assertEqual(ok, 0)
        self.assertEqual(d["ports"], "22")

    def test_rate_limit_pauses(self):
        def busy(url):
            raise app.urllib.error.HTTPError(url, 429, "Too Many Requests", {}, None)
        with self.assertRaises(app.GeoBusy):
            self.lookup(busy)

    def test_rows_without_country_are_asked_again(self):
        now = time.time()
        with self.con:
            self.con.execute("INSERT INTO ips(ip,first,last,score) VALUES('45.10.20.150',?,?,1)", (now, now))
            self.con.execute("INSERT INTO enrich(ip, fetched, ok) VALUES('45.10.20.150', ?, 1)", (now - 2 * 86400,))
        asked = []

        def ipwho(url):
            asked.append(url)
            return {"success": True, "country_code": "SE", "country": "Sweden", "connection": {}}

        class Stop(Exception):
            pass
        sleeps = iter([None, None, Stop()])

        def sleep(_):
            x = next(sleeps)
            if x:
                raise x
        with mock.patch.object(app, "connect", return_value=self.con), mock.patch.object(app, "http_json", _fake_http(ipwho)), \
                mock.patch.object(app.socket, "gethostbyaddr", side_effect=OSError), mock.patch.object(app.time, "sleep", sleep), \
                mock.patch.object(app, "tor_refresh", lambda c: 0), mock.patch.object(app, "vt_lookup", lambda c: 0), \
                mock.patch.object(app, "gn_lookup", lambda c: 0), mock.patch.object(app, "hb_lookup", lambda c: 0), \
                mock.patch.object(app, "nb_lookup", lambda c: 0), mock.patch.object(app, "dbl_lookup", lambda c: 0), \
                mock.patch.object(app, "sh_lookup", lambda c: 0), mock.patch.object(app, "ab_lookup", lambda c: 0):
            with self.assertRaises(Stop):
                app.enrich_loop()
        self.assertEqual(len(asked), 1)
        self.assertEqual(self.con.execute("SELECT cc FROM enrich WHERE ip='45.10.20.150'").fetchone()[0], "SE")


class AddressFixes(unittest.TestCase):
    def test_mapped_and_multicast(self):
        # M30: every spelling of a mapped address is the IPv4 address; multicast is never an attacker.
        for x in ("::ffff:45.10.20.1", "::ffff:2d0a:1401", "0:0:0:0:0:ffff:2d0a:1401"):
            self.assertEqual(app.norm_ip(x), "45.10.20.1", x)
        self.assertIsNone(app.norm_ip("ff0e::1"))

    def test_ipv6_links_keep_colons(self):
        # M3: the router matched literal colons only, and the links encoded them as %3A.
        self.assertIn('href="/ip/2001:db8::5"', app.ip_link("2001:db8::5"))

    def test_first_sendable_reads_past_private(self):
        # M15: a run of private addresses at the top of the queue no longer starves the public ones.
        rows = [("10.0.0.%d" % i,) for i in range(50)] + [("45.10.20.30",)]
        self.assertEqual(app.first_sendable(rows, 1), ["45.10.20.30"])


if __name__ == "__main__":
    unittest.main()
