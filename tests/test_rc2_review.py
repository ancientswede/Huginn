# 1.0.0-rc2: fixes from the Codex review before 1.0 (huginn-totalgranskning-rc2).
import gzip, http.server, json, os, tempfile, threading, time, unittest
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



def cowrie_line(ip, sid):
    return json.dumps({"eventid": "cowrie.login.failed", "src_ip": ip, "timestamp": "2026-11-01T10:00:00.000000Z",
                       "session": sid, "username": "root", "password": "x"})


class ImportFiles(Mem):
    # M32: the honeypot's own rotated logs are gzipped; the import read them as text, said nothing and stored nothing.
    def run_import(self, files):
        d = tempfile.mkdtemp()
        paths = []
        for name, data in files:
            paths.append(os.path.join(d, name))
            with open(paths[-1], "wb") as fh:
                fh.write(data)
        with mock.patch.object(app, "connect", return_value=self.con), mock.patch.object(app, "hold_db_lock", lambda: None), \
                mock.patch.object(app, "init_db", lambda: None), mock.patch("builtins.print"):
            app.import_files(paths)

    def test_gzipped_logs_are_read(self):
        text = (cowrie_line("45.10.20.61", "im1") + "\n").encode()
        self.run_import([("cowrie.json.2026-11-01.gz", gzip.compress(text)), ("cowrie.json.2026-11-02", (cowrie_line("45.10.20.62", "im2") + "\n").encode())])
        self.assertEqual(sorted(r[0] for r in self.con.execute("SELECT ip FROM ips")), ["45.10.20.61", "45.10.20.62"])

    def test_broken_gzip_fails(self):
        with self.assertRaises(SystemExit):
            self.run_import([("cowrie.json.1.gz", gzip.compress(b"x" * 1000)[:15])])


class ServiceSettings(unittest.TestCase):
    # M33: .env is read only by systemd; an import started by hand stored the owner's address unmasked.
    def test_import_needs_the_env_file_settings(self):
        f = tempfile.NamedTemporaryFile(delete=False)
        self.addCleanup(os.unlink, f.name)
        env = {k: v for k, v in os.environ.items() if k not in ("INVOCATION_ID", "HUGINN_HP_HOST")}
        with mock.patch.object(app, "ENV_FILE", f.name), mock.patch.dict(os.environ, env, clear=True):
            with self.assertRaises(SystemExit) as e:
                app.need_service_env()
            self.assertIn("systemd-run", str(e.exception))
            with mock.patch.dict(os.environ, {"INVOCATION_ID": "x"}):
                app.need_service_env()
        with mock.patch.object(app, "ENV_FILE", f.name + ".missing"), mock.patch.dict(os.environ, env, clear=True):
            app.need_service_env()

    def test_missing_rules_are_shown(self):
        # M31: a manual install without static/ classified no web requests and said nothing.
        with mock.patch.dict(app._web, {"rules": [], "sig": "", "error": "FileNotFoundError"}):
            self.assertIn("none loaded", app.web_rules_note())


class SmallFixes(unittest.TestCase):
    def test_c2_exclude_any_spelling(self):
        # M35: the feed compares the short form, the setting kept what the owner typed.
        self.assertEqual(app._canon_ip("2001:0db8:0000:0000:0000:0000:0000:0001"), "2001:db8::1")
        self.assertEqual(app._canon_ip("not-an-ip"), "not-an-ip")

    def test_asname_must_match_the_number(self):
        # L7: a reply for another AS number never names this one.
        txt = ["64502 | US | arin | 2010-07-14 | OTHER-NET"]
        self.assertIsNone(app.nb_asname(txt, "64501"))
        self.assertEqual(app.nb_asname(txt + ["64501 | SE | ripencc | 2001-01-01 | RIGHT-NET"], "64501"), "RIGHT-NET")

    def test_origin_scheme(self):
        # L9: behind a trusted proxy that says https, an http page on the same host is another origin.
        class H:
            client_address = ("10.0.0.2", 1)

        def check(origin, proto=None, proxy=True):
            h = H()
            h.headers = {"Origin": origin, "Host": "huginn.example"}
            if proto:
                h.headers["X-Forwarded-Proto"] = proto
            with mock.patch.object(app, "TRUSTED_PROXIES", {"10.0.0.2"} if proxy else set()):
                return app.Handler.same_origin(h)
        self.assertTrue(check("https://huginn.example", "https"))
        self.assertFalse(check("http://huginn.example", "https"))
        self.assertTrue(check("http://huginn.example"))
        self.assertTrue(check("https://huginn.example", "http", proxy=False))   # an untrusted proxy's header means nothing
        self.assertFalse(check("ftp://huginn.example"))
        self.assertFalse(check("https://evil.example", "https"))

if __name__ == "__main__":
    unittest.main()
