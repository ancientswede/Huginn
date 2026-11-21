# 1.0.0-rc2: fixes from the Codex review before 1.0 (huginn-totalgranskning-rc2).
import gzip, http.server, json, os, tempfile, threading, time, unittest, urllib.parse
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
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
    # Seen live 2026-11-21: 1 813 attackers without a country. ipwho.is answered 429, Shodan answered, and the row was
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


class TrapLimits(unittest.TestCase):
    # M34: POP3 and IMAP had no total time and shared every place, so long sessions could close the other traps.
    def setUp(self):
        from tests.test_slowreply import ROOT as R, load
        d = tempfile.mkdtemp()
        os.environ["LOGS_DIRECTORY"] = d
        self.t = load("hp_traps_rc2", os.path.join(str(R), "honeypot", "hp-traps.py"))

    def talk(self, service, keep=3.0):
        import asyncio

        async def run():
            srv = await asyncio.start_server(self.t.make(service), "127.0.0.1", 0)
            r, w = await asyncio.open_connection("127.0.0.1", srv.sockets[0].getsockname()[1])
            reader = asyncio.ensure_future(r.read())
            start = time.monotonic()
            while not reader.done() and time.monotonic() - start < keep:
                try:
                    w.write(b"NOOP\r\n"); await w.drain()
                except (ConnectionError, OSError):
                    break
                await asyncio.sleep(0.2)
            try:
                got = await asyncio.wait_for(reader, 5)
            except (ConnectionError, OSError):
                got = b""                         # closed on us: nothing was answered
            took = time.monotonic() - start
            w.close(); srv.close(); await srv.wait_closed()
            return took, got
        return asyncio.run(run())

    def test_pop3_session_ends(self):
        self.t.TRAP_MAX_SECS = 1.0
        took, got = self.talk("pop3")
        self.assertTrue(got)                       # the banner came
        self.assertLess(took, 2.5)

    def test_one_trap_cannot_take_every_place(self):
        self.t._per["imap"] = self.t.TRAP_MAX_CONN
        _took, got = self.talk("imap", keep=0.5)
        self.assertEqual(got, b"")                 # IMAP is full: closed at once
        self.t.TRAP_MAX_SECS = 0.5
        _took, got = self.talk("pop3", keep=1.0)
        self.assertTrue(got)                       # POP3 still answers


class Health(unittest.TestCase):
    # M1: /healthz said ok while a collection problem was open, and a failed ntfy send kept the problem from being saved.
    def test_healthz_follows_the_problems(self):
        import http.client
        from http.server import ThreadingHTTPServer
        con = app.connect()
        app.set_meta(con, "last_ingest", time.time())
        self.addCleanup(app.set_meta, con, "health_now", "{}")
        srv = ThreadingHTTPServer(("127.0.0.1", 0), app.Handler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)

        def status():
            c = http.client.HTTPConnection("127.0.0.1", srv.server_address[1], timeout=10)
            c.request("GET", "/healthz", headers={"Host": "127.0.0.1"})
            r = c.getresponse(); body = json.loads(r.read()); c.close()
            return r.status, body["ok"]
        app.set_meta(con, "health_now", json.dumps({"canary": "OpenCanary quiet for 2 days"}))
        self.assertEqual(status(), (503, False))
        app.set_meta(con, "health_now", "{}")
        self.assertEqual(status(), (200, True))


class HealthAlerts(Mem):
    def test_failed_alert_is_tried_again(self):
        def down(*a):
            raise OSError("ntfy down")
        with mock.patch.object(app, "protection_missing", lambda c: ["traps"]), mock.patch.object(app, "NTFY_URL", "http://127.0.0.1:9/x"), \
                mock.patch.object(app, "settings", lambda c=None: {"notify": True}), mock.patch.object(app, "ntfy_post", down), \
                mock.patch.object(app, "health_sources", lambda c, n: {}):
            app.health_check(self.con)
        self.assertIn("prot:traps", json.loads(app.get_meta(self.con, "health_now")))
        self.assertNotIn("prot:traps", json.loads(app.get_meta(self.con, "health_alerted")))
        sent = []
        with mock.patch.object(app, "protection_missing", lambda c: ["traps"]), mock.patch.object(app, "NTFY_URL", "http://127.0.0.1:9/x"), \
                mock.patch.object(app, "settings", lambda c=None: {"notify": True}), mock.patch.object(app, "ntfy_post", lambda *a: sent.append(a)), \
                mock.patch.object(app, "health_sources", lambda c, n: {}):
            app.health_check(self.con)
        self.assertEqual(len(sent), 1)
        self.assertIn("prot:traps", json.loads(app.get_meta(self.con, "health_alerted")))


class Budgets(Mem):
    def test_day_take_stops_at_the_cap(self):
        # M25: booking is read and written in one locked step.
        self.assertTrue(app.day_take(self.con, "vt_day", 2))
        self.assertTrue(app.day_take(self.con, "vt_day", 2))
        self.assertFalse(app.day_take(self.con, "vt_day", 2))
        self.assertEqual(app.day_budget(self.con, "vt_day", 2)[2], 2)

    def test_abusix_allowance_of_one(self):
        # L1: with no resolver test to pay for, an allowance of one is one lookup, not zero.
        now = time.time()
        with self.con:
            self.con.execute("INSERT INTO ips(ip,first,last,score) VALUES('45.10.20.70',?,?,1)", (now, now))
        asked = []
        with mock.patch.object(app, "nb_server", lambda d: "x"), mock.patch.object(app.time, "sleep", lambda s: None):
            n, _ = app.dnslist_lookup(self.con, "Abusix", "abusecontact", True, 1, "9.9.9.9", 86400,
                                      lambda srv, ip: asked.append(ip) or "abuse@example.net", None)
        self.assertEqual((n, asked), (1, ["45.10.20.70"]))

    def test_vt_queue_skips_broken_hashes(self):
        # L6: three broken values at the top no longer keep a real file out of the queue.
        now = time.time()
        good = "ab" * 32
        with self.con:
            for i, b in enumerate(["not-a-hash-%d" % i for i in range(3)] + [good]):
                self.con.execute("INSERT INTO events(h, ts, ip, src, kind, session, a, b) VALUES(?,?,?,?,?,?,?,?)",
                                 ("vt%d" % i, now - (0 if b != good else 3600), "45.10.20.71", "cowrie", "file", "s", "/tmp/x", b))
        asked = []
        with mock.patch.object(app, "vt_key", lambda c: "k" * 64), mock.patch.object(app, "api_urlopen", lambda r, timeout: asked.append(r.full_url) or (_ for _ in ()).throw(OSError("off"))), \
                mock.patch.object(app.time, "sleep", lambda s: None):
            app.vt_lookup(self.con, limit=3)
        self.assertTrue(asked and asked[0].endswith(good))


class DnsTags(Mem):
    def test_answer_and_tag_change_together(self):
        # M10: a timeout on the next address no longer leaves the first one listed without its tag.
        now = time.time()
        app.store(self.con, [("d|%d" % i, now - i, ip, "cowrie", "cmd", "s-d%d" % i, "id", None)
                             for i, ip in enumerate(("45.10.20.80", "45.10.20.81"))])
        answers = iter([[3], OSError("timeout")])

        def q(srv, ip):
            x = next(answers)
            if isinstance(x, Exception):
                raise x
            return x
        with mock.patch.object(app, "dbl_on", lambda c: True), mock.patch.object(app, "nb_server", lambda d: "x"), \
                mock.patch.object(app, "dbl_test", lambda s: "ok"), mock.patch.object(app, "dbl_query", q), \
                mock.patch.object(app.time, "sleep", lambda s: None):
            app.dbl_lookup(self.con)
        listed = [r[0] for r in self.con.execute("SELECT ip FROM dronebl WHERE codes!='[]'")]
        self.assertEqual(len(listed), 1)
        tags = self.con.execute("SELECT tags FROM ips WHERE ip=?", (listed[0],)).fetchone()[0] or ""
        self.assertIn("dronebl", tags)


class Report(Mem):
    def test_abuse_mail_times_are_utc(self):
        # L2: the report says UTC, so the times in it are UTC whatever HUGINN_TZ is.
        t = datetime(2026, 10, 20, 12, 0, tzinfo=timezone.utc).timestamp()
        app.store(self.con, [("r|1", t, "45.10.20.90", "cowrie", "cmd", "s-r", "id", None)])
        with mock.patch.object(app, "TZ", ZoneInfo("Europe/Stockholm")):
            html = app.ab_html(self.con, "45.10.20.90", {"email": "abuse@example.net"})
        self.assertIn("2026-10-20 12:00", urllib.parse.unquote(html))
        self.assertNotIn("2026-10-20 14:00", urllib.parse.unquote(html))


class Builds(unittest.TestCase):
    def test_demo_has_none_of_the_machines_settings(self):
        # L3: the demo is published; the build machine's ntfy server ended up in settings.html.
        import subprocess, sys
        from tests.helpers import ROOT as R
        out = tempfile.mkdtemp()
        env = dict(os.environ, HUGINN_NTFY_URL="http://ntfy-marker-rc2.lan/topic", HUGINN_MASK="mask-marker-rc2")
        subprocess.run([sys.executable, os.path.join(str(R), "tools", "make_demo.py"), os.path.join(out, "d"), "--base", "/"],
                       env=env, check=True, capture_output=True, timeout=300)
        for root, _d, files in os.walk(out):
            for f in files:
                with open(os.path.join(root, f), "rb") as fh:
                    data = fh.read()
                self.assertNotIn(b"marker-rc2", data, f)

    def test_release_candidate_files_run_their_own_image(self):
        # M28: latest only moves for stable releases.
        import subprocess
        from tests.helpers import ROOT as R
        if subprocess.run(["which", "dpkg-deb"], capture_output=True).returncode:
            self.skipTest("needs dpkg-deb")
        out = tempfile.mkdtemp()
        subprocess.run(["bash", os.path.join(str(R), "tools", "build-release.sh"), out], check=True, capture_output=True, timeout=300)
        compose = open(os.path.join(out, "docker-compose.yml")).read()
        want = app.HUGINN_VERSION if "-" in app.HUGINN_VERSION else "latest"
        self.assertIn("huginn:${HUGINN_TAG:-%s}" % want, compose)

if __name__ == "__main__":
    unittest.main()
