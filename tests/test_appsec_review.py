# Fynd från appsec-granskningen 2026-11-22: never-block-lista och tak för blocklistan, nästlad JSON i ##IDS,
# HUGINN_ALLOWED_HOSTS från installern.
import ipaddress, json, os, subprocess, time, unittest
from unittest import mock

from tests.helpers import ROOT, app

NOW = time.time()


def row(ip, src, kind, session=None, a=None, b=None, dt=0.0):
    ts = NOW - 3600 + dt
    h = "appsec|%s|%s|%s|%s|%s|%s" % (ts, ip, kind, session, a, b)
    return (h, ts, ip, src, kind, session, a, b)


class NeverBlock(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.con = app.connect()
        # A compromised honeypot can write a fake decoy event with any source address: score 4, over the default 3.
        app.store(cls.con, [row("8.8.8.8", "canary", "canary", None, "redis", "{}"),
                            row("2001:4860:4860::8888", "canary", "canary", None, "redis", "{}"),
                            row("203.0.113.201", "canary", "canary", None, "redis", "{}"),
                            row("203.0.113.202", "cowrie", "login_ok", "ap2", "root", "x"),
                            row("203.0.113.202", "cowrie", "file", "ap2", "http://192.0.2.9/x", "ab" * 32, 1)])

    def test_resolvers_never_listed(self):
        ips = app.blocklist_ips(self.con, 3, 30, False, True)
        self.assertNotIn("8.8.8.8", ips)
        self.assertNotIn("2001:4860:4860::8888", ips)
        self.assertIn("203.0.113.201", ips)

    def test_own_cidr(self):
        with mock.patch.object(app, "NEVER_BLOCK", app.NEVER_BLOCK + [ipaddress.ip_network("203.0.113.200/30")]):
            ips = app.blocklist_ips(self.con, 3, 30, False, True)
        self.assertNotIn("203.0.113.201", ips)
        self.assertNotIn("203.0.113.202", ips)

    def test_manual_block_wins(self):
        with self.con:
            self.con.execute("INSERT OR REPLACE INTO flags(ip, flag, note) VALUES('8.8.8.8','block','')")
        try:
            self.assertIn("8.8.8.8", app.blocklist_ips(self.con, 3, 30, False, True))
        finally:
            with self.con:
                self.con.execute("DELETE FROM flags WHERE ip='8.8.8.8'")

    def test_cap_keeps_highest_score(self):
        with mock.patch.object(app, "BL_MAX", 1):
            self.assertEqual(app.blocklist_ips(self.con, 3, 30, False, True), ["203.0.113.202"])

    def test_env_parsing(self):
        self.assertEqual(app._nets(" 192.0.2.1/24, nonsense ,2001:db8::/32,"),
                         [ipaddress.ip_network("192.0.2.0/24"), ipaddress.ip_network("2001:db8::/32")])


class NestedIds(unittest.TestCase):
    def test_nested_json_does_not_stop_sync(self):
        deep = "[" * 60000
        good = json.dumps({"t": time.strftime("%Y-%m-%dT%H:%M:%S+0000", time.gmtime(NOW - 60)), "ip": "203.0.113.71",
                           "sid": 2025883, "sev": 1, "sig": "ET TEST", "cat": "x", "proto": "TCP", "port": 80})
        app.parse_export("##COWRIE\n##IDS\n" + deep + "\n" + good + "\n##END\n", set())
        self.assertEqual([r[2] for r in app.parse_export.ids], ["203.0.113.71"])


class AllowedHosts(unittest.TestCase):
    def test_installer_writes_allowed_hosts(self):
        with open(os.path.join(ROOT, "install-huginn.sh")) as fh:
            src = fh.read()
        self.assertIn("HUGINN_ALLOWED_HOSTS=$(allowed_hosts)", src)
        start = src.index("allowed_hosts() {")
        fn = src[start:src.index("\n}\n", start) + 3]
        out = subprocess.run(["bash", "-c", fn + "\nWEB_PORT=8095; allowed_hosts"], capture_output=True, text=True, timeout=10).stdout.strip()
        hosts = out.split(",")
        self.assertIn("localhost:8095", hosts)
        self.assertIn("127.0.0.1:8095", hosts)
        self.assertEqual(len(hosts), len(set(hosts)))
        for h in hosts:
            self.assertRegex(h, r"^(\[[0-9a-f:]+\]|[a-z0-9._-]+):8095$")


# Codex-granskningen av rc3 (2026-11-22).
class CodexRc3(unittest.TestCase):
    def test_c2_never_block_and_cap(self):
        con = app.connect()
        sha = "cd" * 32
        with con:
            con.execute("INSERT OR REPLACE INTO files(sha, src, size, type, iocs, mtime, updated) VALUES(?, 'cowrie', 120, 'ASCII text', ?, ?, ?)",
                        (sha, json.dumps(["9.9.9.9", "203.0.113.230", "198.51.100.231"]), NOW, NOW))
        rows = [row("203.0.113.%d" % n, "cowrie", "file", "c2%d" % n, "http://192.0.2.1/x", sha) for n in (221, 222, 223)]
        rows.append(row("203.0.113.224", "cowrie", "file", "c24", "http://198.51.100.231/y", "ee" * 32))
        app.store(con, rows)
        c2 = app.c2_list(con)
        self.assertNotIn("9.9.9.9", c2)                         # was already left out (BENIGN_IOC)
        self.assertIn("203.0.113.230", c2)
        with mock.patch.object(app, "NEVER_BLOCK", app.NEVER_BLOCK + [ipaddress.ip_network("203.0.113.230/32")]):
            self.assertNotIn("203.0.113.230", app.c2_list(con))
        with mock.patch.object(app, "BL_MAX", 1):
            self.assertEqual(list(app.c2_list(con)), ["198.51.100.231"])   # 4 sources beats 3

    def test_mapped_never_block_net(self):
        self.assertEqual(app._nets("::ffff:203.0.113.0/120"), [ipaddress.ip_network("203.0.113.0/24")])

    def test_ids_counters_ascii_only(self):
        app.parse_export("##COWRIE\n##IDS\nrules 1²\ndropped ٣\n##END\n", set())
        self.assertEqual(app.parse_export.meta["ids_dropped"], 0)

    def test_fake_status_in_a_log_loses(self):
        fake = "##STATUS\n" + "\n".join("sandbox:cowrie ok" for _ in range(100))
        real = "##STATUS\nsandbox:cowrie missing\n"
        app.parse_export("##COWRIE\n" + fake + "\n##CANARY\n" + real + "##FILES\n##END\n", set())
        self.assertEqual(app.parse_export.meta["status"], {"sandbox:cowrie": False})

    def test_hp_export_drops_marker_lines(self):
        with open(os.path.join(ROOT, "honeypot/hp-export")) as fh:
            src = fh.read()
        line = next(x for x in src.splitlines() if x.startswith("keep() {"))
        out = subprocess.run(["bash", "-c", line + "\nprintf '%s\\n' '{\"a\":1}' '##STATUS' 'sandbox:cowrie ok' | keep"],
                             capture_output=True, text=True, timeout=10).stdout
        self.assertEqual(out.splitlines(), ['{"a":1}', "sandbox:cowrie ok"])

    def test_sandbox_failure_leaves_service_stopped(self):
        with open(os.path.join(ROOT, "honeypot/setup-sandbox.sh")) as fh:
            src = fh.read()
        self.assertNotIn('rm -f "$f"', src)
        self.assertEqual(src.count('systemctl stop "$unit"'), 2)

    def test_isolation_refused_and_ping_fail(self):
        with open(os.path.join(ROOT, "tools/check-isolation.sh")) as fh:
            src = fh.read()
        self.assertIn('refused) bad "$l"', src)
        self.assertIn('then bad "$h" "LAN: answers ping"', src)
        start = src.index("tcp_state() {")
        fn = src[start:src.index("\n}\n", start) + 3]
        out = subprocess.run(["bash", "-c", fn + "\ntcp_state 127.0.0.1 1"], capture_output=True, text=True, timeout=10).stdout.strip()
        self.assertEqual(out, "refused")


# Fuzzningen 2026-11-22: länkar byggdes av angriparstyrd text (hassh, filhash, tty-hash).
class FuzzLinks(unittest.TestCase):
    def ev(self, eventid, **kw):
        d = {"eventid": eventid, "src_ip": "198.51.100.23", "session": "fz1", "timestamp": "2026-11-01T10:00:00.000000Z"}
        d.update(kw)
        return json.dumps(d)

    def test_only_real_hashes_are_read(self):
        self.assertIsNone(app.p_cowrie(self.ev("cowrie.client.kex", hassh="/bin/busybox ECCHI")))
        self.assertIsNone(app.p_cowrie(self.ev("cowrie.client.kex", hassh=["ab" * 16])))
        self.assertEqual(app.p_cowrie(self.ev("cowrie.client.kex", hassh="ab" * 16))[5], "ab" * 16)
        self.assertIsNone(app.p_cowrie(self.ev("cowrie.log.closed", shasum="2ad4{x", size=10)))
        self.assertEqual(app.p_cowrie(self.ev("cowrie.log.closed", shasum="cd" * 32, size=10))[3], "tty")
        r = app.p_cowrie(self.ev("cowrie.session.file_download", url="http://192.0.2.9/x", shasum="wget http://x/y; sh y"))
        self.assertEqual((r[3], r[5], r[6]), ("file", "http://192.0.2.9/x", None))
        self.assertEqual(app.p_cowrie(self.ev("cowrie.session.file_upload", filename="x", shasum="ef" * 32))[6], "ef" * 32)

    def test_seg_encodes(self):
        self.assertEqual(app.seg("a b/<c>&"), "a%20b%2F%3Cc%3E%26")
        self.assertEqual(app.seg(None), "")


class CodexRc3Small(unittest.TestCase):
    # Tre små rester från Codex rc3-granskningen, rättade i rc4.
    def setUp(self):
        self.con = app.connect()

    def tearDown(self):
        self.con.execute("DELETE FROM meta WHERE k='hp_status'")
        self.con.commit()

    def status(self, items, at=None):
        app.set_meta(self.con, "hp_status", json.dumps({"at": at or time.time(), "items": items}))
        self.con.commit()

    def test_no_checks_is_not_all_in_place(self):
        self.status({})
        self.assertEqual(app.protection_missing(self.con), ["nocheck:sandbox", "nocheck:limits"])
        note = app.protection_note(self.con)
        self.assertNotIn("all in place", note)
        self.assertIn("no sandbox checks reported", note)
        self.status({"option:suricata": True, "running:suricata": True})
        self.assertIn("nocheck:sandbox", app.protection_missing(self.con))
        self.status({"sandbox:cowrie": True, "limits:cowrie": True})
        self.assertEqual(app.protection_missing(self.con), [])
        self.assertIn("all in place", app.protection_note(self.con))

    def test_old_empty_report_stays_quiet(self):
        self.status({}, time.time() - 7200)                 # the sync check covers an old report
        self.assertEqual(app.protection_missing(self.con), [])

    def test_same_origin_ignores_host_case(self):
        class H:
            client_address = ("127.0.0.1", 1)
        h = H()
        h.headers = {"Origin": "http://Huginn.Example:8095", "Host": "huginn.example:8095"}
        self.assertTrue(app.Handler.same_origin(h))
        h.headers = {"Origin": "http://evil.example:8095", "Host": "huginn.example:8095"}
        self.assertFalse(app.Handler.same_origin(h))

    def test_healthz_unknown_host_says_only_ok(self):
        import http.client, threading
        srv = app.HuginnServer(("127.0.0.1", 0), app.Handler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            def get(host):
                c = http.client.HTTPConnection("127.0.0.1", srv.server_address[1], timeout=10)
                c.request("GET", "/healthz", headers={"Host": host})
                r = c.getresponse()
                out = (r.status, json.loads(r.read()))
                c.close()
                return out
            with mock.patch.object(app, "ALLOWED_HOSTS", {"huginn.example"}):
                code, body = get("rebind.example")
                self.assertEqual(set(body), {"ok"})
                code2, body2 = get("HUGINN.example")
                self.assertEqual(code, code2)
                self.assertIn("version", body2)
                # update-huginn.sh asks 127.0.0.1:PORT: it must get the version, or every update rolls back (rc4 deploy 2026-11-23)
                for h in ("127.0.0.1:8095", "localhost:8095", "127.0.0.1", "[::1]:8095"):
                    self.assertIn("version", get(h)[1], h)
                self.assertEqual(set(get("127.0.0.1.rebind.example:8095")[1]), {"ok"})
        finally:
            srv.shutdown()
            srv.server_close()


class RenameRc5(unittest.TestCase):
    # rc5: Huginn heter RavenTrap. Bara synligt namn; gamla standardtiteln visas som det nya namnet, egna titlar behålls.
    def setUp(self):
        self.con = app.connect()

    def tearDown(self):
        self.con.execute("DELETE FROM meta WHERE k='settings'")
        self.con.commit()

    def test_old_default_title_shows_new_name(self):
        for saved, shown in (("Huginn", "RavenTrap"), ("My honeypot", "My honeypot")):
            app.set_meta(self.con, "settings", json.dumps({"v": 9, "title": saved}))
            self.con.commit()
            self.assertEqual(app.settings(self.con)["title"], shown)

    def test_update_check_tries_new_then_old_repo(self):
        import urllib.error
        asked = []

        def fake(req, timeout=20):
            asked.append(req.full_url)
            if "RavenTrap" in req.full_url:
                raise urllib.error.HTTPError(req.full_url, 404, "Not Found", {}, None)
            class R:
                def read(self, n):
                    return json.dumps([{"name": "v1.0.0"}]).encode()
            return R()
        self.con.execute("DELETE FROM meta WHERE k IN ('update_checked','update_latest','update_error')")
        with mock.patch.object(app, "UPDATE_CHECK", True), mock.patch.object(app, "api_urlopen", fake), \
                mock.patch.object(app, "UPDATE_REPOS", ["ancientswede/RavenTrap", "ancientswede/Huginn"]):
            app.check_update(self.con)
        self.assertEqual([u.split("/")[5] for u in asked], ["RavenTrap", "Huginn"])
        self.assertEqual(app.get_meta(self.con, "update_latest"), "1.0.0")
        self.assertEqual(app.get_meta(self.con, "update_error"), "")

    def test_interfaces_keep_the_old_name(self):
        # Feeds, metrics, env names and the service stay "huginn": firewalls and dashboards must not break.
        self.assertIn('HUGINN_ALLOWED_HOSTS', open(app.__file__).read())
        self.assertIn("list=huginn", open(app.__file__).read())
