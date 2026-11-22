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
