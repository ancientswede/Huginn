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
