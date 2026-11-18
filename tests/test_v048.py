# 0.48 Tor exit nodes: daily list from the Tor Project, tag "tor", never "returned", off the blocklist unless chosen.
import io, time, unittest, urllib.parse
from unittest import mock

from tests.helpers import app
from tests.test_v046 import SettingsKey

TOR_IP, OTHER = "46.10.0.150", "46.10.0.151"     # public-looking: the list keeps only global addresses (test database only)


def big_list(*extra):
    # The fetch refuses a list with fewer than 100 addresses; documentation-free public-looking fillers.
    return "\n".join(list(extra) + ["# comment", "not-an-ip", "10.0.0.1"] + ["45.%d.%d.1" % (i // 200, i % 200) for i in range(150)]) + "\n"


class FakeResp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()


def clean(con):
    with con:
        con.execute("DELETE FROM tor")
        for ip in (TOR_IP, OTHER):
            con.execute("DELETE FROM ips WHERE ip=?", (ip,))
            con.execute("DELETE FROM sessions WHERE ip=?", (ip,))
            con.execute("DELETE FROM events WHERE ip=?", (ip,))
            con.execute("DELETE FROM flags WHERE ip=?", (ip,))
        for k in ("tor_on", "tor_bl", "tor_fetched", "tor_count", "tor_error", "tor_wait_until"):
            con.execute("DELETE FROM meta WHERE k=?", (k,))


def add_attacker(con, ip, days_ago=(20, 1)):
    # Two sessions with logins and commands, far enough apart to count as coming back.
    now = time.time()
    with con:
        for i, d in enumerate(days_ago):
            t = now - d * 86400
            con.execute("INSERT INTO sessions(session, ip, start, end, proto, port, logins_ok, logins_fail, cmds, files, tcpip, exploits) "
                        "VALUES(?,?,?,?,'ssh',22,1,5,3,0,0,0)", ("s-%s-%d" % (ip, i), ip, t, t + 60))
            con.execute("INSERT INTO events(ts, src, kind, ip, session, a, b) VALUES(?, 'cowrie', 'cmd', ?, ?, 'uname -a', '')",
                        (t + 5, ip, "s-%s-%d" % (ip, i)))
        app.recompute_ip(con, ip)


class Tor(unittest.TestCase):
    def setUp(self):
        self.con = app.connect()
        clean(self.con)
        add_attacker(self.con, TOR_IP)
        add_attacker(self.con, OTHER)

    def tearDown(self):
        clean(self.con)

    def fetch(self, body):
        with mock.patch.object(app, "api_urlopen", return_value=FakeResp(body.encode())) as u, mock.patch.object(app, "ENRICH", True):
            n = app.tor_refresh(self.con, force=True)
        return n, u

    def tags(self, ip):
        return (self.con.execute("SELECT tags FROM ips WHERE ip=?", (ip,)).fetchone()[0] or "").split(",")

    def test_parse(self):
        got = app.tor_parse(big_list(TOR_IP, "2001:db8::1"))
        self.assertIn("45.0.0.1", got)
        self.assertNotIn("10.0.0.1", got)        # private: never
        self.assertNotIn("not-an-ip", got)

    def test_tag_replaces_returned(self):
        self.assertIn("returned", self.tags(TOR_IP))
        n, u = self.fetch(big_list(TOR_IP))
        self.assertGreaterEqual(n, 150)
        self.assertEqual(u.call_args[0][0].full_url, app.TOR_URL)
        t = self.tags(TOR_IP)
        self.assertIn("tor", t)
        self.assertNotIn("returned", t)
        self.assertNotIn("stepped-up", t)
        self.assertIn("returned", self.tags(OTHER))
        self.assertIsNotNone(app.export_ip(TOR_IP)["tor_exit"])
        self.assertIsNone(app.export_ip(OTHER)["tor_exit"])

    def test_blocklist(self):
        self.fetch(big_list(TOR_IP))
        bl = app.blocklist_ips(self.con, 1, 30, False, True)
        self.assertNotIn(TOR_IP, bl)
        self.assertIn(OTHER, bl)
        self.assertIn(TOR_IP, app.blocklist_ips(self.con, 1, 30, False, True, True))
        app.set_meta(self.con, "tor_bl", "1")
        self.assertIn(TOR_IP, app.blocklist_ips(self.con, 1, 30, False, True))
        app.set_meta(self.con, "tor_bl", "0")
        with self.con:
            self.con.execute("INSERT INTO flags VALUES(?, 'block', '', ?)", (TOR_IP, time.time()))
        self.assertIn(TOR_IP, app.blocklist_ips(self.con, 1, 30, False, True))   # Always block wins
        self.assertEqual(app.bl_params({"tor": "1"})[4], True)
        self.assertEqual(app.bl_params({})[4], False)

    def test_window(self):
        # Listed long after the attack: not Tor then.
        with self.con:
            self.con.execute("INSERT INTO tor VALUES(?,?,?)", (OTHER, time.time() + 40 * 86400, time.time() + 41 * 86400))
            app.recompute_ip(self.con, OTHER)
        self.assertNotIn("tor", self.tags(OTHER))

    def test_short_list_and_errors(self):
        n, _ = self.fetch(TOR_IP + "\n")
        self.assertIsNone(n)
        self.assertIn("only 1 addresses", app.get_meta(self.con, "tor_error"))
        self.assertNotIn("tor", self.tags(TOR_IP))
        self.assertGreater(float(app.get_meta(self.con, "tor_wait_until")), time.time())

    def test_once_a_day_and_off(self):
        with mock.patch.object(app, "ENRICH", True):
            app.set_meta(self.con, "tor_fetched", time.time() - 3600)
            with mock.patch.object(app, "api_urlopen") as u:
                self.assertIsNone(app.tor_refresh(self.con))
            u.assert_not_called()
            app.set_meta(self.con, "tor_on", "0")
            with mock.patch.object(app, "api_urlopen") as u:
                self.assertIsNone(app.tor_refresh(self.con, force=True))
            u.assert_not_called()


class Pages(SettingsKey):
    def setUp(self):
        self.con = app.connect()
        clean(self.con)
        add_attacker(self.con, TOR_IP)
        with self.con:
            self.con.execute("INSERT INTO tor VALUES(?,?,?)", (TOR_IP, time.time() - 86400, time.time()))
            app.recompute_ip(self.con, TOR_IP)

    def tearDown(self):
        clean(self.con)

    def test_pages_and_settings(self):
        h = {"Cookie": self.cookie}
        _r, html = self.req("GET", "/ip/" + TOR_IP, headers=h)
        self.assertIn(">tor</span>", html)
        _r, html = self.req("GET", "/ips?tag=tor&days=all", headers=h)
        self.assertIn(TOR_IP, html)
        _r, html = self.req("GET", "/blocklist", headers=h)
        self.assertIn("Tor exits", html)
        self.assertIn("tor=0", html)
        _r, html = self.req("GET", "/settings", headers=h)
        self.assertIn('id="tor"', html)
        r, _ = self.req("POST", "/settings/tor", urllib.parse.urlencode({"on": "1", "bl": "1"}), self.hdr(h))
        self.assertEqual(r.status, 303)
        self.assertTrue(app.tor_bl(self.con))
        r, _ = self.req("POST", "/settings/tor", urllib.parse.urlencode({}), self.hdr(h))
        self.assertEqual(r.status, 303)
        self.assertEqual(app.get_meta(self.con, "tor_on"), "0")
        self.assertNotIn("tor", (self.con.execute("SELECT tags FROM ips WHERE ip=?", (TOR_IP,)).fetchone()[0] or "").split(","))
        _r, html = self.req("GET", "/help", headers=h)
        self.assertIn("Tor exit", html)


del SettingsKey
