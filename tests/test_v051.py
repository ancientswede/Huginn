# 0.51 DroneBL: a free DNS list of drones, botnets, proxies and brute forcers. Tag dronebl (no score), attacker page,
# JSON export, Campaigns tab, Settings panel with a DNS test. In-memory database, DNS mocked.
import json, time, unittest, urllib.parse
from unittest import mock

from tests.helpers import app
from tests.test_v0491 import IP, Mem, event
from tests.test_v046 import SettingsKey

PUB = "45.10.20.30"            # looks public: lookups only send global addresses


def fake_dns(listed):
    # dns_ask stand-in: the test address and the listed ones answer 127.0.0.code, the rest NXDOMAIN ([]).
    def ask(server, name, qtype=1, **kw):
        assert qtype == 1 and name.endswith(".dnsbl.dronebl.org")
        ip = ".".join(reversed(name[:-len(".dnsbl.dronebl.org")].split(".")))
        if ip == "127.0.0.2":
            return [[127, 0, 0, 1]]
        return [[127, 0, 0, c] for c in listed.get(ip, [])]
    return ask


class Lookup(Mem):
    def setUp(self):
        super().setUp()
        now = time.time()
        with self.con:
            self.con.executemany("INSERT INTO ips(ip,first,last,score) VALUES(?,?,?,?)",
                                 [(PUB, now - 60, now, 5), ("45.10.20.31", now - 60, now - 1, 4), ("10.0.0.5", now, now, 9), ("2001:db8::1", now, now, 9)])
        app.store(self.con, [event("a", now, ip=PUB)])

    def run_lookup(self, listed, test_answer=None):
        ask = fake_dns(listed)
        if test_answer is not None:
            orig = ask
            ask = lambda s, n, q=1, **k: test_answer if n.startswith("2.0.0.127.") else orig(s, n, q)
        with mock.patch.object(app, "dns_ask", ask), mock.patch.object(app, "nb_server", lambda c: "9.9.9.9"), \
                mock.patch.object(app.time, "sleep", lambda s: None):
            return app.dbl_lookup(self.con)

    def test_listed_gets_tag_and_classes_no_score(self):
        before = self.con.execute("SELECT score FROM ips WHERE ip=?", (PUB,)).fetchone()[0]
        self.assertEqual(self.run_lookup({PUB: [13, 15]}), 2)              # two public IPv4 addresses, LAN and IPv6 skipped
        d = app.dbl_get(self.con, PUB)
        self.assertEqual(d["classes"], ["brute force attacker", "compromised router or gateway"])
        tags = self.con.execute("SELECT tags, score FROM ips WHERE ip=?", (PUB,)).fetchone()
        self.assertIn("dronebl", tags[0])
        self.assertEqual(tags[1], before)
        self.assertFalse(app.dbl_get(self.con, "45.10.20.31")["listed"])
        self.assertIsNone(app.dbl_get(self.con, "10.0.0.5"))
        self.assertIsNone(app.dbl_get(self.con, "2001:db8::1"))
        html = app.dbl_html(self.con, d, PUB)
        self.assertIn("brute force attacker", html)
        self.assertIn("IPv4 only", app.dbl_html(self.con, None, "2001:db8::1"))

    def test_only_recent_attackers_asked(self):
        # 1.0.0-rc2: an address last seen over 30 days ago is not looked up, so the weekly recheck does not grow for ever.
        old = time.time() - 40 * 86400
        with self.con:
            self.con.execute("INSERT INTO ips(ip,first,last,score) VALUES(?,?,?,?)", ("45.10.20.40", old, old, 9))
        self.assertEqual(self.run_lookup({}), 2)
        self.assertIsNone(app.dbl_get(self.con, "45.10.20.40"))

    def test_blocked_resolver_pauses_and_says_so(self):
        self.assertEqual(self.run_lookup({PUB: [13]}, test_answer=[]), 0)
        self.assertIsNone(app.dbl_get(self.con, PUB))                     # nothing stored as "not listed"
        self.assertIn("drops DroneBL's answers", app.get_meta(self.con, "dbl_error"))
        self.assertGreater(float(app.get_meta(self.con, "dbl_wait_until")), time.time() + 5 * 3600)

    def test_odd_answer_is_an_error(self):
        with mock.patch.object(app, "dns_ask", lambda *a, **k: [[10, 0, 0, 1]]):
            with self.assertRaises(OSError):
                app.dbl_query("9.9.9.9", PUB)

    def test_dns_default_follows_httpbl(self):
        self.assertEqual(app.dbl_dns(self.con), "system")
        app.set_meta(self.con, "hb_dns", "9.9.9.9")
        self.assertEqual(app.dbl_dns(self.con), "9.9.9.9")
        app.set_meta(self.con, "dbl_dns", "1.1.1.1")
        self.assertEqual(app.dbl_dns(self.con), "1.1.1.1")

    def test_off_and_daily_limit(self):
        app.set_meta(self.con, "dbl_on", "0")
        self.assertEqual(self.run_lookup({}), 0)
        app.set_meta(self.con, "dbl_on", "1")
        app.set_meta(self.con, "dbl_day", app.day_budget(self.con, "dbl_day", 1)[1] + ":%d" % app.DBL_DAILY)
        self.assertEqual(self.run_lookup({}), 0)

    def test_export_and_campaigns(self):
        self.run_lookup({PUB: [16]})
        with mock.patch.object(app, "db", return_value=self.con):
            data = app.export_ip(PUB)
        self.assertEqual(data["dronebl"]["classes"], ["autorooting worm"])


class Pages(SettingsKey):
    def test_settings_saves_after_test(self):
        con = app.connect()
        with mock.patch.object(app, "dns_ask", fake_dns({})):
            r, _ = self.req("POST", "/settings/dronebl", urllib.parse.urlencode({"on": "1", "dns": "9.9.9.9"}), self.hdr({"Cookie": self.cookie}))
        self.assertEqual(r.getheader("Location"), "/settings?ok=dblon#dronebl")
        self.assertEqual(app.get_meta(con, "dbl_dns"), "9.9.9.9")
        with mock.patch.object(app, "dns_ask", lambda *a, **k: []):
            r, html = self.req("POST", "/settings/dronebl", urllib.parse.urlencode({"on": "1", "dns": "1.1.1.1"}), self.hdr({"Cookie": self.cookie}))
        self.assertEqual(r.status, 400)
        self.assertEqual(app.get_meta(con, "dbl_dns"), "9.9.9.9")      # nothing saved
        _r, html = self.req("GET", "/settings", headers={"Cookie": self.cookie})
        self.assertIn('id="dronebl"', html)
        _r, html = self.req("GET", "/campaigns", headers={"Cookie": self.cookie})
        self.assertIn('data-ctab="dronebl"', html)
        for k in ("dbl_dns", "dbl_on"):
            with con:
                con.execute("DELETE FROM meta WHERE k=?", (k,))


if __name__ == "__main__":
    unittest.main()
