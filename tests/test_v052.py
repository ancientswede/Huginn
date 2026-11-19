# 0.52 Spamhaus ZEN (own resolver only, error codes are errors), Abusix abuse contacts with a Report link, and a DNS
# picker that takes any resolver. In-memory database, DNS mocked.
import json, time, unittest, urllib.parse
from unittest import mock

from tests.helpers import app
from tests.test_v0491 import Mem, event
from tests.test_v046 import SettingsKey

PUB, PUB2 = "45.10.20.40", "45.10.20.41"


def zen(listed, error=None):
    def ask(server, name, qtype=1, **kw):
        if name.endswith(".zen.spamhaus.org"):
            ip = ".".join(reversed(name[:-len(".zen.spamhaus.org")].split(".")))
            if error is not None:
                return [[127, 255, 255, error]]
            if ip == "127.0.0.2":
                return [[127, 0, 0, 2], [127, 0, 0, 4], [127, 0, 0, 10]]
            return [[127, 0, 0, c] for c in listed.get(ip, [])]
        if name.endswith(".abuse-contacts.abusix.org"):
            ip = ".".join(reversed(name[:-len(".abuse-contacts.abusix.org")].split(".")))
            return ["abuse@example.net"] if ip == PUB else []
        raise AssertionError(name)
    return ask


class Lookups(Mem):
    def setUp(self):
        super().setUp()
        now = time.time()
        with self.con:
            self.con.executemany("INSERT INTO ips(ip,first,last,score,cmds,logins_ok,logins_fail,files) VALUES(?,?,?,?,?,?,?,?)",
                                 [(PUB, now - 3600, now, 5, 3, 1, 4, 0), (PUB2, now - 60, now - 1, 4, 0, 0, 2, 0)])
        app.store(self.con, [event("a", now, ip=PUB), event("b", now, ip=PUB2)])
        app.set_meta(self.con, "sh_dns", "127.0.0.1")

    def go(self, f, ask):
        with mock.patch.object(app, "dns_ask", ask), mock.patch.object(app, "nb_server", lambda c: c), \
                mock.patch.object(app.time, "sleep", lambda s: None):
            return f(self.con)

    def test_spamhaus_tags_xbl_not_pbl(self):
        self.assertEqual(self.go(app.sh_lookup, zen({PUB: [4], PUB2: [10]})), 2)
        tag = lambda ip: self.con.execute("SELECT tags FROM ips WHERE ip=?", (ip,)).fetchone()[0] or ""
        self.assertIn("spamhaus", tag(PUB))
        self.assertNotIn("spamhaus", tag(PUB2))                  # a home range is no accusation
        self.assertEqual(app.sh_get(self.con, PUB)["classes"], ["XBL: exploited or infected"])
        self.assertIn("t-red", app.sh_html(self.con, app.sh_get(self.con, PUB), PUB))

    def test_spamhaus_error_codes_are_errors(self):
        self.assertEqual(self.go(app.sh_lookup, zen({}, error=254)), 0)
        self.assertIsNone(app.sh_get(self.con, PUB))
        self.assertIn("public DNS", app.get_meta(self.con, "sh_error"))
        with mock.patch.object(app, "dns_ask", zen({}, error=255)):
            with self.assertRaises(OSError):
                app.sh_query("127.0.0.1", PUB)

    def test_spamhaus_never_through_public_resolver(self):
        app.set_meta(self.con, "sh_dns", "9.9.9.9")
        with mock.patch.object(app, "dns_ask", side_effect=AssertionError("must not ask")):
            self.assertEqual(app.sh_lookup(self.con), 0)
        self.assertIn("public DNS", app.get_meta(self.con, "sh_error"))

    def test_abuse_contact_and_report_link(self):
        app.set_meta(self.con, "nb_dns", "127.0.0.1")
        self.assertEqual(self.go(app.ab_lookup, zen({})), 2)
        a = app.ab_get(self.con, PUB)
        self.assertEqual(a["email"], "abuse@example.net")
        html = app.ab_html(self.con, PUB, a)
        self.assertIn("mailto:abuse@example.net?", html)
        self.assertIn("Abusix", urllib.parse.unquote(html))
        self.assertIn("none found", app.ab_html(self.con, PUB2, app.ab_get(self.con, PUB2)))
        # an odd TXT answer cannot inject anything into the link
        with mock.patch.object(app, "dns_ask", lambda *a, **k: ['x" onmouseover="alert(1) abuse@evil.example<script>']):
            self.assertEqual(app.ab_query("127.0.0.1", PUB), "abuse@evil.example")

    def test_export(self):
        self.go(app.sh_lookup, zen({PUB: [4]}))
        app.set_meta(self.con, "nb_dns", "127.0.0.1")
        self.go(app.ab_lookup, zen({}))
        with mock.patch.object(app, "db", return_value=self.con):
            d = app.export_ip(PUB)
        self.assertEqual(d["spamhaus"]["classes"], ["XBL: exploited or infected"])
        self.assertEqual(d["abuse_contact"]["email"], "abuse@example.net")


class TagLists(unittest.TestCase):
    def test_help_and_filter_list_new_tags(self):
        h = app.v_help()
        h = h if isinstance(h, str) else h.decode()
        for t in ("dronebl", "spamhaus"):
            self.assertIn(app.esc(app.TAG_HELP[t]), h)


class Picker(unittest.TestCase):
    def test_other_server_wins(self):
        self.assertEqual(app.dns_from_form({"dns": "9.9.9.9", "dns_other": " 192.0.2.53 "}, "system"), "192.0.2.53")
        self.assertEqual(app.dns_from_form({"dns": "9.9.9.9", "dns_other": ""}, "system"), "9.9.9.9")
        self.assertIn("127.0.0.1", app.dns_picker("x", "system"))


class Pages(SettingsKey):
    def test_spamhaus_settings(self):
        con = app.connect()
        r, _ = self.req("POST", "/settings/spamhaus", urllib.parse.urlencode({"on": "1", "dns": "9.9.9.9"}), self.hdr({"Cookie": self.cookie}))
        self.assertEqual(r.status, 400)                           # public resolver refused before asking
        with mock.patch.object(app, "dns_ask", zen({})):
            r, _ = self.req("POST", "/settings/spamhaus", urllib.parse.urlencode({"on": "1", "dns": "system", "dns_other": "127.0.0.1"}),
                            self.hdr({"Cookie": self.cookie}))
        self.assertEqual(r.getheader("Location"), "/settings?ok=shon#spamhaus")
        self.assertEqual(app.get_meta(con, "sh_dns"), "127.0.0.1")
        _r, html = self.req("GET", "/settings", headers={"Cookie": self.cookie})
        self.assertIn('id="spamhaus"', html)
        self.assertIn("Needs your own DNS resolver", html)
        for k in ("sh_dns", "sh_on"):
            with con:
                con.execute("DELETE FROM meta WHERE k=?", (k,))


if __name__ == "__main__":
    unittest.main()
