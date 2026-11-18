# 0.47 Netblocks: Team Cymru's IP-to-ASN service over DNS (TXT), shown per attacker, as a filter, a column and on Campaigns.
import struct, time, unittest, urllib.parse
from unittest import mock

from tests.helpers import app
from tests.test_v0461 import FakeServer
from tests.test_v046 import SettingsKey

IPS = ("203.0.113.10", "203.0.113.11", "198.51.100.40", "2001:db8::9")


def clean(con):
    with con:
        con.execute("DELETE FROM netblock")
        con.execute("DELETE FROM asname")
        con.execute("DELETE FROM ips WHERE ip IN (%s)" % ",".join("?" * len(IPS)), IPS)
        for k in ("nb_on", "nb_dns", "nb_error", "nb_wait_until", "nb_day"):
            con.execute("DELETE FROM meta WHERE k=?", (k,))


def txt_reply(query, texts, rcode=0, split=False):
    # A reply to `query` with TXT records (each optionally split into two character strings).
    q = query[12:]
    hdr = query[:2] + struct.pack(">HHHHH", 0x8180 | rcode, 1, len(texts), 0, 0)
    body = q
    for t in texts:
        b = t.encode()
        parts = [b[:10], b[10:]] if split else [b]
        rdata = b"".join(bytes([len(p)]) + p for p in parts)
        body += b"\xc0\x0c" + struct.pack(">HHIH", 16, 1, 300, len(rdata)) + rdata
    return hdr + body


class Txt(unittest.TestCase):
    def ask(self, handler, name="1.0.0.10.origin.asn.cymru.com"):
        srv = FakeServer(handler)
        try:
            return app.dns_ask("127.0.0.1", name, 16, timeout=1, port=srv.port), srv.names
        finally:
            srv.close()

    def test_txt_records(self):
        got, names = self.ask(lambda q: [txt_reply(q, ["13335 | 1.1.1.0/24 | AU | apnic | 2011-08-11"], split=True)])
        self.assertEqual(got, ["13335 | 1.1.1.0/24 | AU | apnic | 2011-08-11"])
        self.assertEqual(names, ["1.0.0.10.origin.asn.cymru.com"])
        self.assertEqual(self.ask(lambda q: [txt_reply(q, [], rcode=3)])[0], [])

    def test_a_still_works(self):
        from tests.test_v0461 import dns_reply
        srv = FakeServer(lambda q: [dns_reply(q, [127, 1, 1, 1])])
        try:
            self.assertEqual(app.dns_a("127.0.0.1", "x.example", timeout=1, port=srv.port), [127, 1, 1, 1])
        finally:
            srv.close()

    def test_bad_txt_length(self):
        def bad(q):
            r = txt_reply(q, ["abc"])
            return [r[:-4] + b"\x09" + r[-3:]]        # a character string longer than its record
        with self.assertRaises(OSError):
            self.ask(bad)


class Parse(unittest.TestCase):
    def test_names(self):
        self.assertEqual(app.nb_qname("203.0.113.10"), "10.113.0.203.origin.asn.cymru.com")
        n = app.nb_qname("2001:db8::9")
        self.assertTrue(n.endswith(".origin6.asn.cymru.com"))
        self.assertTrue(n.startswith("9.0.0.0."))
        self.assertEqual(n.count("."), 32 + 3)

    def test_most_specific_wins(self):
        n = app.nb_parse("203.0.113.10", ["64500 | 203.0.112.0/22 | NL | ripencc | 2015-01-01",
                                          "64501 64502 | 203.0.113.0/24 | DE | ripencc | 2024-03-05"])
        self.assertEqual(n, {"prefix": "203.0.113.0/24", "asn": "64501", "cc": "DE", "registry": "ripencc", "allocated": "2024-03-05"})

    def test_junk_is_dropped(self):
        self.assertIsNone(app.nb_parse("203.0.113.10", []))
        self.assertIsNone(app.nb_parse("203.0.113.10", ["64500 | 198.51.100.0/24 | US | arin | 2000-01-01"]))   # not holding the address
        self.assertIsNone(app.nb_parse("203.0.113.10", ["x | 203.0.113.0/24 | US"]))
        n = app.nb_parse("203.0.113.10", ["64500 | 203.0.113.0/24 | <b> | ev'il | 2020-13"])
        self.assertEqual((n["cc"], n["registry"], n["allocated"]), (None, None, None))

    def test_asname(self):
        self.assertEqual(app.nb_asname(["13335 | US | arin | 2010-07-14 | CLOUDFLARENET - Cloudflare, Inc., US"]),
                         "CLOUDFLARENET - Cloudflare, Inc., US")
        self.assertIsNone(app.nb_asname(["13335 | US"]))


class Lookup(unittest.TestCase):
    def setUp(self):
        self.con = app.connect()
        clean(self.con)
        now = time.time()
        with self.con:
            for i, ip in enumerate(IPS):
                self.con.execute("INSERT INTO ips(ip, first, last, score) VALUES(?,?,?,1)", (ip, now - 100, now - i))
        app.set_meta(self.con, "nb_dns", "9.9.9.9")

    def tearDown(self):
        clean(self.con)

    def fake(self, name):
        if name.startswith("AS"):
            return ["%s | DE | ripencc | 2001-01-01 | EXAMPLE-NET <script>" % name[2:7]]
        if name.endswith("113.0.203.origin.asn.cymru.com"):
            return ["64501 | 203.0.113.0/24 | DE | ripencc | 2024-03-05"]
        return []

    def run_lookup(self):
        asked = []

        def ask(server, name, qtype=1, *a, **k):
            asked.append((server, name, qtype))
            return self.fake(name)
        with mock.patch.object(app, "dns_ask", ask), mock.patch.object(app, "sendable_ip", lambda ip: True), mock.patch.object(app.time, "sleep"):
            done = app.nb_lookup(self.con)
        return done, asked

    def test_lookup_stores_blocks_and_owner(self):
        done, asked = self.run_lookup()
        self.assertEqual(done, 4)
        self.assertTrue(all(s == "9.9.9.9" and t == 16 for s, _n, t in asked))
        a = app.nb_get(self.con, "203.0.113.11")
        self.assertEqual((a["prefix"], a["asn"], a["cc"], a["allocated"]), ("203.0.113.0/24", "64501", "DE", "2024-03-05"))
        self.assertEqual(a["name"], "EXAMPLE-NET <script>")
        self.assertIsNone(app.nb_get(self.con, "198.51.100.40")["prefix"])          # not routed: stored, not asked again
        self.assertIn(("9.9.9.9", "AS64501.asn.cymru.com", 16), asked)
        # Nothing is asked again within 30 days.
        done, asked = self.run_lookup()
        self.assertEqual((done, asked), (0, []))
        # The page escapes the owner and counts the block.
        self.assertIn("2 attackers in this block", app.nb_html(self.con, a))
        self.assertNotIn("<script>", app.nb_owner_html(a))
        self.assertIn("allocated 2024-03-05", app.nb_owner_html(a))

    def test_off_and_errors(self):
        app.set_meta(self.con, "nb_on", "0")
        self.assertEqual(self.run_lookup(), (0, []))
        app.set_meta(self.con, "nb_on", "1")
        with mock.patch.object(app, "dns_ask", side_effect=OSError("no answer from DNS server 9.9.9.9")), \
                mock.patch.object(app, "sendable_ip", lambda ip: True):
            self.assertEqual(app.nb_lookup(self.con), 0)
        self.assertIn("no answer", app.get_meta(self.con, "nb_error"))
        self.assertGreater(float(app.get_meta(self.con, "nb_wait_until")), time.time())
        self.assertEqual(self.run_lookup(), (0, []))                                  # paused for an hour

    def test_private_addresses_never_sent(self):
        with mock.patch.object(app, "dns_ask") as d:
            app.nb_lookup(self.con)
        d.assert_not_called()                                                         # documentation ranges are not global

    def test_system_dns(self):
        with mock.patch("builtins.open", mock.mock_open(read_data="# x\nnameserver bad\nnameserver 192.0.2.53\n")):
            self.assertEqual(app.system_dns(), "192.0.2.53")
        with mock.patch("builtins.open", side_effect=OSError):
            self.assertIsNone(app.system_dns())


class Pages(SettingsKey):
    def setUp(self):
        self.con = app.connect()
        clean(self.con)
        now = time.time()
        with self.con:
            for ip in IPS[:2]:
                self.con.execute("INSERT INTO ips(ip, first, last, score, tags, sessions, logins_ok, logins_fail, cmds, files, tarpit_s) "
                                 "VALUES(?,?,?,1,'returned',0,0,0,0,0,0)", (ip, now - 100, now))
                self.con.execute("INSERT INTO netblock VALUES(?,?,?,?,?,?,?)", (ip, now, "203.0.113.0/24", "64501", "DE", "ripencc", "2024-03-05"))
            self.con.execute("INSERT INTO asname VALUES('64501', ?, 'EXAMPLE-NET')", (now,))

    def tearDown(self):
        clean(self.con)

    def get(self, path):
        return self.req("GET", path, headers={"Cookie": self.cookie})

    def test_attacker_page_list_and_campaigns(self):
        r, html = self.get("/ip/203.0.113.10")
        self.assertEqual(r.status, 200)
        self.assertIn("203.0.113.0/24", html)
        self.assertIn("2 attackers in this block", html)
        self.assertIn("EXAMPLE-NET", html)
        self.assertIn("Same netblock 203.0.113.0/24", html)
        self.assertNotIn("Same /24 network", html)
        r, html = self.get("/ips?" + urllib.parse.urlencode({"net": "203.0.113.0/24", "days": "all"}))
        self.assertEqual(r.status, 200)
        self.assertIn("Netblock 203.0.113.0/24", html)
        self.assertIn("203.0.113.11", html)
        self.assertNotIn("198.51.100.40", html)
        r, html = self.get("/ips?net=not-a-block&days=all")                        # ignored, not an error
        self.assertEqual(r.status, 200)
        r, html = self.get("/campaigns")
        self.assertIn("<h2>Netblocks</h2>", html)
        self.assertIn("EXAMPLE-NET", html)
        j = app.export_ip("203.0.113.10")["netblock"]
        self.assertEqual((j["prefix"], j["owner"], j["asn"]), ("203.0.113.0/24", "EXAMPLE-NET", "64501"))

    def test_gone_attacker_not_counted(self):
        # Codex 047 L2: a netblock row whose attacker is gone is neither counted nor listed.
        with self.con:
            self.con.execute("DELETE FROM ips WHERE ip=?", (IPS[1],))
        self.assertIn("only this attacker", app.nb_html(self.con, app.nb_get(self.con, IPS[0])))
        r, html = self.get("/ip/" + IPS[0])
        self.assertNotIn("Same netblock", html)

    def test_settings(self):
        r, html = self.get("/settings")
        self.assertIn('id="netblock"', html)
        h = self.hdr({"Cookie": self.cookie})
        r, _ = self.req("POST", "/settings/netblock", urllib.parse.urlencode({"dns": "1.1.1.1"}), h)
        self.assertEqual(r.status, 303)
        self.assertEqual((app.get_meta(self.con, "nb_on"), app.get_meta(self.con, "nb_dns")), ("0", "1.1.1.1"))
        r, _ = self.req("POST", "/settings/netblock", urllib.parse.urlencode({"dns": "evil;x", "on": "1"}), h)
        self.assertEqual(r.status, 400)
        with mock.patch.object(app, "system_dns", return_value=None):
            r, html = self.req("POST", "/settings/netblock", urllib.parse.urlencode({"dns": "system", "on": "1"}), h)
        self.assertEqual(r.status, 400)
        self.assertIn("no name server", html)
        r, _ = self.req("POST", "/settings/netblock", urllib.parse.urlencode({"dns": "system", "on": "1"}), h)
        self.assertEqual(r.status, 303)
        self.assertEqual(app.get_meta(self.con, "nb_on"), "1")


del SettingsKey


class CampaignTabs(unittest.TestCase):
    def test_tabs_and_panes(self):
        html = app.v_campaigns({})
        for k in ("scripts", "hassh", "netblocks", "web", "ids", "mail", "proxy", "slow"):
            self.assertIn('href="#c-%s" data-ctab="%s"' % (k, k), html)
            self.assertIn('id="c-%s" class="ctab-pane" data-cpane="%s"' % (k, k), html)
        self.assertIn("hgCtab", app.JS)
        self.assertNotIn(" style=", html)
