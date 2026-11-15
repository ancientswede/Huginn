# 0.43 Optional Suricata IDS on the honeypot: export filter, parsing, counting, score and pages.
import json, os, re, subprocess, time, unittest
from datetime import datetime, timezone

from tests.helpers import ROOT, app


def t(ago=60):
    return datetime.fromtimestamp(time.time() - ago, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f+0000")


def alert(**kw):
    a = {"t": t(), "ip": "203.0.113.71", "port": 80, "proto": "TCP", "sid": 2025883, "rev": 6, "sev": 1,
         "sig": "ET EXPLOIT MVPower DVR Shell UCE", "cat": "Attempted Administrator Privilege Gain"}
    a.update(kw)
    return json.dumps(a)


def export(*lines, rules="1794756836"):
    return "##COWRIE\n##IDS\n" + "\n".join(lines) + ("\nrules %s" % rules if rules else "") + "\n##END\n"


def cowrie(ip, sid="v43a"):
    ev = {"eventid": "cowrie.login.failed", "src_ip": ip, "timestamp": t(30).replace("+0000", "Z"), "session": sid, "username": "root", "password": "x"}
    return json.dumps(ev)


class Parse(unittest.TestCase):
    def test_good_alert(self):
        rows, _h = app.parse_export(export(alert()), set())
        self.assertEqual(rows, [])
        (h, ts, ip, sid, sev, sig, cat, proto, port), = app.parse_export.ids
        self.assertTrue(h.startswith("ids:"))
        self.assertEqual((ip, sid, sev, proto, port), ("203.0.113.71", 2025883, 1, "TCP", 80))
        self.assertAlmostEqual(ts, time.time() - 60, delta=5)
        self.assertTrue(app.parse_export.meta["has_ids"])
        self.assertEqual(app.parse_export.meta["ids_rules"], 1794756836)

    def test_bad_alerts_dropped(self):
        bad = [alert(ip="10.0.0.1"), alert(ip="x"), alert(sid=0), alert(sid="2x"), alert(sig="two\nlines"), alert(sig="å"),
               alert(sig=""), alert(sig=None), alert(t=t(20 * 86400)), alert(t="tomorrow"), "{not json", "[1]"]
        app.parse_export(export(*bad), set())
        self.assertEqual(app.parse_export.ids, [])

    def test_fields_cleaned(self):
        app.parse_export(export(alert(sev=9, port=True, proto="TCP; drop", cat="x" * 300)), set())
        (_h, _ts, _ip, _sid, sev, _sig, cat, proto, port), = app.parse_export.ids
        self.assertEqual((sev, port, proto, cat), (3, 0, "", ""))

    def test_seen_lines_skipped(self):
        line = alert()
        _r, hashes = app.parse_export(export(line), set())
        app.parse_export(export(line), hashes)
        self.assertEqual(app.parse_export.ids, [])

    def test_no_section_is_off(self):
        app.parse_export("##COWRIE\n##END\n", set())
        self.assertFalse(app.parse_export.meta["has_ids"])
        self.assertIsNone(app.parse_export.meta["ids_rules"])


class Store(unittest.TestCase):
    def setUp(self):
        self.con = app.connect()

    @classmethod
    def tearDownClass(cls):
        # The test database is shared: leave no IDS rows behind for tests that expect empty pages.
        con = app.connect()
        with con:
            for t in ("ids", "ids_seen"):
                con.execute("DELETE FROM %s" % t)
            con.execute("DELETE FROM meta WHERE k IN ('hp_ids', 'hp_status')")

    def sync(self, *lines):
        rows, _h = app.parse_export(export(*lines), set())
        app.apply_honeypot_meta(self.con, app.parse_export.meta)
        app.store(self.con, rows)
        return app.store_ids(self.con, app.parse_export.ids)

    def test_counted_per_day_once(self):
        a, b = alert(ip="203.0.113.72", t=t(100)), alert(ip="203.0.113.72", t=t(50))
        self.assertEqual(self.sync(a, b), 2)
        self.assertEqual(self.sync(a, b), 0)              # the export sends the same lines again: not counted twice
        r = self.con.execute("SELECT n, sev, port FROM ids WHERE ip='203.0.113.72'").fetchone()
        self.assertEqual(tuple(r), (2, 1, 80))

    def test_ports_kept_and_worst_severity(self):
        ip = "203.0.113.77"
        self.sync(alert(ip=ip, port=80, t=t(300)), alert(ip=ip, port=8080, t=t(200)), alert(ip=ip, port=80, sev=2, t=t(100)), alert(ip=ip, port=None, proto="ICMP", t=t(90)))
        self.sync(alert(ip=ip, port=53, proto="UDP", t=t(80)), alert(ip=ip, port=53, proto="TCP", t=t(70)))
        rows = {(r["proto"], r["port"]): (r["n"], r["sev"]) for r in self.con.execute("SELECT * FROM ids WHERE ip=?", (ip,))}
        self.assertEqual(rows, {("TCP", 80): (2, 1), ("TCP", 8080): (1, 1), ("ICMP", 0): (1, 1), ("UDP", 53): (1, 1), ("TCP", 53): (1, 1)})
        self.assertEqual(app.ids_ports("TCP/80,TCP/8080,ICMP/0"), "ICMP, TCP/80, TCP/8080")

    def test_same_looking_alerts_both_count(self):
        # Two connections in the same microsecond look alike after the export's cut; "h" keeps them apart.
        self.assertEqual(self.sync(alert(ip="203.0.113.78", h="a" * 20), alert(ip="203.0.113.78", h="b" * 20)), 2)

    def test_rules_line_outside_the_window(self):
        lines = [alert(ip="203.0.113.79", t=t(10 + i), h="%020d" % i) for i in range(20000)]
        app.parse_export(export(*lines + ["dropped 7"]), set())
        self.assertEqual(len(app.parse_export.ids), 20000)
        self.assertEqual(app.parse_export.meta["ids_rules"], 1794756836)
        self.assertEqual(app.parse_export.meta["ids_dropped"], 7)

    def test_score_and_tag(self):
        ip = "203.0.113.73"
        rows, _h = app.parse_export("##COWRIE\n" + cowrie(ip, "v43b") + "\n##END\n", set())
        app.store(self.con, rows)
        before = self.con.execute("SELECT score, tags FROM ips WHERE ip=?", (ip,)).fetchone()
        self.sync(alert(ip=ip, sev=3, sid=2031502, sig="ET INFO Request to Hidden Environment File - Inbound"),
                  alert(ip=ip, sev=2, sid=2001219, sig="ET SCAN Potential SSH Scan"))
        mid = self.con.execute("SELECT score, tags FROM ips WHERE ip=?", (ip,)).fetchone()
        self.assertEqual(tuple(mid), tuple(before))         # scans and information: described, not scored
        self.sync(alert(ip=ip))
        after = self.con.execute("SELECT score, tags FROM ips WHERE ip=?", (ip,)).fetchone()
        self.assertEqual(after["score"], before["score"] + 3)
        self.assertIn("ids-alert", after["tags"].split(","))
        r = self.con.execute("SELECT * FROM ips WHERE ip=?", (ip,)).fetchone()
        self.assertNotIn("unavailable", app.score_html(r))
        self.assertIn("IDS alert 3", app.score_html(r))

    def test_unknown_ip_not_added(self):
        self.sync(alert(ip="203.0.113.74"))
        self.assertIsNone(self.con.execute("SELECT 1 FROM ips WHERE ip='203.0.113.74'").fetchone())
        self.assertIsNotNone(self.con.execute("SELECT 1 FROM ids WHERE ip='203.0.113.74'").fetchone())

    def test_pages(self):
        ip = "203.0.113.75"
        rows, _h = app.parse_export("##COWRIE\n" + cowrie(ip, "v43c") + "\n##END\n", set())
        app.store(self.con, rows)
        self.sync(alert(ip=ip, sid=2099001, sig="ET TEST <script>alert(1)</script> CVE-2016-20016"), alert(ip="203.0.113.76", sid=2099001, sig="ET TEST <script>alert(1)</script> CVE-2016-20016"))
        html = app.v_ip(ip)
        self.assertIn("IDS alerts", html)
        self.assertIn('href="/campaign/ids/2099001"', html)
        self.assertNotIn("<script>alert(1)", html)
        page = app.v_campaign("ids", "2099001")
        self.assertIn("CVE-2016-20016", page)
        self.assertIn('href="/ip/%s"' % ip, page)                 # known attacker: a link
        self.assertNotIn('href="/ip/203.0.113.76"', page)         # only seen by Suricata: no page to link to
        self.assertIsNone(app.v_campaign("ids", "1"))
        camp = app.v_campaigns()
        self.assertIn("<h2>IDS alerts</h2>", camp)
        self.assertIn("/campaign/ids/2099001", camp)
        data = app.export_ip(ip)
        self.assertEqual(data["ids_alerts"][0]["sid"], 2099001)

    def test_settings_card(self):
        app.set_meta(self.con, "hp_ids", json.dumps({"on": False}))
        self.assertIn("--suricata-on", app.ids_card())
        self.assertIn("--suricata-on", app.v_campaigns() if not self.con.execute("SELECT 1 FROM ids").fetchone() else "--suricata-on")
        app.set_meta(self.con, "hp_ids", json.dumps({"on": True, "rules": time.time() - 3600}))
        app.set_meta(self.con, "hp_status", json.dumps({"at": time.time(), "items": {"running:suricata": True}}))
        html = app.ids_card()
        self.assertIn("rules updated 60m ago", html)
        self.assertIn('sp-status on', html)
        app.set_meta(self.con, "hp_status", json.dumps({"at": time.time(), "items": {"running:suricata": False}}))
        self.assertIn("Not running", app.ids_card())
        app.set_meta(self.con, "hp_ids", json.dumps({"on": True, "rules": time.time(), "dropped": 1234}))
        self.assertIn("more alerts than one sync takes", app.ids_card())
        self.assertIn("running:suricata", app.protection_missing(self.con))

    def test_retention_forgets_old_seen(self):
        self.con.execute("INSERT OR IGNORE INTO ids_seen(h, ts) VALUES('ids:old', ?)", (time.time() - 30 * 86400,))
        self.con.commit()
        app.retention(self.con)
        self.assertIsNone(self.con.execute("SELECT 1 FROM ids_seen WHERE h='ids:old'").fetchone())


class Export(unittest.TestCase):
    # hp-export's filter: only alerts on traffic TO the honeypot, as a few fixed fields.
    def filter_code(self):
        src = open(os.path.join(ROOT, "honeypot", "hp-export")).read()
        return re.search(r"\| python3 -I -c '(.*?)' \"\$\(hostname -I", src, re.S).group(1)

    def run_filter(self, lines, own="192.0.2.10 2001:db8::10"):
        out = subprocess.run(["python3", "-I", "-c", self.filter_code(), own], input="\n".join(lines).encode(), capture_output=True, check=True)
        self.meta = [x for x in out.stdout.decode().splitlines() if not x.startswith("{")]
        return [json.loads(x) for x in out.stdout.decode().splitlines() if x.startswith("{")]

    def eve(self, src, dst, **kw):
        e = {"timestamp": "2026-11-15T15:41:30.685627+0000", "event_type": "alert", "src_ip": src, "dest_ip": dst, "src_port": 4444,
             "dest_port": 80, "proto": "TCP", "payload": "SECRET", "http": {"url": "/x"},
             "alert": {"signature_id": 1, "rev": 2, "severity": 1, "signature": "ET X", "category": "Y", "metadata": {"a": ["b"]}}}
        e.update(kw)
        return json.dumps(e)

    def test_filter(self):
        got = self.run_filter([self.eve("203.0.113.9", "192.0.2.10"), self.eve("192.0.2.10", "203.0.113.9"),
                               self.eve("203.0.113.9", "192.0.2.99"), self.eve("203.0.113.9", "192.0.2.10", event_type="flow"),
                               "garbage", json.dumps({"event_type": "alert"}), self.eve("203.0.113.9", "2001:db8::10")])
        self.assertEqual(len(got), 2)
        self.assertEqual(set(got[0]), {"t", "ip", "port", "proto", "sid", "rev", "sev", "sig", "cat", "h"})
        self.assertEqual(got[0]["ip"], "203.0.113.9")
        self.assertNotIn("SECRET", json.dumps(got))
        # Another way of writing the same IPv6 address is still this machine.
        self.assertEqual(len(self.run_filter([self.eve("203.0.113.9", "2001:0db8:0:0::10")])), 1)
        # Reply alerts are dropped BEFORE the newest-20000 cut, so they cannot push real ones out.
        many = [self.eve("192.0.2.10", "203.0.113.9")] * 25000
        self.assertEqual(len(self.run_filter([self.eve("203.0.113.9", "192.0.2.10")] + many)), 1)
        self.assertEqual(self.meta, [])
        # More real alerts than one sync takes: the newest 20000, and how many were left out.
        got = self.run_filter([self.eve("203.0.113.9", "192.0.2.10", src_port=i) for i in range(20005)])
        self.assertEqual((len(got), self.meta), (20000, ["dropped 5"]))

    def test_scripts_parse(self):
        for f in ("honeypot/setup-suricata.sh", "honeypot/hp-export", "update-honeypot.sh", "install-honeypot.sh", "uninstall-honeypot.sh"):
            subprocess.run(["bash", "-n", os.path.join(ROOT, f)], check=True)


if __name__ == "__main__":
    unittest.main()
