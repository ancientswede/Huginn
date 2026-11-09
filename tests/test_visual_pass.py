# The 0.22 visual pass: what the pages promise, not how they look.
import re, time, unittest
import unittest.mock

from tests.helpers import app

NOW = time.time()
IP = "198.51.100.60"


def rows_for(sid, cmds, ip=IP, port="2225"):
    rows = [(ip, "connect", sid, "ssh", port), (ip, "login_ok", sid, "root", "pw")]
    rows += [(ip, "cmd", sid, c, None) for c in cmds]
    rows.append((ip, "closed", sid, "4.0", None))
    return [("v|%s|%d" % (sid, i), NOW - 500 + i, r[0], "cowrie", r[1], r[2], r[3], r[4]) for i, r in enumerate(rows)]


class VisualPass(unittest.TestCase):
    def setUp(self):
        self.con = app.connect()
        with self.con:
            for t in ("events", "sessions", "ips", "seen", "enrich", "flags"):
                self.con.execute("DELETE FROM %s" % t)
            self.con.execute("DELETE FROM meta WHERE k='settings'")
        app._persona_cache.clear()
        app._local.h12 = False

    def add(self, *batches):
        rows = []
        for b in batches:
            rows += b
        app.store(self.con, rows)

    def many_ips(self, n):
        with self.con:
            for i in range(n):
                self.con.execute("INSERT INTO ips(ip,first,last,sessions,logins_ok,logins_fail,cmds,files,tcpip,exploits,score,tags) "
                                 "VALUES(?,?,?,1,0,0,0,0,0,0,3,'')", ("203.0.113.%d" % (i + 1), NOW - 100, NOW - i))

    def test_ip_heading_is_the_address(self):
        self.add(rows_for("a", ["uname -a"]))
        self.assertIn('<h1 class="ip-title mono">%s</h1>' % IP, app.v_ip(IP))

    def test_scripts_lead_with_commands(self):
        self.add(rows_for("a", ["uname -s -m", "nproc", "free -m"]))
        html = app.v_campaigns()
        self.assertRegex(html, r'class="scr mono"[^>]*>uname -s -m ; nproc<')
        self.assertIn('class="hash mono muted"', html)
        self.assertNotIn("First command", html)

    def test_script_cell_escapes_attacker_text(self):
        html = app.script_cell("ab" * 8, ["<img src=x>"])
        self.assertNotIn("<img", html)
        self.assertNotIn("href", app.script_cell("not-a-hash", ["id"]))

    def test_page_size(self):
        self.many_ips(60)
        count = lambda h: len(re.findall(r'<a class="mono" href="/ip/', h))
        self.assertEqual(count(app.v_ips({"days": "all"})), 60)
        self.assertEqual(count(app.v_ips({"days": "all"}, mobile=True)), 25)
        self.assertEqual(count(app.v_ips({"days": "all", "n": "50"}, mobile=True)), 50)
        self.assertEqual(count(app.v_ips({"days": "all", "n": "7"}, mobile=True)), 25)      # only the offered sizes

    def test_second_page_follows_the_size(self):
        self.many_ips(60)
        first = app.v_ips({"days": "all", "n": "25"})
        second = app.v_ips({"days": "all", "n": "25", "p": "1"})
        ips = lambda h: set(re.findall(r'<a class="mono" href="/ip/([^"]+)"', h))
        self.assertFalse(ips(first) & ips(second))
        self.assertEqual(first.count('class="pager'), 2)                                    # above and below the list
        self.assertIn("n=25", first)

    def test_personas_bar_matches_the_numbers(self):
        self.add(rows_for("a", ["id"]), rows_for("b", []), rows_for("c", ["id", "w"]))
        html = app.v_personas()
        self.assertIn('class="dist"', html)
        for label in ("No command", "One line", "Stopped short", "Went for payload"):
            self.assertIn(label, html)
        self.assertNotRegex(html, r"\sstyle=")

    def test_empty_sections_draw_no_table(self):
        for html in (app.v_personas(), app.v_campaigns(), app.v_files()):
            self.assertNotIn("<thead>", html)
            self.assertIn('class="empty muted"', html)

    def test_raven_data_grows_with_finds(self):
        html = app.page("x", "")
        self.assertRegex(html, r"id=brand data-file='0(\.0)?' data-took='0' data-read='0'")
        with self.con:
            self.con.execute("INSERT INTO ips(ip,first,last,sessions,logins_ok,logins_fail,cmds,files,tcpip,exploits,score,tags) "
                             "VALUES(?,?,?,1,0,0,0,0,0,0,3,'shell,took-bait')", (IP, NOW, NOW))
        self.assertIn("data-took='1'", app.page("x", ""))

    def test_receipt_empty(self):
        self.assertIn("Nothing to bill yet", app.v_receipt({}))

    def test_receipt_adds_up(self):
        rows = [("t|%d" % i, NOW - 50 - i, IP, "endlessh", "tarpit", None, str(3600 * (i + 1)), "4000%d" % i) for i in range(2)]
        app.store(self.con, rows)
        html = app.v_receipt({"days": "7"})
        self.assertIn("3h 0m", html)                                                        # 1 h + 2 h
        self.assertIn("2h 0m", html)                                                        # the longest
        self.assertIn("Feature films", html)
        self.assertNotRegex(html, r"\sstyle=")

    def test_receipt_rejects_other_periods(self):
        with unittest.mock.patch.object(app, "DEMO", False):
            self.assertIn('class="chip on" href="/receipt?days=7"', app.v_receipt({"days": "<x>"}))

    def test_receipt_longest_covers_hidden_rows_without_naming_them(self):
        hidden, shown = "198.51.100.61", "198.51.100.62"
        app.store(self.con, [("h|1", NOW - 60, hidden, "endlessh", "tarpit", None, "7200", "40001"), ("h|2", NOW - 50, shown, "endlessh", "tarpit", None, "600", "40002")])
        with self.con:
            self.con.execute("INSERT OR REPLACE INTO enrich(ip,cc) VALUES(?,'XX')", (hidden,))
            self.con.execute("INSERT OR REPLACE INTO meta(k,v) VALUES('settings',?)", ('{"hide_cc":["XX"]}',))
        html = app.v_receipt({"days": "7"})
        self.assertIn("2h 0m", html)
        self.assertNotIn(hidden, html)
        self.assertNotIn(">Guest<", html)

    def test_one_stop_is_not_called_none(self):
        self.add(rows_for("a", ["id", "w"]))
        self.assertIn("No repeated stopping points yet", app.v_personas())

    def test_page_past_the_end_shows_the_last_one(self):
        self.many_ips(60)
        for p in ("9", "9223372036854775807", "99999999999999999999999"):
            self.assertIn("51–60 of 60", app.v_ips({"days": "all", "n": "25", "p": p}))

    def test_worth(self):
        self.assertIsNone(app.receipt_worth(60))
        self.assertEqual(app.receipt_worth(900)[0], "Coffee breaks")
        self.assertEqual(app.receipt_worth(7200)[0], "Feature films")
        self.assertEqual(app.receipt_worth(558 * 60)[0], "Lord of the Rings trilogies")


if __name__ == "__main__":
    unittest.main()
