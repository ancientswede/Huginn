# The Search page: what it finds, how it treats special characters, and that log text stays harmless.
import json, time, unittest

from tests.helpers import app

NOW = time.time()
IP = "198.51.100.60"
SHA = "cd" * 32


def row(ip, kind, session, a=None, b=None, ago=10, n=0):
    ts = NOW - ago
    return ("s|%s|%s|%s|%s|%s|%d" % (ip, kind, session, a, b, n), ts, ip, "cowrie", kind, session, a, b)


class Search(unittest.TestCase):
    def setUp(self):
        app._local.h12 = False
        self.con = app.connect()
        with self.con:
            for t in ("events", "sessions", "ips", "seen", "files"):
                self.con.execute("DELETE FROM %s" % t)

    def find(self, q, **kw):
        return app.v_search(dict(q=q, **kw))

    def test_short_query_asks_for_more(self):
        self.assertIn("at least 3", self.find("ab"))
        self.assertIn("at least 3", self.find("  a "))

    def test_command_is_found_and_marked(self):
        app.store(self.con, [row(IP, "cmd", "s1", "wget http://203.0.113.9/x")])
        self.assertIn("<mark>203.0.113.9</mark>", self.find("203.0.113.9"))

    def test_case_does_not_matter(self):
        app.store(self.con, [row(IP, "cmd", "s1", "Wget http://example.org/a")])
        self.assertIn("<mark>Wget</mark>", self.find("wGET"))

    def test_variants_are_one_row_counting_every_attacker(self):
        app.store(self.con, [row("198.51.100.61", "cmd", "s1", "ping -c 1 203.0.113.1"), row("198.51.100.62", "cmd", "s2", "ping -c 9 203.0.113.2")])
        html = self.find("ping")
        self.assertEqual(html.count("<td class='mono wrap'>"), 1)
        self.assertRegex(html, r"Commands <span class=muted>1</span>")
        self.assertRegex(html, r"<td class='num nw'>2</td><td class='num nw'>2</td>")

    def test_percent_and_underscore_are_plain_characters(self):
        app.store(self.con, [row(IP, "cmd", "s1", "echo 100percent"), row(IP, "cmd", "s2", "echo a_b_c"), row(IP, "cmd", "s3", "echo axbxc")])
        self.assertIn("Nothing found", self.find("100%p"))
        html = self.find("a_b")
        self.assertIn("<mark>a_b</mark>", html)
        self.assertNotIn("axbxc", html)

    def test_backslash_is_a_plain_character(self):
        app.store(self.con, [row(IP, "cmd", "s1", r"echo \x41\x42")])
        self.assertIn("<mark>", self.find(r"\x41"))

    def test_file_by_hash_name_and_address_inside(self):
        app.store(self.con, [row(IP, "file", "s1", "/tmp/dropper", SHA)])
        with self.con:
            self.con.execute("INSERT INTO files(sha,src,size,type,arch,packed,iocs,mtime,updated) VALUES(?,?,?,?,?,?,?,?,?)",
                             (SHA, "download", 10, "ELF", "arm", 0, json.dumps(["http://c2.example.net/a"]), NOW, NOW))
        for q in (SHA[:12], "dropper", "c2.example"):
            self.assertIn("/campaign/file/" + SHA, self.find(q), q)
        self.assertIn("<mark>c2.example</mark>", self.find("c2.example"))

    def add_file(self, iocs, mtime=NOW):
        with self.con:
            self.con.execute("INSERT INTO files(sha,src,size,type,arch,packed,iocs,mtime,updated) VALUES(?,?,?,?,?,?,?,?,?)",
                             (SHA, "download", 10, "ELF", "arm", 0, json.dumps(iocs), mtime, NOW))

    def test_address_with_characters_json_would_escape(self):
        app.store(self.con, [row(IP, "file", "s1", "/tmp/a", SHA)])
        self.add_file(["http://例.example/path", 'http://example.org/a"b'])
        self.assertIn("/campaign/file/" + SHA, self.find("例.example"))
        self.assertIn("/campaign/file/" + SHA, self.find('a"b'))

    def test_two_names_do_not_join_into_a_match(self):
        app.store(self.con, [row(IP, "file", "s1", "abc", SHA), row(IP, "file", "s2", "def", SHA)])
        self.assertIn("Nothing found", self.find("abc,def"))
        self.assertIn("<mark>def</mark>", self.find("def"))

    def test_file_known_only_from_metadata(self):
        self.add_file(["http://c2.example.net/a"])
        html = self.find(SHA[:12])
        self.assertIn(SHA[:16], html)
        self.assertNotIn("/campaign/file/" + SHA, html)         # that page needs events

    def test_counts_are_complete_on_a_big_result(self):
        app.store(self.con, [row(IP, "cmd", "s", "echo needle%d" % i, n=i) for i in range(250)])
        self.assertRegex(self.find("needle"), r"<td class='num nw'>250</td>")

    def test_failed_download_and_decoy_data(self):
        app.store(self.con, [row(IP, "file_fail", "s1", "http://bad.example.net/x"), row(IP, "canary", None, "http", "GET /admin.php", n=1)])
        self.assertIn("Failed downloads", self.find("bad.example"))
        self.assertIn("Decoy services", self.find("admin.php"))

    def test_session_and_ip_by_start(self):
        app.store(self.con, [row(IP, "connect", "abcdef012345", "ssh", "2225")])
        self.assertIn("Sessions", self.find("abcdef"))
        self.assertIn("Attackers", self.find("198.51.100"))
        self.assertNotIn("Sessions <span", self.find("cdef012"))

    def test_time_limit(self):
        app.store(self.con, [row(IP, "cmd", "s1", "old command here", ago=20 * 86400)])
        self.assertIn("old command", self.find("old command"))
        self.assertIn("Nothing found", self.find("old command", days="7"))

    def test_odd_days_value_means_all(self):
        app.store(self.con, [row(IP, "cmd", "s1", "some command", ago=20 * 86400)])
        self.assertIn("some command", self.find("some command", days="<x>"))

    def test_long_result_says_how_much_is_shown(self):
        app.store(self.con, [row(IP, "canary", None, "http", "GET /needle", n=i, ago=i + 1) for i in range(app.SEARCH_ROWS + 3)])
        html = self.find("needle")
        self.assertIn("latest %d shown" % app.SEARCH_ROWS, html)
        self.assertIn(">%d</span> <span class=muted>latest" % (app.SEARCH_ROWS + 3), html)

    def test_nothing_is_unescaped(self):
        bad = "<img src=x onerror=alert(1)>"
        app.store(self.con, [row(IP, "cmd", "s1", bad), row(IP, "canary", None, bad, bad, n=1), row(IP, "file_fail", "s2", bad, n=2)])
        html = self.find("onerror")
        self.assertNotIn("<img src=x", html)
        self.assertNotRegex(html, r"\sstyle=")
        self.assertNotIn('"><script', self.find('"><script>alert(1)</script>'))

    def test_snippet_keeps_the_longest_match_whole(self):
        q = "a" * 200
        self.assertIn("<mark>%s</mark>" % q, app.snippet("x" * 100 + q, q))

    def test_snippet_shows_the_match_in_long_text(self):
        html = app.snippet("x" * 2000 + " needle " + "y" * 2000, "needle")
        self.assertIn("<mark>needle</mark>", html)
        self.assertLess(len(html), 400)
