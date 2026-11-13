# 0.30 The attacker page folds repeated sessions and filters them; the honeypot reports its protection and Huginn alerts
# when a sandbox, a limit, a patch or a service is missing.
import json, time, unittest
from unittest import mock

from tests.helpers import app

IP = "198.51.100.181"
NOW = time.time()


class Sessions(unittest.TestCase):
    def setUp(self):
        self.con = app.connect()
        self.clean()
        rows = []
        add = lambda sid, start, cmds=0, lo=0, lf=0, h=None: rows.append((sid, IP, start, start + 5, "ssh", 2225, "SSH-2.0-Go", None, 5,
                                                                         lo, lf, cmds, 0, 0, 0, h))
        for i in range(3):
            add("scr%05d" % i, NOW - 3600 * (i + 1), cmds=2, lo=1, h="a" * 16)
        add("one00001", NOW - 100, cmds=4, lo=1, h="b" * 16)
        for i in range(5):
            add("con%05d" % i, NOW - 7200 - i)
        for i in range(2):
            add("log%05d" % i, NOW - 9000 - i, lf=3)
        with self.con:
            self.con.executemany("INSERT INTO sessions(session, ip, start, end, proto, port, version, hassh, duration, logins_ok, logins_fail, "
                                 "cmds, files, tcpip, exploits, cmdhash) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", rows)
            app.recompute_ip(self.con, IP)

    def tearDown(self):
        self.clean()

    def clean(self):
        with self.con:
            for t in ("events", "sessions", "ips"):
                self.con.execute("DELETE FROM %s" % t)

    def test_fold_and_filter(self):
        page = app.v_ip(IP)
        self.assertIn("×3 like this", page)
        self.assertIn("Show 2 more like this", page)
        self.assertIn("5 sessions only connected", page)
        self.assertIn("2 sessions tried to log in, nothing more", page)
        self.assertIn('All <span class=muted>11</span>', page)
        self.assertIn('With commands <span class=muted>4</span>', page)
        self.assertIn('With logins <span class=muted>6</span>', page)
        self.assertLess(page.index('id="s-one00001"'), page.index('id="s-scr00000"'))     # newest busy session first
        self.assertEqual(page.count('id="s-con00000"'), 1)                                # every session still reachable once
        cmds = app.v_ip(IP, {"s": "cmds"})
        self.assertNotIn("only connected", cmds)
        self.assertNotIn('id="s-log00000"', cmds)
        self.assertIn('class="chip on" href="/ip/%s?s=cmds#sessions"' % IP, cmds)
        logins = app.v_ip(IP, {"s": "logins"})
        self.assertIn("tried to log in", logins)
        self.assertNotIn("only connected", logins)
        self.assertIn('class="chip on" href="/ip/%s#sessions"' % IP, app.v_ip(IP, {"s": "<script>"}))   # unknown filter: all


class Protection(unittest.TestCase):
    def setUp(self):
        self.con = app.connect()
        with self.con:
            self.con.execute("DELETE FROM meta WHERE k IN ('hp_status','health_alerted','health_now','last_success')")

    def export(self, status):
        text = "##COWRIE\n##CANARY\n" + (("##STATUS\n" + "\n".join(status) + "\n") if status is not None else "") + "##FILES\n##END\n"
        app.parse_export(text, set())
        app.apply_honeypot_meta(self.con, app.parse_export.meta)

    def test_parse_is_strict(self):
        got = app.parse_status(["sandbox:cowrie ok", "patch:wget missing", "patch:x ok; rm -rf /", "evil:cowrie ok", "running:<b> ok", "limits:opencanary ok"])
        self.assertEqual(got, {"sandbox:cowrie": True, "patch:wget": False, "limits:opencanary": True})

    def test_note_and_alerts(self):
        self.assertIn("not reported", app.protection_note(self.con))
        good = ["sandbox:cowrie ok", "limits:cowrie ok", "running:cowrie ok", "patch:ping ok", "patch:exec ok"]
        self.export(good)
        self.assertIn("all in place: sandbox and limits on 1 services, 2 patches", app.protection_note(self.con))
        sent = []
        post = lambda body, title, prio=3: sent.append((title, body))
        with mock.patch.object(app, "NTFY_URL", "http://ntfy.invalid/x"), mock.patch.object(app, "ntfy_post", post):
            self.assertEqual(app.health_check(self.con), {})
            self.export(good[:1] + ["limits:cowrie missing"] + good[2:])
            issues = app.health_check(self.con)
            self.assertEqual(list(issues), ["prot:limits:cowrie"])
            self.assertIn("cowrie memory/file limits", sent[-1][1])
            self.export(good[:1] + ["limits:cowrie missing", "running:cowrie missing"] + good[3:])
            app.health_check(self.con)
            self.assertIn("cowrie not running", sent[-1][1])                  # a second loss alerts again
            self.assertEqual(len(sent), 2)
            self.export(good)
            app.health_check(self.con)
            self.assertEqual(sent[-1][0], "Huginn: collection is back")
        self.assertIn("all in place", app.protection_note(self.con))
        self.export(None)                                                     # an older honeypot: the last report stays
        self.assertIn("all in place", app.protection_note(self.con))

    def test_old_report_is_not_an_alarm(self):
        with self.con:
            app.set_meta(self.con, "hp_status", json.dumps({"at": NOW - 7200, "items": {"patch:wget": False}}))
        self.assertEqual(app.protection_missing(self.con), [])


if __name__ == "__main__":
    unittest.main()
