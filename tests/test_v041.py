# 0.41 Goodbye on logout from Settings: hp-export "goodbye on|off", Huginn reads one line only.
import json, os, stat, subprocess, sys, tempfile, time, unittest
from unittest import mock

from tests.helpers import app, ROOT


def fake_ssh(script):
    # A stand-in for ssh: a tiny program that prints what the honeypot would.
    d = tempfile.mkdtemp()
    p = os.path.join(d, "fake")
    with open(p, "w") as f:
        f.write("#!/bin/sh\n" + script + "\n")
    os.chmod(p, stat.S_IRWXU)
    return lambda command: [p, command]


class Client(unittest.TestCase):
    def test_on_and_off(self):
        with mock.patch.object(app, "hp_ssh", fake_ssh('echo "goodbye on"')):
            self.assertEqual(app.hp_goodbye_set(True), (True, None))
        with mock.patch.object(app, "hp_ssh", fake_ssh('echo "goodbye off"')):
            self.assertEqual(app.hp_goodbye_set(False), (False, None))

    def test_old_honeypot_sends_the_export(self):
        # An old hp-export ignores the command and streams everything: read one line, stop, explain.
        with mock.patch.object(app, "hp_ssh", fake_ssh('echo "##COWRIE"; yes "{\\"eventid\\":\\"x\\"}" | head -c 50000000')):
            t = time.time()
            state, err = app.hp_goodbye_set(True)
        self.assertIsNone(state)
        self.assertIn("update-honeypot.sh", err)
        self.assertLess(time.time() - t, 10)

    def test_error_text(self):
        with mock.patch.object(app, "hp_ssh", fake_ssh('echo "refused: /etc/huginn-goodbye is a symlink" >&2; exit 2')):
            state, err = app.hp_goodbye_set(True)
        self.assertIsNone(state)
        self.assertIn("symlink", err)


class Card(unittest.TestCase):
    def setUp(self):
        self.con = app.connect()

    def tearDown(self):
        with self.con:
            self.con.execute("DELETE FROM meta WHERE k='hp_status'")

    def status(self, **items):
        with self.con:
            app.set_meta(self.con, "hp_status", json.dumps({"at": time.time(), "items": items}))

    def test_states(self):
        self.status(**{"patch:goodbye": True, "option:goodbye": False})
        html = app.honeypot_card()
        self.assertIn('action="/settings/goodbye"', html)
        self.assertIn("value=1><button>Turn on logout message</button>", html)
        self.status(**{"patch:goodbye": True, "option:goodbye": True})
        self.assertIn("Turn off logout message", app.honeypot_card())
        self.status(**{"patch:goodbye": False, "option:goodbye": False})
        html = app.honeypot_card()
        self.assertIn("Run update-honeypot.sh", html)
        self.assertNotIn("/settings/goodbye", html)


class Export(unittest.TestCase):
    def test_hp_export_accepts_only_the_two_words(self):
        # The case statement: "goodbye on|off" exactly; anything else is the normal export (never a command).
        src = open(os.path.join(ROOT, "honeypot", "hp-export")).read()
        self.assertIn('"goodbye on"|"goodbye off")', src)
        self.assertIn('[ ! -L "$f" ] || { echo "refused', src)
        self.assertIn("*) ;;  # any other command gets the normal export", src)


if __name__ == "__main__":
    unittest.main()


class ScopedSave(unittest.TestCase):
    # 0.41 Settings: each form saves only its own part (Codex review: a partial form must never reset the others).
    def setUp(self):
        self.con = app.connect()
        self.before = app.get_meta(self.con, "settings", "")
        with self.con:
            app.set_meta(self.con, "settings", json.dumps(dict(app.SETTINGS_DEFAULT, notify=True, overview="board", title="Mine",
                                                               cards=["hero", "top"], notify_events=["bait"])))

    def tearDown(self):
        with self.con:
            app.set_meta(self.con, "settings", self.before)

    def test_appearance_keeps_views_and_notifications(self):
        self.assertTrue(app.save_settings({"scope": "appearance", "theme": "dark", "title": "", "notify": "0"}, {}))
        st = app.settings()
        self.assertEqual((st["theme"], st["title"]), ("dark", "Huginn"))        # empty title -> default, as before
        self.assertEqual((st["cards"], st["notify"], st["notify_events"], st["overview"]), (["hero", "top"], True, ["bait"], "board"))

    def test_views_empty_lists_only_touch_views(self):
        self.assertTrue(app.save_settings({"scope": "views", "hidden_nets": "cn as14061"}, {}))
        st = app.settings()
        self.assertEqual((st["cards"], st["ips_cols"], st["hide_cc"], st["hide_asn"]), ([], [], ["CN"], ["14061"]))
        self.assertEqual((st["title"], st["notify"], st["notify_events"]), ("Mine", True, ["bait"]))

    def test_notifications_only(self):
        self.assertTrue(app.save_settings({"scope": "notifications"}, {"notify_events": ["files", "nope"]}))
        st = app.settings()
        self.assertEqual((st["notify"], st["notify_events"]), (False, ["files"]))
        self.assertEqual((st["title"], st["cards"]), ("Mine", ["hero", "top"]))

    def test_unknown_scope_saves_nothing(self):
        self.assertFalse(app.save_settings({"scope": "everything", "theme": "light", "title": "X"}, {}))
        self.assertEqual(app.settings()["title"], "Mine")

    def test_redirect_targets(self):
        self.assertEqual(app.settings_url("views"), "/settings?ok=views#views")
        self.assertEqual(app.settings_url("vtdel"), "/settings?ok=vtdel#virustotal")
        self.assertEqual(app.settings_url("1"), "/settings?ok=1")
        self.assertEqual(app.settings_url("<x>"), "/settings?ok=%3Cx%3E")

    def test_messages_land_in_their_section(self):
        html = app.v_settings(ok="views")
        i = html.index('id="views"')
        self.assertGreater(html.index("Views &amp; defaults saved."), i)
        self.assertLess(html.index("Views &amp; defaults saved."), html.index('id="notifications"'))
        html = app.v_settings(at="greynoise", err="GreyNoise refused <that> key.")
        self.assertIn("GreyNoise refused &lt;that&gt; key.", html)
        self.assertGreater(html.index("GreyNoise refused"), html.index('id="greynoise"'))
        self.assertIn("buymeacoffee.com/ancientswede", html)
        self.assertIn("Buy me a coffee", app.footer())


class ReviewFixes(unittest.TestCase):
    # Codex review of the rebuilt Settings (huginn-settings-ui/SVAR-2.md).
    def setUp(self):
        self.con = app.connect()

    def tearDown(self):
        with self.con:
            for k in ("metrics_token", "metrics_on"):
                self.con.execute("DELETE FROM meta WHERE k=?", (k,))

    def test_metrics_token_not_in_page(self):
        with self.con:
            app.set_meta(self.con, "metrics_token", "tok-SECRET-1234567890abcdef")
            app.set_meta(self.con, "metrics_on", "1")
        html = app.v_settings()
        self.assertNotIn("tok-SECRET-1234567890abcdef", html)
        self.assertIn('data-copy-url="/settings/metrics/copy?what=token"', html)
        self.assertIn("••••cdef", html)
        self.assertIn("credentials: tok-SECRET", app.metrics_job("http://h:8095", "tok-SECRET-1234567890abcdef"))

    def test_ntfy_destination_never_shows_userinfo(self):
        with mock.patch.object(app, "NTFY_URL", "https://user:pa55word@ntfy.example:8443/topic"):
            html = app.v_settings()
        self.assertIn("ntfy.example:8443", html)
        self.assertNotIn("pa55word", html)
        self.assertNotIn("user:", html)

    def test_key_error_once_with_link_and_aria(self):
        html = app.v_settings(at="virustotal", err="VirusTotal refused that key.")
        self.assertEqual(html.count("VirusTotal refused that key."), 1)
        self.assertIn('<a href="#err-virustotal">See VirusTotal</a>', html)
        self.assertIn('id="err-virustotal"', html)
        self.assertIn('aria-invalid=true aria-describedby="err-virustotal"', html)

    def test_client_refuses_the_wrong_state(self):
        with mock.patch.object(app, "hp_ssh", fake_ssh('echo "goodbye off"')):
            state, err = app.hp_goodbye_set(True)
        self.assertIsNone(state)
        self.assertIn("still off", err)

    def test_hp_export_checks_its_work(self):
        src = open(os.path.join(ROOT, "honeypot", "hp-export")).read()
        self.assertIn('|| { echo "could not create $f" >&2; exit 2; }', src)
        self.assertIn('[ "$now" = "$want" ] || { echo "goodbye is still $now" >&2; exit 2; }', src)

    def test_settings_css_stays_under_sp(self):
        import re
        s = open(os.path.join(ROOT, "app.py")).read()
        block = s[s.index("# 0.41 Settings page (Codex proposal"):s.index("# 0.28: wide screens (2K)")]
        css = "".join(re.findall(r'"((?:[^"\\]|\\.)*)"', block))
        bad = [p.strip() for sel in re.findall(r'(?:^|})\s*([^{}@]+)\{', css) for p in sel.split(",")
               if p.strip() and not re.match(r"(\.sp( |\{|$)|html\[data-density=compact\] \.sp|html\[data-theme=dark\] \.sp |html:not\(\[data-theme=light\]\) \.sp )", p.strip())]
        self.assertEqual(bad, [])


class GoodbyeStats(unittest.TestCase):
    def setUp(self):
        self.con = app.connect()
        self.clean()

    def tearDown(self):
        self.clean()

    def clean(self):
        with self.con:
            self.con.execute("DELETE FROM events WHERE kind='goodbye'")

    def test_counts(self):
        self.assertIn("Not shown to anyone yet.", app.goodbye_stats(self.con))
        now = time.time()
        with self.con:
            for i, (ip, age) in enumerate((("203.0.113.1", 60), ("203.0.113.1", 3600), ("203.0.113.2", 10 * 86400))):
                self.con.execute("INSERT INTO events(h, ts, ip, src, kind, session, a) VALUES(?,?,?,?,?,?,?)",
                                 ("gb%d" % i, now - age, ip, "cowrie", "goodbye", "gbs%d" % i, "9 s, 2 lines typed"))
        text = app.goodbye_stats(self.con)
        self.assertIn("Shown 3 times to 2 addresses · 2 in the last 7 days", text)
