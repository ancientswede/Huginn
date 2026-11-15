# 0.44 Suricata on and off from Settings: hp-export "ids on|off", only for a Suricata already set up on the honeypot.
import json, os, time, unittest
from unittest import mock

from tests.helpers import app, ROOT
from tests.test_v041 import fake_ssh


class Client(unittest.TestCase):
    def test_on_and_off(self):
        with mock.patch.object(app, "hp_ssh", fake_ssh('echo "ids on"')):
            self.assertEqual(app.hp_ids_set(True), (True, None))
        with mock.patch.object(app, "hp_ssh", fake_ssh('echo "ids off"')):
            self.assertEqual(app.hp_ids_set(False), (False, None))

    def test_wrong_word_or_state_refused(self):
        with mock.patch.object(app, "hp_ssh", fake_ssh('echo "goodbye on"')):
            self.assertIsNone(app.hp_ids_set(True)[0])
        with mock.patch.object(app, "hp_ssh", fake_ssh('echo "ids off"')):
            state, err = app.hp_ids_set(True)
        self.assertIsNone(state)
        self.assertIn("still off", err)

    def test_not_set_up_and_old_honeypot(self):
        with mock.patch.object(app, "hp_ssh", fake_ssh('echo "Suricata is not set up on the honeypot: run ./update-honeypot.sh --suricata-on there once" >&2; exit 2')):
            self.assertIn("--suricata-on", app.hp_ids_set(True)[1])
        with mock.patch.object(app, "hp_ssh", fake_ssh('echo "##COWRIE"')):
            self.assertIn("0.44", app.hp_ids_set(True)[1])
        with mock.patch.object(app, "hp_ssh", fake_ssh('echo "goodbye on"')):
            self.assertEqual(app.hp_goodbye_set(True), (True, None))        # the goodbye switch is unchanged

    def test_hp_export_words(self):
        src = open(os.path.join(ROOT, "honeypot", "hp-export")).read()
        self.assertIn('"ids on"|"ids off")', src)
        self.assertIn("is not set up on the honeypot", src)
        self.assertIn('echo "option:suricata ok"', src)


class Card(unittest.TestCase):
    def setUp(self):
        self.con = app.connect()

    def tearDown(self):
        with self.con:
            self.con.execute("DELETE FROM meta WHERE k IN ('hp_status', 'hp_ids')")

    def state(self, ids, **items):
        with self.con:
            app.set_meta(self.con, "hp_status", json.dumps({"at": time.time(), "items": items}))
            app.set_meta(self.con, "hp_ids", json.dumps(ids))

    def test_states(self):
        self.state({"on": False})
        html = app.ids_card()
        self.assertNotIn('action="/settings/ids"', html)                  # not set up: how to, no button
        self.assertIn("--suricata-on", html)
        self.state({"on": False}, **{"option:suricata": True})
        self.assertIn("value=1><button>Turn on Suricata</button>", app.ids_card())
        self.state({"on": True, "rules": time.time()}, **{"option:suricata": True, "running:suricata": True})
        html = app.ids_card()
        self.assertIn("Turn off Suricata", html)
        self.assertIn("sp-status on", html)
        self.assertNotIn("running:suricata", app.protection_missing(self.con))
        self.assertNotIn("option:suricata", app.protection_missing(self.con))

    def test_messages(self):
        self.assertEqual(app.SETTINGS_OK["idson"][0], "honeypot")
        self.assertEqual(app.SETTINGS_OK["idsoff"][0], "honeypot")


if __name__ == "__main__":
    unittest.main()
