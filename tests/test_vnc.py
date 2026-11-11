# 0.24.1 VNC passwords count as logins when OpenCanary knows them; unknown ones stay plain hits.
import json, time, unittest

from tests.helpers import app

NOW = time.time()
IP = "198.51.100.81"


def line(pw):
    return json.dumps({"src_host": IP, "dst_port": 5900, "utc_time": "2026-11-11 10:00:00.000000",
                       "logdata": {"VNC Server Challenge": "aa", "VNC Client Response": "bb", "VNC Password": pw}})


class Vnc(unittest.TestCase):
    def setUp(self):
        self.con = app.connect()
        self.clean()

    def tearDown(self):
        self.clean()

    def clean(self):
        with self.con:
            for t in ("events", "sessions", "ips", "seen"):
                self.con.execute("DELETE FROM %s" % t)
            self.con.execute("DELETE FROM meta WHERE k IN ('settings','vnc_logins')")
        app._board_cache.clear()

    def test_parser(self):
        self.assertEqual(app.p_canary(line("123456"))[6], " / 123456")
        self.assertEqual(app.p_canary(line(app.VNC_UNKNOWN))[6], json.dumps({"VNC Password": app.VNC_UNKNOWN}))
        self.assertTrue(app.canary_is_login("vnc", app.p_canary(line("pass / word"))[6]))

    def test_old_rows_are_rewritten_once(self):
        old = [("vnc|1", NOW - 60, IP, "canary", "canary", None, "vnc", '{"VNC Password": "password"}'),
               ("vnc|2", NOW - 50, IP, "canary", "canary", None, "vnc", json.dumps({"VNC Password": app.VNC_UNKNOWN})),
               ("vnc|3", NOW - 40, IP, "canary", "canary", None, "redis", '{"CMD": "INFO", "ARGS": ""}')]
        app.store(self.con, old)
        app.vnc_logins_backfill(self.con)
        b = dict(self.con.execute("SELECT h, b FROM events").fetchall())
        self.assertEqual(b["vnc|1"], " / password")
        self.assertIn("not in the common list", b["vnc|2"])
        self.assertEqual(b["vnc|3"], '{"CMD": "INFO", "ARGS": ""}')
        self.assertEqual(app.get_meta(self.con, "vnc_logins"), "1")
        rows = app.cred_rows(self.con, NOW - 3600)
        self.assertEqual([(r[2], r[3], r[4], r[5]) for r in rows], [("vnc", "", "password", False)])
        svcs = app.board_services(self.con, app.settings(self.con), "24h")
        self.assertEqual((svcs["vnc"]["hits"], svcs["vnc"]["logins"]), (2, 1))


if __name__ == "__main__":
    unittest.main()
