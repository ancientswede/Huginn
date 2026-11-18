# 0.49.1 fixes from the Codex review of 0.25-0.49 (Codex-Agent/huginn-totalgranskning-049/SVAR.md). Each test is the
# review's reproduction turned around: it now checks the fixed behaviour. In-memory database, made-up data.
import hashlib, importlib.machinery, importlib.util, io, json, os, sqlite3, tempfile, time, unittest, zipfile
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from tests.helpers import ROOT, app

IP = "192.0.2.10"


def tool(name):
    loader = importlib.machinery.SourceFileLoader(name.replace("-", "_") + "_0491", os.path.join(ROOT, "honeypot", name))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


def event(h, ts, kind="canary", a="ftp", b="", sid=None, ip=IP):
    return h, ts, ip, "cowrie" if sid else "canary", kind, sid, a, b


class Mem(unittest.TestCase):
    def setUp(self):
        self.con = sqlite3.connect(":memory:")
        self.addCleanup(self.con.close)
        self.con.row_factory = sqlite3.Row
        self.con.executescript(app.SCHEMA)
        for t, c in (("enrich", "rdns_ok INTEGER"), ("capped", "src TEXT"), ("sessions", "tty TEXT"), ("sessions", "termsize TEXT"),
                     ("files", "family TEXT"), ("files", "mb TEXT"), ("files", "mb_checked REAL")):
            try:
                self.con.execute("ALTER TABLE %s ADD COLUMN %s" % (t, c))
            except sqlite3.OperationalError:
                pass
        self.con.commit()
        p = patch.object(app, "db", return_value=self.con)
        p.start()
        self.addCleanup(p.stop)

    def tags(self):
        return self.con.execute("SELECT tags FROM ips WHERE ip=?", (IP,)).fetchone()[0] or ""


class Collect(Mem):
    def test_m1_rule_change_recomputes_old_tags(self):
        app.store(self.con, [event("web", time.time(), a="http")])
        with patch.object(app, "web_rules", return_value=([object()], "rules-1")), \
                patch.object(app, "web_classify", return_value=("probe", "example", "", 1, "rule", 0, "")):
            app.classify_web(self.con)
        self.assertIn("web-probe", self.tags())
        with patch.object(app, "web_rules", return_value=([object()], "rules-2")), \
                patch.object(app, "web_classify", return_value=("none", "", "", 0, "", 0, "")):
            app.classify_web(self.con)
        self.assertNotIn("web-probe", self.tags())
        self.assertIsNone(app.get_meta(self.con, "webrules_redo"))

    def test_m2_same_line_twice_counts_once(self):
        now = time.time()
        same = event("same", now)
        with patch.object(app, "DECOY_CAP", 2):
            app.store(self.con, [same, same, event("distinct", now + 0.1)])
        self.assertEqual(tuple(self.con.execute("SELECT kept, dropped FROM capped").fetchone()), (2, 0))

    def test_m2_counted_row_remembered_after_retention(self):
        old = time.time() - 4 * 86400
        with patch.object(app, "DECOY_CAP", 1), patch.object(app, "RETENTION_DAYS", 30):
            batch = [event("kept", old), event("counted", old + 0.1)]
            app.store(self.con, batch)
            app.retention(self.con)
            app.store(self.con, batch)
            self.assertEqual(self.con.execute("SELECT dropped FROM capped").fetchone()[0], 1)

    def test_m3_old_rows_not_stored_again(self):
        with patch.object(app, "RETENTION_DAYS", 7):
            old, fresh = event("old", time.time() - 8 * 86400), event("fresh", time.time())
            app.store(self.con, [old, fresh])
            app.retention(self.con)
            app.store(self.con, [old, fresh])
            self.assertEqual(self.con.execute("SELECT COUNT(*) FROM events").fetchone()[0], 1)


class Returns(Mem):
    def test_m7_tarpit_covers_its_days(self):
        today = int(time.time() // 86400) * 86400
        old = today - 9 * 86400
        app.store(self.con, [event("start", old + 60, "tarpit_open", "50100"), event("visit", old + 70),
                             event("finish", today + 20, "tarpit", str(today - old - 40), "50100"),
                             event("shell", today + 30, "cmd", "echo example", sid="demo-session")])
        self.assertIsNone(app.return_info(self.con, IP, n=7))
        self.assertNotIn("stepped-up", self.tags())

    def test_m21_failed_download_is_not_a_payload(self):
        today = int(time.time() // 86400) * 86400
        app.store(self.con, [event("old", today - 9 * 86400), event("connect", today + 20, "connect", "ssh", "2225", "s1"),
                             event("failed", today + 21, "file_fail", "https://example.test/x", sid="s1")])
        self.assertEqual(app.return_info(self.con, IP, n=7)[2:], (0, 1))
        self.assertNotIn("stepped-up", self.tags())

    def test_l2_reused_port_still_stuck(self):
        now = time.time()
        app.store(self.con, [event("o1", now - 120, "tarpit_open", "50100"), event("c1", now - 100, "tarpit", "20", "50100"),
                             event("o2", now - 20, "tarpit_open", "50100")])
        self.assertEqual(app.time_wasted(self.con, now - 3600)["stuck"], 1)


class Tor(Mem):
    def test_m8_gap_between_listings_is_not_tor(self):
        day = 86400.0
        with self.con:
            self.con.execute("INSERT INTO torp VALUES(?,?,?)", (IP, 0 * day, 10 * day))
            self.con.execute("INSERT INTO torp VALUES(?,?,?)", (IP, 100 * day, 110 * day))
        app.set_meta(self.con, "torp_init", "1")
        self.assertTrue(app.tor_is(self.con, IP, 5 * day))
        self.assertTrue(app.tor_is(self.con, IP, 105 * day))
        self.assertFalse(app.tor_is(self.con, IP, 55 * day))


class Lookups(Mem):
    def test_m10_empty_vt_answer_is_an_error(self):
        sha = hashlib.sha256(b"inventory example").hexdigest()
        app.store_files(self.con, [{"sha": sha, "size": 17}])
        with patch.object(app, "vt_key", return_value="k" * 64), patch.object(app, "api_urlopen", return_value=io.BytesIO(b"{}")):
            self.assertEqual(app.vt_lookup(self.con), 0)
        self.assertIsNone(app.vt_get(sha))
        self.assertTrue(app.get_meta(self.con, "vt_error"))

    def test_m10_real_answer_still_found(self):
        sha = hashlib.sha256(b"real").hexdigest()
        app.store_files(self.con, [{"sha": sha, "size": 4}])
        body = json.dumps({"data": {"type": "file", "id": sha, "attributes": {"last_analysis_stats": {"malicious": 3, "undetected": 5}}}})
        with patch.object(app, "vt_key", return_value="k" * 64), patch.object(app, "api_urlopen", return_value=io.BytesIO(body.encode())):
            self.assertEqual(app.vt_lookup(self.con), 1)
        self.assertEqual((app.vt_get(sha)["mal"], app.vt_get(sha)["total"]), (3, 8))

    def test_m11_private_rows_do_not_block_public_ones(self):
        now = time.time()
        with self.con:
            self.con.executemany("INSERT INTO ips(ip,last,score) VALUES(?,?,?)", [("10.0.0.1", now, 101), ("10.0.0.2", now, 102), ("1.1.1.1", now - 1, 10)])
        asked = []
        with patch.object(app, "gn_daily", return_value=20), patch.object(app, "time") as t:
            t.time.return_value, t.sleep = now, (lambda s: None)
            with patch.object(app, "api_urlopen", side_effect=lambda req, **k: asked.append(req.full_url) or io.BytesIO(b'{"noise": false}')):
                app.gn_lookup(self.con, limit=2)
        self.assertEqual(asked, ["https://api.greynoise.io/v3/community/1.1.1.1"])
        self.assertFalse(app.sendable_ip("224.0.0.1"))

    def test_m12_greynoise_research_without_enrich_row(self):
        app.store(self.con, [event("start", time.time())])
        with self.con:
            self.con.execute("INSERT INTO greynoise(ip,data) VALUES(?,?)", (IP, json.dumps({"seen": True, "class": "benign"})))
        self.assertEqual(app.blocklist_ips(self.con, 1, 7, False, True), [])
        self.assertEqual(app.blocklist_ips(self.con, 1, 7, True, True), [IP])

    def test_l5_key_test_respects_daily_limit(self):
        app.set_meta(self.con, "vt_day", app.day_budget(self.con, "vt_day", 1)[1] + ":%d" % app.VT_DAILY)
        self.assertEqual(app.day_budget(self.con, "vt_day", app.VT_DAILY)[0], 0)


class Misc(Mem):
    def test_m14_settings_saves_do_not_undo_each_other(self):
        self.assertTrue(app.save_settings({"scope": "appearance", "title": "Audit dashboard"}, {}))
        self.assertTrue(app.save_settings({"scope": "views", "bl_min": "25"}, {}))
        st = app.settings(self.con)
        self.assertEqual((st["title"], st["bl_min"]), ("Audit dashboard", 25))

    def test_m18_failed_delivery_is_tried_again(self):
        now = time.time()
        app.set_meta(self.con, "ntfy_last", now - app.NOTIFY_EVERY - 100)
        app.store(self.con, [event("f", now - 1, "file", "example.bin", "a" * 64, "sample")])
        st = dict(app.settings(self.con), notify=True, notify_events=["files"])
        with patch.object(app, "NTFY_URL", "unused"), patch.object(app, "settings", return_value=st):
            with patch.object(app, "ntfy_post", side_effect=OSError("down")):
                app.notify(self.con)
            self.assertLess(float(app.get_meta(self.con, "ntfy_last")), now - 1)
            app.set_meta(self.con, "ntfy_retry_at", 0)
            with patch.object(app, "ntfy_post") as send:
                app.notify(self.con)
                send.assert_called_once()
                self.assertIn("New files captured: 1", send.call_args[0][0])

    def test_l7_feed_token_not_logged(self):
        self.assertEqual(app.log_path("/feed/abcdefghijklmnop1234/txt?min=5"), "/feed/<token>/txt")

    def test_l8_old_report_is_not_all_in_place(self):
        data = {"items": {"sandbox:cowrie": False}, "at": time.time() - 3601}
        app.set_meta(self.con, "hp_status", json.dumps(data))
        note = app.protection_note(self.con)
        self.assertNotIn("all in place", note)
        self.assertIn("no recent report", note)


class Honeypot(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="hp0491-"))
        self.dl, self.out = self.tmp / "dl", self.tmp / "out"
        self.dl.mkdir()

    def run_zip(self, z, *args):
        o, e = io.StringIO(), io.StringIO()
        with redirect_stdout(o), redirect_stderr(e):
            rc = z.main(["hp-sample-zip"] + list(args))
        return rc, o.getvalue(), e.getvalue()

    def test_m4_l3_included_line_and_unique_names(self):
        z = tool("hp-sample-zip")
        plain = b"ordinary text for the zip test"
        sha, gone = hashlib.sha256(plain).hexdigest(), hashlib.sha256(b"gone").hexdigest()
        (self.dl / sha).write_bytes(plain)
        with patch.object(z, "OUT_DIR", str(self.out)), patch.object(z, "download_dirs", return_value=[str(self.dl)]), \
                patch.object(z.time, "time", return_value=1_780_000_000):
            rc, out, _ = self.run_zip(z, sha, gone)
            self.assertEqual(rc, 0)
            self.assertIn("included: " + sha + "\n", out)
            self.assertIn("not included: " + gone, out)
            rc2, out2, _ = self.run_zip(z, sha)             # same second: a name of its own
            self.assertEqual(rc2, 0)
        names = sorted(p.name for p in self.out.iterdir())
        import datetime
        stamp = datetime.datetime.fromtimestamp(1_780_000_000, datetime.timezone.utc).strftime("%Y%m%d-%H%M%S")
        self.assertEqual(names, ["samples-%s-2.zip" % stamp, "samples-%s.zip" % stamp])
        self.assertEqual(zipfile.ZipFile(self.out / names[1]).read(sha + ".bin", pwd=b"infected"), plain)
        # Huginn marks only what the pasted line holds
        con = sqlite3.connect(":memory:")
        con.executescript(app.SCHEMA)
        self.assertEqual(app.mark_shared(con, "included: " + sha), 1)

    def test_m5_found_keeps_paths_not_bytes(self):
        z = tool("hp-sample-zip")
        data = os.urandom(1000)
        sha = hashlib.sha256(data).hexdigest()
        (self.dl / "redir_abcd1234").write_bytes(data)
        found = z.find({sha}, [str(self.dl)])
        self.assertEqual(found[sha][1:], ("redir_abcd1234", 1000))
        self.assertIsInstance(found[sha][0], str)

    def test_m6_whole_file_hashed(self):
        fi = tool("hp-fileinfo")
        data = b"x" * (fi.MAXREAD + 1)
        (self.dl / "tmp_bigfile1").write_bytes(data)
        cache = self.tmp / "cache.json"
        o = io.StringIO()
        with patch.object(fi, "DIRS", [str(self.dl)]), patch.object(fi, "CACHE", str(cache)), redirect_stdout(o):
            fi.main()
        rows = [json.loads(l) for l in o.getvalue().splitlines()]
        self.assertEqual(rows[0]["sha"], hashlib.sha256(data).hexdigest())
        # deleted from the honeypot: no longer exported
        (self.dl / "tmp_bigfile1").unlink()
        o = io.StringIO()
        with patch.object(fi, "DIRS", [str(self.dl)]), patch.object(fi, "CACHE", str(cache)), redirect_stdout(o):
            fi.main()
        self.assertEqual(o.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
