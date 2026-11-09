# The rotating web identity: the catalogue on the honeypot and what Huginn does with its history.
import importlib.machinery, importlib.util, os, re, tempfile, time, unittest
from unittest import mock

from tests.helpers import app, ROOT


def load_tool():
    path = os.path.join(ROOT, "honeypot", "hp-identity")
    spec = importlib.util.spec_from_loader("hp_identity", importlib.machinery.SourceFileLoader("hp_identity", path))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


tool = load_tool()
NOW = time.time()


class Catalogue(unittest.TestCase):
    def test_many_brands_of_both_kinds(self):
        kinds = [v["kind"] for v in tool.IDENTITIES.values()]
        self.assertGreaterEqual(kinds.count("nas"), 6)
        self.assertGreaterEqual(kinds.count("router"), 8)

    def test_every_label_survives_the_export_filter(self):
        for ident in tool.IDENTITIES.values():
            self.assertRegex(ident["id"], tool.ID_RE)
            for model in ident["models"]:
                label = "%s %s" % (ident["vendor"], model)
                self.assertRegex(label, tool.LABEL_RE)
                line = "1800000000 %s %s %s" % (ident["id"], ident["kind"], label)
                self.assertEqual(len(app.parse_identities([line])), 1, line)

    def test_pages_work_with_opencanary(self):
        for ident in tool.IDENTITIES.values():
            if ident["layout"] == "builtin":
                continue
            page = tool.login_page(ident, ident["models"][0])
            self.assertIn('name="username"', page)
            self.assertIn('name="password"', page)
            self.assertEqual((page.count("<!--STARTERR-->"), page.count("<!--ENDERR-->")), (1, 1))
            self.assertIn("/index.html", page)
            self.assertNotRegex(page, r"(?:src=|url\(|https?://)", ident["id"])         # nothing from anywhere else

    def test_skin_has_every_file_opencanary_opens(self):
        with tempfile.TemporaryDirectory() as d:
            ident = tool.IDENTITIES["mikrotik"]
            skin = tool.build_skin(ident, "hEX S", d)
            for f in ("index.html", "404.html", "403.html", "redirect.html"):
                self.assertTrue(os.path.isfile(os.path.join(skin, f)), f)
            self.assertTrue(os.path.isdir(os.path.join(skin, "static")))
            self.assertIn("[[URL]]", open(os.path.join(skin, "404.html")).read())

    def test_rotation_avoids_the_last_ones(self):
        recent = list(tool.IDENTITIES)[:3]
        for _ in range(200):
            self.assertNotIn(tool.choose(recent), recent)

    def test_rotate_is_not_due_yet(self):
        with mock.patch.object(tool, "lock", return_value=1), mock.patch.object(tool, "recover"), \
                mock.patch.object(tool, "history", return_value=[(int(NOW) - 86400, "qnap", "nas", "QNAP TS-264")]), \
                mock.patch.object(tool, "rotate_days", return_value=21), mock.patch.object(tool, "apply_identity") as ap, \
                mock.patch.object(tool.os, "geteuid", return_value=0):
            self.assertEqual(tool.main(["x", "rotate"]), 0)
            ap.assert_not_called()

    def test_rotate_when_due_and_never_when_off(self):
        old = [(int(NOW) - 30 * 86400, "qnap", "nas", "QNAP TS-264")]
        with mock.patch.object(tool, "lock", return_value=1), mock.patch.object(tool, "recover"), mock.patch.object(tool, "history", return_value=old), mock.patch.object(tool, "apply_identity") as ap, mock.patch.object(tool.os, "geteuid", return_value=0):
            with mock.patch.object(tool, "rotate_days", return_value=21):
                tool.main(["x", "rotate"])
            self.assertEqual(ap.call_count, 1)
            with mock.patch.object(tool, "rotate_days", return_value=0):
                tool.main(["x", "rotate"])
            self.assertEqual(ap.call_count, 1)


class Change(unittest.TestCase):
    # The whole change as a transaction, with OpenCanary and systemd replaced by a dictionary.
    def setUp(self):
        self.d = tempfile.TemporaryDirectory()
        state = os.path.join(self.d.name, "state")
        skins = os.path.join(self.d.name, "skins")
        os.makedirs(skins)
        self.conf = {"http.port": 8080, "http.banner": "old", "http.skin": "nasLogin", "http.skindir": "", "https.skin": "nasLogin", "https.certificate": "/o.pem", "https.key": "/o.key"}
        def write(change):
            for k, v in change.items():
                if v is None:
                    self.conf.pop(k, None)
                else:
                    self.conf[k] = v
        self.writes = write
        self.patches = [mock.patch.object(tool, "STATE", state), mock.patch.object(tool, "HISTORY", state + "/history"), mock.patch.object(tool, "PENDING", state + "/pending"),
                        mock.patch.object(tool, "LOCK", state + "/lock"), mock.patch.object(tool, "SKINS", skins), mock.patch.object(tool, "OC_HOME", self.d.name),
                        mock.patch.object(tool, "read_conf", lambda: dict(self.conf)), mock.patch.object(tool, "write_conf", write),
                        mock.patch.object(tool, "ensure_cert", return_value=("/n.pem", "/n.key"))]
        for p in self.patches:
            p.start()
        real = tool.build_skin
        mock.patch.object(tool, "build_skin", lambda i, m, root=skins: real(i, m, root)).start()
        self.addCleanup(mock.patch.stopall)
        self.addCleanup(self.d.cleanup)

    def test_success(self):
        with mock.patch.object(tool, "restart"), mock.patch.object(tool, "serving", return_value=True):
            tool.apply_identity(tool.IDENTITIES["qnap"])
        self.assertEqual(self.conf["http.banner"], tool.IDENTITIES["qnap"]["banner"])
        self.assertEqual(tool.history()[-1][1], "qnap")
        self.assertFalse(os.path.exists(tool.PENDING))

    def test_timeout_goes_back(self):
        import subprocess
        before = dict(self.conf)
        calls = []
        def restart():
            calls.append(1)
            if len(calls) == 1:
                raise subprocess.TimeoutExpired("systemctl", 60)
        with mock.patch.object(tool, "restart", restart), mock.patch.object(tool, "serving", return_value=True):
            with self.assertRaises(SystemExit):
                tool.apply_identity(tool.IDENTITIES["qnap"])
        self.assertEqual(self.conf, before)
        self.assertEqual(tool.history(), [])
        self.assertFalse(os.path.exists(tool.PENDING))

    def test_full_disk_on_history_goes_back(self):
        before = dict(self.conf)
        with mock.patch.object(tool, "restart"), mock.patch.object(tool, "serving", return_value=True), mock.patch.object(tool, "add_history", side_effect=OSError("disk full")):
            with self.assertRaises(SystemExit):
                tool.apply_identity(tool.IDENTITIES["qnap"])
        self.assertEqual(self.conf, before)

    def test_same_device_again_keeps_the_pages_in_use_until_proven(self):
        with mock.patch.object(tool, "restart"), mock.patch.object(tool, "serving", return_value=True):
            tool.apply_identity(tool.IDENTITIES["qnap"])
        first = self.conf["http.skindir"]
        with mock.patch.object(tool, "restart"), mock.patch.object(tool, "serving", side_effect=[False, True]):
            with self.assertRaises(SystemExit):
                tool.apply_identity(tool.IDENTITIES["qnap"])
        self.assertEqual(self.conf["http.skindir"], first)
        self.assertTrue(os.path.isfile(os.path.join(first, "index.html")))
        self.assertEqual(os.listdir(tool.SKINS), [os.path.basename(first)])

    def test_old_pages_go_after_success(self):
        with mock.patch.object(tool, "restart"), mock.patch.object(tool, "serving", return_value=True):
            tool.apply_identity(tool.IDENTITIES["qnap"])
            tool.apply_identity(tool.IDENTITIES["asus"])
        self.assertEqual(os.listdir(tool.SKINS), [os.path.basename(self.conf["http.skindir"])])

    def test_interrupted_change_is_undone_by_the_next_run(self):
        before = dict(self.conf)
        os.makedirs(tool.STATE)
        tool.save_pending(before)
        self.conf["http.banner"] = "half done"
        with mock.patch.object(tool, "restart") as r:
            tool.recover()
        self.assertEqual(self.conf, before)
        r.assert_called_once()
        self.assertFalse(os.path.exists(tool.PENDING))

    def test_only_one_change_at_a_time(self):
        held = tool.lock()
        self.assertIsNotNone(held)
        self.assertIsNone(tool.lock())
        os.close(held)
        again = tool.lock()
        self.assertIsNotNone(again)
        os.close(again)

    def test_timer_steps_aside_for_a_running_change(self):
        held = tool.lock()
        with mock.patch.object(tool.os, "geteuid", return_value=0), mock.patch.object(tool, "apply_identity") as ap:
            self.assertEqual(tool.main(["x", "rotate"]), 0)
            with self.assertRaises(SystemExit):
                tool.main(["x", "set", "qnap"])
            ap.assert_not_called()
        os.close(held)

    def test_pages_are_readable_whatever_the_umask(self):
        old = os.umask(0o077)
        try:
            skin = tool.build_skin(tool.IDENTITIES["qnap"], "TS-264", tool.SKINS)
        finally:
            os.umask(old)
        self.assertEqual(os.stat(skin).st_mode & 0o777, 0o755)
        self.assertEqual(os.stat(os.path.join(skin, "static")).st_mode & 0o777, 0o755)
        self.assertEqual(os.stat(os.path.join(skin, "index.html")).st_mode & 0o777, 0o644)


class Huginn(unittest.TestCase):
    def setUp(self):
        self.con = app.connect()
        with self.con:
            for t in ("events", "sessions", "ips", "web_identities"):
                self.con.execute("DELETE FROM %s" % t)
        app._identity_cache.clear()
        app._persona_cache.clear()
        app._local.h12 = False

    def hit(self, key, ts, b, ip="198.51.100.70"):
        app.store(self.con, [(key, ts, ip, "canary", "canary", None, "http", b)])

    def announce(self, *lines):
        app.apply_honeypot_meta(self.con, {"identities": app.parse_identities(list(lines))})

    def test_only_the_expected_shape_gets_in(self):
        self.assertEqual(app.parse_identities(["1800000000 qnap nas <img src=x>", "x qnap nas QNAP", "1800000000 Q nas QNAP", "1800000000 qnap fridge QNAP"]), [])

    def test_export_section_is_read(self):
        rows, _h = app.parse_export("##IDENTITY\n1800000000 mikrotik router MikroTik hEX S\n##END\n", set())
        self.assertEqual(rows, [])
        self.assertEqual(app.parse_export.meta["identities"], [(1800000000.0, "mikrotik", "router", "MikroTik hEX S")])

    def test_hits_land_on_the_device_of_that_moment(self):
        t0 = int(NOW) - 4 * 86400
        self.announce("%d qnap nas QNAP TS-264" % t0, "%d tp-link router TP-Link AX55" % (t0 + 2 * 86400))
        self.hit("a", t0 + 60, "GET /admin (404)  · curl")
        self.hit("b", t0 + 120, "root / admin", ip="198.51.100.71")
        self.hit("c", t0 + 2 * 86400 + 60, "POST /x (404)")
        rows = {r["id"]: r for r in app.identity_stats(self.con)}
        self.assertEqual((rows["qnap"]["hits"], rows["qnap"]["ips"], rows["qnap"]["logins"]), (2, 2, 1))
        self.assertEqual((rows["tp-link"]["hits"], rows["tp-link"]["logins"]), (1, 0))
        self.assertTrue(rows["tp-link"]["now"])
        self.assertFalse(rows["qnap"]["now"])
        self.assertAlmostEqual(rows["qnap"]["per_day"], 1.0, places=2)

    def test_a_device_that_comes_back_is_added_up(self):
        t0 = int(NOW) - 6 * 86400
        self.hit("first", t0, "GET /first (404)")
        self.announce("%d qnap nas QNAP TS-264" % t0, "%d asus router ASUS RT-AX58U" % (t0 + 86400), "%d qnap nas QNAP TS-464" % (t0 + 2 * 86400))
        rows = {r["id"]: r for r in app.identity_stats(self.con)}
        self.assertEqual(len(rows), 2)
        self.assertAlmostEqual(rows["qnap"]["secs"] / 86400, 5, delta=0.01)
        self.assertEqual(rows["qnap"]["label"], "QNAP TS-464")

    def test_pruned_time_is_not_counted_as_quiet(self):
        t0 = int(NOW) - 30 * 86400
        self.announce("%d qnap nas QNAP TS-264" % t0, "%d asus router ASUS RT-AX58U" % (t0 + 20 * 86400), "%d tp-link router TP-Link AX55" % (t0 + 25 * 86400))
        self.hit("a", t0 + 22 * 86400, "GET /a (404)")          # everything older has been pruned
        rows = {r["id"]: r for r in app.identity_stats(self.con)}
        self.assertNotIn("qnap", rows)
        self.assertAlmostEqual(rows["asus"]["secs"] / 86400, 3, delta=0.01)

    def test_login_with_a_method_as_user_name(self):
        t0 = int(NOW) - 86400
        self.announce("%d qnap nas QNAP TS-264" % t0)
        self.hit("a", t0 + 10, "GET / admin")
        self.hit("b", t0 + 20, "GET / (404)")
        self.hit("c", t0 + 30, "POST /x/y (404)  body: u / p")
        self.hit("d", t0 + 40, "GET /  · curl / 8")
        self.assertEqual(app.identity_stats(self.con)[0]["logins"], 1)

    def test_announced_twice_is_stored_once(self):
        line = "%d qnap nas QNAP TS-264" % (int(NOW) - 100)
        self.announce(line)
        self.announce(line)
        self.assertEqual(self.con.execute("SELECT COUNT(*) FROM web_identities").fetchone()[0], 1)

    def test_page(self):
        self.assertIn("has not announced", app.v_personas())
        t0 = int(NOW) - 86400
        self.hit("first", t0, "GET /first (404)")
        self.announce("%d qnap nas QNAP TS-264" % t0, "%d asus router ASUS RT-AX58U" % (t0 + 3600))
        app._identity_cache.clear()
        html = app.v_personas()
        self.assertIn("QNAP TS-264", html)
        self.assertIn("hits a day", html)
        self.assertIn('class="now-tag"', html)
        self.assertNotRegex(html, r"\sstyle=")


if __name__ == "__main__":
    unittest.main()
