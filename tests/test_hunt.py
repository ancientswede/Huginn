# Found in the security and bug hunt of 0.23: one bad line must not freeze Huginn, and web requests are not logins.
import fcntl, gzip, json, os, random, re, shutil, signal, sqlite3, tempfile, threading, time, unittest
from unittest import mock

from tests.helpers import app

OLD_V6 = r"(?<![\w:.])[0-9a-fA-F:]*:[0-9a-fA-F:]*:[0-9a-fA-F:]*(?![\w:.])"
NOW = time.time()


class TooSlow(Exception):
    pass


def within(secs, fn):
    def alarm(*_a):
        raise TooSlow()
    old = signal.signal(signal.SIGALRM, alarm)
    signal.setitimer(signal.ITIMER_REAL, secs)
    try:
        return fn()
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, old)


class Regex(unittest.TestCase):
    CRAFTED = [":" * 1990 + "g", "a:" * 995 + "g", "::" * 995 + ".", ":" * 2990 + "g", "1:" * 1495 + "-g", ("a:" * 40 + "g ") * 40]

    def test_a_crafted_line_is_cheap_everywhere(self):
        for s in self.CRAFTED:
            within(1, lambda: app.cmd_shape(s))
            within(1, lambda: app.cmd_html(s))
            within(1, lambda: app.cmd_html(s, {"abc.sh": "a" * 64}))
            within(1, lambda: app.script_hash([s, s]))

    def test_payload_guess_is_bounded(self):
        for u in ("wget ", "curl ", "wget \t", "wget a "):
            within(0.2, lambda: app.PAYLOAD_RE.search((u * 900)[:4000] + "g"))

    def test_same_matches_as_the_old_pattern(self):
        # Campaign ids come from these shapes: the fix must not change what counts as an address.
        rnd = random.Random(7)
        for _ in range(4000):
            s = "".join(rnd.choice("a1f:: .-g_/") for _ in range(rnd.randint(0, 40)))
            self.assertEqual(re.sub(OLD_V6, "X", s), re.sub(app.V6_TOKEN, "X", s), s)

    def test_addresses_still_recognised(self):
        self.assertIn("<ip>", app.cmd_shape("ping6 2001:db8::1"))
        self.assertIn("<ip>", app.cmd_shape("ping6 ::1"))
        self.assertNotIn("<ip>", app.cmd_shape("date 12:30:45"))
        self.assertIn("/search?q=2001", app.cmd_html("ping6 2001:db8::1"))
        self.assertNotIn("/search", app.cmd_html("date 12:30:45"))


class Rest(unittest.TestCase):
    def setUp(self):
        self.con = app.connect()
        with self.con:
            for t in ("events", "sessions", "ips", "seen", "enrich", "flags"):
                self.con.execute("DELETE FROM %s" % t)
            self.con.execute("DELETE FROM meta WHERE k IN ('seen_rowid','last_seen_error','settings')")
        app.set_meta(self.con, "seen_done", "1")

    def cmd(self, key, text, ip="198.51.100.40"):
        return [(key, NOW - 3, ip, "cowrie", "cmd", "s" + key, text, None)]

    def test_a_failed_update_of_new_is_repaired_by_the_next_one(self):
        with mock.patch.object(app, "note_seen", side_effect=sqlite3.OperationalError("database is locked")):
            app.store(self.con, self.cmd("a1", "only_once --flag"))
        self.assertIn("locked", app.get_meta(self.con, "last_seen_error"))
        app.store(self.con, self.cmd("a2", "something_else"))
        have = {r[0] for r in self.con.execute("SELECT ex FROM seen WHERE kind='cmd'")}
        self.assertEqual(have, {"only_once --flag", "something_else"})
        self.assertFalse(app.get_meta(self.con, "last_seen_error"))

    def test_crash_right_after_the_events_on_the_first_run_after_an_upgrade(self):
        self.assertIsNone(app.get_meta(self.con, "seen_rowid"))
        with mock.patch.object(app, "note_seen", side_effect=KeyboardInterrupt):        # a crash, not a handled error
            with self.assertRaises(KeyboardInterrupt):
                app.store(self.con, self.cmd("u1", "before_the_crash"))
        app.store(self.con, self.cmd("u2", "after_the_crash"))
        have = {r[0] for r in self.con.execute("SELECT ex FROM seen WHERE kind='cmd'")}
        self.assertEqual(have, {"before_the_crash", "after_the_crash"})

    def test_retry_also_when_nothing_new_arrives(self):
        with mock.patch.object(app, "note_seen", side_effect=sqlite3.OperationalError("locked")):
            app.store(self.con, self.cmd("r1", "waits_for_retry"))
        app.store(self.con, [])
        self.assertEqual(self.con.execute("SELECT COUNT(*) FROM seen WHERE ex='waits_for_retry'").fetchone()[0], 1)

    def test_two_writers_count_once(self):
        app.store(self.con, self.cmd("w0", "start_here"))
        other = app.connect()
        with self.con:
            self.con.execute("INSERT INTO events(h,ts,ip,src,kind,session,a) VALUES('w1',?,?,?,?,?,?)", (NOW, "198.51.100.40", "cowrie", "cmd", "sw1", "counted_once"))
        app.note_seen(self.con, None)
        app.note_seen(other, None)
        self.assertEqual(self.con.execute("SELECT n FROM seen WHERE ex='counted_once'").fetchone()[0], 1)

    def test_two_stores_seeing_no_position_cannot_move_it_back(self):
        with self.con:
            self.con.execute("DELETE FROM meta WHERE k='seen_rowid'")
        real, other_done, errors = app.recompute_ip, threading.Event(), []

        def second():
            try:
                con = app.connect()
                app.store(con, self.cmd("t2", "second_writer"))
                con.close()
            except Exception as e:
                errors.append(e)
            other_done.set()

        calls = []

        def slow(con, ip):
            if not calls:                 # the first store is inside its transaction: let the other one try to start now
                calls.append(1)
                threading.Thread(target=second, daemon=True).start()
                time.sleep(0.3)
                self.assertFalse(other_done.is_set())
            return real(con, ip)

        with mock.patch.object(app, "recompute_ip", slow):
            app.store(self.con, self.cmd("t1", "first_writer"))
        self.assertTrue(other_done.wait(20))
        self.assertEqual(errors, [])
        for ex in ("first_writer", "second_writer"):
            self.assertEqual(self.con.execute("SELECT n FROM seen WHERE ex=?", (ex,)).fetchone()[0], 1, ex)

    def test_rowids_reused_after_pruning(self):
        app.store(self.con, self.cmd("p1", "old_one"))
        app.set_meta(self.con, "seen_rowid", "100")              # New had got this far, then the top rows were pruned
        with mock.patch.object(app, "note_seen", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                app.store(self.con, self.cmd("p2", "after_pruning"))
        app.store(self.con, self.cmd("p3", "next_one"))
        self.assertEqual(self.con.execute("SELECT COUNT(*) FROM seen WHERE ex='after_pruning'").fetchone()[0], 1)

    def test_a_line_is_counted_once(self):
        app.store(self.con, self.cmd("b1", "same_thing"))
        app.store(self.con, self.cmd("b2", "other_thing"))
        self.assertEqual(self.con.execute("SELECT n FROM seen WHERE ex='same_thing'").fetchone()[0], 1)

    def test_a_position_above_the_table_is_not_trusted(self):
        app.store(self.con, self.cmd("c1", "first_cmd"))
        app.set_meta(self.con, "seen_rowid", "999999999")
        app.store(self.con, self.cmd("c2", "second_cmd"))
        self.assertEqual(self.con.execute("SELECT COUNT(*) FROM seen WHERE ex='second_cmd'").fetchone()[0], 1)

    def test_backups_take_turns(self):
        os.makedirs(app.BACKUP_DIR, mode=0o700, exist_ok=True)
        with open(os.path.join(app.BACKUP_DIR, ".lock"), "a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            with self.assertRaisesRegex(RuntimeError, "another backup"):
                app.backup_db()

    def test_nothing_starts_during_a_restore(self):
        os.makedirs(app.DATA, exist_ok=True)
        with open(os.path.join(app.DATA, ".running"), "a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            with self.assertRaises(SystemExit):
                app.hold_db_lock()

    def test_restore_keeps_committed_wal_data(self):
        with tempfile.TemporaryDirectory() as d:
            db, gz, data = os.path.join(d, "huginn.db"), os.path.join(d, "good.db.gz"), d
            con = sqlite3.connect(db)
            con.execute("PRAGMA journal_mode=WAL")
            con.execute("PRAGMA wal_autocheckpoint=0")
            con.executescript(app.SCHEMA)
            con.execute("INSERT INTO meta(k,v) VALUES('in_wal','yes')")
            con.commit()
            self.assertGreater(os.path.getsize(db + "-wal"), 0)                 # committed, only in the log
            backup = os.path.join(d, "b.db")
            bk = sqlite3.connect(backup)
            bk.executescript(app.SCHEMA)
            bk.execute("INSERT INTO meta(k,v) VALUES('from_backup','yes')")
            bk.commit()
            bk.close()
            with open(backup, "rb") as a, gzip.open(gz, "wb") as o:
                shutil.copyfileobj(a, o)
            with mock.patch.object(app, "DB_PATH", db), mock.patch.object(app, "DATA", data), mock.patch.object(app, "need_service_user"), mock.patch("builtins.print"):
                # Interrupted at the very last step: the old database must be whole.
                with mock.patch.object(app.os, "replace", side_effect=OSError("power cut")):
                    with self.assertRaises(OSError):
                        app.restore_db(gz)
                check = sqlite3.connect(db)
                self.assertEqual(check.execute("SELECT v FROM meta WHERE k='in_wal'").fetchone()[0], "yes")
                check.close()
                app.restore_db(gz)
            new = sqlite3.connect(db)
            self.assertEqual(new.execute("SELECT v FROM meta WHERE k='from_backup'").fetchone()[0], "yes")
            new.close()
            kept = [n for n in os.listdir(d) if ".before-restore-" in n and not n.endswith(("-wal", "-shm"))]
            self.assertTrue(kept)
            old = sqlite3.connect(os.path.join(d, sorted(kept)[-1]))
            self.assertEqual(old.execute("SELECT v FROM meta WHERE k='in_wal'").fetchone()[0], "yes")
            old.close()
            with mock.patch.object(app, "DB_PATH", db), mock.patch.object(app, "DATA", data), mock.patch.object(app, "need_service_user"), mock.patch.object(app, "settle_wal", return_value="busy"):
                with self.assertRaisesRegex(SystemExit, "reading the database"):
                    app.restore_db(gz)
            self.assertFalse(os.path.samefile(db, os.path.join(d, sorted(kept)[-1])))

    def test_restore_wants_a_huginn_database(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "x.db")
            sqlite3.connect(p).execute("CREATE TABLE other(a)").connection.commit()
            self.assertEqual(app.check_copy(p), "ok")
            self.assertIn("not a Huginn database", app.check_is_huginn(p))
            q = os.path.join(d, "y.db")
            c = sqlite3.connect(q)
            c.executescript(app.SCHEMA)
            c.execute("DROP TABLE meta")
            c.execute("CREATE TABLE meta(x)")
            c.commit()
            c.close()
            self.assertIn("table meta lacks", app.check_is_huginn(q))
        self.assertEqual(app.check_is_huginn(app.DB_PATH), "ok")

    def test_empty_ipv6_list_still_clears(self):
        ipset = app.render_feed("ipset", ["203.0.113.5"])[0]
        self.assertIn("flush huginn6", ipset)
        self.assertIn("/ipv6 firewall address-list remove", app.render_feed("mikrotik", ["203.0.113.5"])[0])
        self.assertNotIn("huginn6", app.render_feed("ipset", ["203.0.113.5"], False)[0])

    def test_reverse_dns_words_do_not_make_a_researcher(self):
        self.assertEqual(app.research_flag("research.attacker.example", "Cheap VPS", "Cheap VPS", None), 0)
        self.assertEqual(app.research_flag("evilshodan.io", None, None, None), 0)
        self.assertEqual(app.research_flag("scan-1.shodan.io", None, None, None), 0)            # not checked yet: not good enough
        self.assertEqual(app.research_flag("scan-1.shodan.io", None, None, None, None), 0)
        self.assertEqual(app.research_flag(None, "Censys, Inc.", None, None), 1)
        self.assertEqual(app.research_flag("mine.example", None, None, "x.shadowserver.org", 1), 0)   # a checked name vouches only for itself
        self.assertEqual(app.research_flag("scan-1.shodan.io", None, None, None, 0), 0)         # the name does not point back here
        self.assertEqual(app.research_flag("scan-1.shodan.io", None, None, None, 1), 1)

    def add_scanner(self, ip, extra=()):
        with self.con:
            self.con.execute("INSERT INTO ips(ip,first,last,sessions,logins_ok,logins_fail,cmds,files,tcpip,exploits,score,tags) VALUES(?,?,?,1,0,0,0,0,0,0,9,'')", (ip, NOW, NOW))
            self.con.execute("INSERT OR REPLACE INTO enrich(ip,research) VALUES(?,1)", (ip,))
            for i, (svc, b) in enumerate(extra):
                self.con.execute("INSERT INTO events(h,ts,ip,src,kind,a,b) VALUES(?,?,?,?,?,?,?)", ("%s%d" % (ip, i), NOW, ip, "canary", "canary", svc, b))

    def test_a_scanner_that_logs_in_is_listed(self):
        self.add_scanner("203.0.113.10")
        self.add_scanner("203.0.113.11", [("ftp", "root / toor")])
        self.add_scanner("203.0.113.12", [("http", "GET /  · Mozilla / 5.0")])
        self.assertEqual(app.blocklist_ips(self.con, 3, 30, False, True), ["203.0.113.11"])
        self.assertEqual(len(app.blocklist_ips(self.con, 3, 30, True, True)), 3)

    def test_csv_service_column(self):
        with self.con:
            self.con.execute("INSERT INTO events(h,ts,ip,src,kind,a,b) VALUES('z',?,?,?,?,?,?)", (NOW, "198.51.100.21", "traps", "canary", "=1+1", "root / x"))
        self.assertNotIn(",=1+1,", app.cred_export(self.con, "csv", "all")[0])

    def test_database_is_private(self):
        app.tighten_data()
        self.assertEqual(os.stat(app.DB_PATH).st_mode & 0o777, 0o640)
        self.assertEqual(os.stat(app.DATA).st_mode & 0o777, 0o750)

    def test_password_cache_is_replaced_not_emptied(self):
        with self.con:
            self.con.execute("INSERT INTO events(h,ts,ip,src,kind,a,b) VALUES('p1',?,?,?,?,?,?)", (NOW, "198.51.100.22", "cowrie", "login_fail", "root", "hunter2"))
        first = app.cred_index(self.con)
        app.set_meta(self.con, "last_ingest", repr(NOW + 1))
        second = app.cred_index(self.con)
        self.assertIsNot(first, second)
        self.assertEqual(first["distinct"], 1)


class Logins(unittest.TestCase):
    def setUp(self):
        self.con = app.connect()
        with self.con:
            for t in ("events", "sessions", "ips", "seen"):
                self.con.execute("DELETE FROM %s" % t)

    def add(self, svc, b, ip="198.51.100.20", src="canary"):
        app.store(self.con, [("l|%s|%s" % (svc, b), NOW - 5, ip, src, "canary", None, svc, b)])

    def test_parsers_keep_the_separator_for_logins(self):
        web = json.dumps({"dst_port": 8080, "logdata": {"METHOD": "PROPFIND", "PATH": "/x", "STATUS": "404", "BODY": "a / b", "USERAGENT": "c / d"}, "logtype": 3000, "src_host": "198.51.100.5", "utc_time": "2026-11-09 10:00:00.000"})
        redis = json.dumps({"dst_port": 6379, "logdata": {"CMD": "AUTH", "ARGS": "u / p" + "x" * 900}, "logtype": 17001, "src_host": "198.51.100.5", "utc_time": "2026-11-09 10:00:00.000"})
        login = json.dumps({"dst_port": 8080, "logdata": {"USERNAME": "admin", "PASSWORD": "pw"}, "logtype": 3001, "src_host": "198.51.100.5", "utc_time": "2026-11-09 10:00:00.000"})
        mail = json.dumps({"event": "mail", "service": "smtp", "src_ip": "198.51.100.5", "ts": "2026-11-09T10:00:00+00:00", "mail_from": "a@b", "rcpt_count": 1, "subject": "user / pass"})
        got = [app.p_canary(web), app.p_canary(redis), app.p_traps(mail)]
        for r in got:
            self.assertFalse(app.canary_is_login(r[5], r[6]), r[6])
        r = app.p_canary(login)
        self.assertTrue(app.canary_is_login(r[5], r[6]))
        self.assertEqual(r[6], "admin / pw")

    def test_repeated_separators_are_all_neutralised(self):
        for s in (" / / ", "a / / / b", " /  / "):
            self.assertNotIn(" / ", app.not_a_login(s))

    def test_real_logins_count(self):
        for svc, b in (("http", "admin / hunter2"), ("https", "root / a / b"), ("ftp", "anon / x"), ("http", "GET / admin")):
            self.assertTrue(app.canary_is_login(svc, b), b)

    def test_requests_and_data_do_not(self):
        for svc, b in (("http", "POST /x (404)  body: fakeuser / fakepass"), ("https", "GET /  · Mozilla/5.0 (X11; Linux / x86)"), ("http", "GET / (404)"),
                       ("http", "PUT /a/b (404)  body: a / b  · curl / 8"), ("redis", '{"CMD": "AUTH", "ARGS": "x / y"}'),
                       ("redis", '{"CMD": "AUTH", "ARGS": "x / y' + "z" * 590 + "…"), ("http", "PROPFIND /a  · x / y"), ("smtp", "relay: a -> 1 recipient(s): user / pass")):
            self.assertFalse(app.canary_is_login(svc, b), b)

    def test_password_list_is_clean(self):
        self.add("http", "POST /x (404)  body: fakeuser / fakepass")
        self.add("http", "realuser / realpass")
        self.assertEqual([(r[3], r[4]) for r in app.cred_rows(self.con, 0)], [("realuser", "realpass")])
