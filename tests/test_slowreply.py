# 0.27 Slow replies: the mail trap waits before "queued", the web trap trickles out the robots-only export.
import asyncio, ast, io, json, os, shutil, subprocess, tempfile, time, types, unittest

from tests.helpers import app, ROOT

import importlib.machinery, importlib.util


def load(name, path):
    spec = importlib.util.spec_from_loader(name, importlib.machinery.SourceFileLoader(name, path))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


patches = load("hp_patches_slow", os.path.join(ROOT, "honeypot", "patches.py"))
IP = "198.51.100.141"


class Mail(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        os.environ["LOGS_DIRECTORY"] = self.d
        self.t = load("hp_traps_slow", os.path.join(ROOT, "honeypot", "hp-traps.py"))
        self.t.SMTP_WAIT = (0.3, 0.3)

    def tearDown(self):
        shutil.rmtree(self.d)

    def events(self):
        out = []
        for f in os.listdir(self.d):
            out += [json.loads(l) for l in open(os.path.join(self.d, f))]
        return out

    def session(self, mails):
        async def run():
            srv = await asyncio.start_server(self.t.make("smtp"), "127.0.0.1", 0)
            r, w = await asyncio.open_connection("127.0.0.1", srv.sockets[0].getsockname()[1])
            got = [await r.readline()]
            msg = b"MAIL FROM:<a@example.net>\r\nRCPT TO:<b@example.org>\r\nDATA\r\nSubject: hi\r\n\r\ntest\r\n.\r\n"
            w.write(b"EHLO bot\r\n" + msg * mails + b"QUIT\r\n")       # pipelined, like real relay bots
            t = time.monotonic()
            while True:
                line = await asyncio.wait_for(r.readline(), 10)
                if not line:
                    break
                got.append(line)
            took = time.monotonic() - t
            w.close()
            srv.close()
            await srv.wait_closed()
            await asyncio.sleep(0.1)
            return took, b"".join(got).decode()
        return asyncio.run(run())

    def test_wait_after_logged_message_and_end_record(self):
        took, out = self.session(2)
        self.assertGreaterEqual(took, 0.6)
        self.assertEqual(out.count("queued as"), 2)
        self.assertIn("221 ", out)                                   # the pipelined QUIT still answered in order
        ev = self.events()
        self.assertEqual([e["event"] for e in ev if e["event"] in ("mail", "end")], ["mail", "mail", "end"])
        end = ev[-1]
        self.assertEqual((end["mails"], end["waited"]), (2, 0.6))
        self.assertGreaterEqual(end["secs"], 0.6)

    def test_caps(self):
        self.t.SMTP_MAX_MAILS = 1
        _took, out = self.session(3)
        self.assertEqual(out.count("queued as"), 1)
        self.assertIn("421 4.7.0", out)
        self.t.SMTP_MAX_MAILS, self.t.SMTP_MAX_SECS = 50, -1
        _took, out = self.session(1)
        self.assertNotIn("queued", out)
        self.assertIn("421 4.4.2", out)
        self.t.SMTP_MAX_SECS, self.t._mail = 600, self.t.SMTP_MAX_CONN   # mail is full: closed at once, other traps not
        _took, out = self.session(1)
        self.assertEqual(out, "")
        self.t._mail = 0


class Reactor:
    def __init__(self):
        self.calls = []

    def callLater(self, delay, fn, *a):
        c = types.SimpleNamespace(delay=delay, fn=fn, a=a, live=True)
        c.active = lambda: c.live
        c.cancel = lambda: setattr(c, "live", False)
        self.calls.append(c)
        return c

    def run(self, n=1000):
        while n and any(c.live for c in self.calls):
            c = next(c for c in self.calls if c.live)
            c.live = False
            c.fn(*c.a)
            n -= 1


class Deferred:
    def __init__(self):
        self.eb = []

    def addErrback(self, fn):
        self.eb.append(fn)
        return self


class Req:
    def __init__(self):
        self.out, self.finished, self.d = b"", False, Deferred()

    def write(self, b):
        self.out += b

    def finish(self):
        self.finished = True

    def notifyFinish(self):
        return self.d

    def lose(self):
        for fn in self.d.eb:
            fn(Exception("connection lost"))


class Drip(unittest.TestCase):
    def setUp(self):
        import sys
        tw = types.ModuleType("twisted"); tw.web = types.ModuleType("twisted.web"); tw.internet = types.ModuleType("twisted.internet")
        srv = types.ModuleType("twisted.web.server"); srv.NOT_DONE_YET = 1
        mods = {"twisted": tw, "twisted.web": tw.web, "twisted.web.server": srv, "twisted.internet": tw.internet}
        self.old = {k: sys.modules.get(k) for k in mods}
        sys.modules.update(mods)
        self.ns = {}
        exec(patches.HTTP_HELPER, self.ns)

    def tearDown(self):
        import sys
        for k, v in self.old.items():
            if v is None:
                sys.modules.pop(k, None)
            else:
                sys.modules[k] = v

    def test_whole_payload_slowly_then_counter_free(self):
        rx, req, ended = Reactor(), Req(), []
        payload = b"[device]\nrole=storage\nusername=backup\npassword=x\n"
        self.assertEqual(self.ns["hpw_drip"](req, payload, IP, lambda h, s: ended.append(h), rx), 1)
        self.assertTrue(0 < len(req.out) < len(payload))               # first part at once
        self.assertEqual(self.ns["HPW_DRIPS"], {IP: 1})
        rx.run()
        self.assertEqual((req.out, req.finished, ended), (payload, True, ["done"]))
        self.assertAlmostEqual(sum(c.delay for c in rx.calls), self.ns["HPW_DRIP_SECS"] * (1 - 1.0 / 10), places=3)
        self.assertEqual(self.ns["HPW_DRIPS"], {})

    def test_client_leaves_and_caps(self):
        rx, req, ended = Reactor(), Req(), []
        self.ns["hpw_drip"](req, b"x" * 100, IP, lambda h, s: ended.append(h), rx)
        req.lose()
        rx.run()
        self.assertEqual((ended, req.finished, len(req.out)), (["gone"], False, 10))
        self.assertEqual(self.ns["HPW_DRIPS"], {})
        ok = self.ns["hpw_drip_ok"]
        self.assertTrue(ok("robots_backup", b"GET", IP))
        self.assertFalse(ok("robots_backup", b"HEAD", IP))
        self.assertFalse(ok("env", b"GET", IP))                          # first, valuable replies stay fast
        self.ns["HPW_DRIPS"][IP] = 2
        self.assertFalse(ok("robots_backup", b"GET", IP))
        self.ns["HPW_DRIPS"].clear()
        self.ns["HPW_DRIPS"].update({"192.0.2.%d" % i: 1 for i in range(32)})
        self.assertFalse(ok("robots_backup", b"GET", IP))


class Render(unittest.TestCase):
    UPSTREAM = ('import os\nclass Error(Resource):\n'
                '    def __init__(self, factory, error_code="404"):\n'
                '        self.factory = factory\n'
                '        self.error_code = error_code\n' + patches.HTTP_OLD + '\n'
                '    def render_GET(self, request):\n'
                '        return b"error"\n'
                'class CanaryHTTP:\n'
                '    def getService(self):\n'
                '        root.putChild(b"index.html", page)\n')

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir)
        self.path = os.path.join(self.dir, "http.py")

    def test_v1_honeypot_is_upgraded(self):
        try:
            old = subprocess.run(["git", "-C", ROOT, "show", "v0.25.0:honeypot/patches.py"], capture_output=True, text=True, check=True).stdout
        except (OSError, subprocess.CalledProcessError):
            self.skipTest("no git history")
        v1 = os.path.join(self.dir, "v1.py")
        open(v1, "w").write(old)
        open(self.path, "w").write(self.UPSTREAM)
        self.assertEqual(load("hp_patches_v1", v1).opencanary_http(self.path), 0)
        self.assertIn("Huginn webreply v1", open(self.path).read())
        self.assertEqual(patches.opencanary_http(self.path), 0)
        code = open(self.path).read()
        self.assertIn("Huginn webreply v2", code)
        self.assertEqual(open(self.path + ".orig").read(), self.UPSTREAM)
        self.assertEqual(patches.opencanary_http(self.path), 3)
        open(self.path, "w").write(code.replace("HPW_DRIP_MAX = 32", "HPW_DRIP_MAX = 99"))   # an unknown local change stays
        self.assertEqual(patches.opencanary_http(self.path), 1)

    def test_slow_reply_logged_twice(self):
        open(self.path, "w").write(self.UPSTREAM)
        self.assertEqual(patches.opencanary_http(self.path), 0)
        tree = ast.parse(open(self.path).read())
        error = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "Error")
        env = {"Resource": type("Resource", (), {"render": lambda self, r: b"error"}), "os": os}
        exec(patches.HTTP_HELPER, env)
        exec(compile(ast.Module(body=[error], type_ignores=[]), self.path, "exec"), env)
        robots = ["/backup/archive-x/"]
        env["hpw_load"] = lambda f: {"robots": robots, "replies": {"robots_backup": ["text/plain; charset=utf-8", "[device]\npassword=x\n"]}}
        dripped = []
        def fake_drip(request, payload, ip, ended):
            dripped.append((payload, ip)); ended("done", 5.0); return "NOT_DONE_YET"
        env["hpw_drip"] = fake_drip
        logs = []
        factory = types.SimpleNamespace(banner=b"nginx", logger=types.SimpleNamespace(LOG_HTTP_GET=1), log=lambda d, **k: logs.append(d) or kws.append(k))
        kws = []
        def request(method):
            addr = lambda h, p: types.SimpleNamespace(host=h, port=p)
            tr = types.SimpleNamespace(getHost=lambda: addr("192.0.2.9", 8080), getPeer=lambda: addr(IP, 40000))
            r = types.SimpleNamespace(uri=b"/backup/archive-x/db.ini", method=method, content=io.BytesIO(), transport=tr, headers={})
            r.getHeader = lambda n: "ua"
            r.setHeader = lambda n, v: r.headers.update({n: v})
            r.setResponseCode = lambda s: None
            r.getClientAddress = lambda: types.SimpleNamespace(host=IP)
            return r
        self.assertEqual(env["Error"](factory).render(request(b"GET")), "NOT_DONE_YET")
        self.assertEqual(dripped, [(b"[device]\npassword=x\n", IP)])
        self.assertEqual((logs[0]["HP_SLOW"], logs[0]["HP_REPLY"], logs[0]["HP_ROBOTS"]), ("1", "robots_backup", "1"))
        self.assertEqual(logs[1], {"PATH": "/backup/archive-x/db.ini", "METHOD": "GET", "HP_DRIP": "done", "HP_DRIP_SECS": 5.0})
        self.assertEqual((kws[1]["src_host"], kws[1]["dst_port"]), (IP, 8080))      # addresses kept, not read from a closed socket
        self.assertNotIn("transport", kws[1])
        self.assertEqual(env["Error"](factory).render(request(b"HEAD")), b"")   # HEAD: fast, no body, no drip
        self.assertNotIn("HP_SLOW", logs[-1])


class Huginn(unittest.TestCase):
    def setUp(self):
        self.con = app.connect()
        self.clean()

    def tearDown(self):
        self.clean()

    def clean(self):
        with self.con:
            for t in ("events", "sessions", "ips", "seen", "webhits"):
                self.con.execute("DELETE FROM %s" % t)

    def test_parse_and_campaigns(self):
        utc = time.strftime("%Y-%m-%d %H:%M:%S.000000", time.gmtime(time.time() - 600))
        iso = time.strftime("%Y-%m-%dT%H:%M:%S.000000Z", time.gmtime(time.time() - 600))
        web = lambda ld: json.dumps({"src_host": IP, "dst_port": 80, "utc_time": utc, "logdata": ld})
        hit = app.p_canary(web({"PATH": "/backup/a/x", "METHOD": "GET", "STATUS": 200, "HP_REPLY": "robots_backup", "HP_ROBOTS": "1", "HP_SLOW": "1"}))
        self.assertIn("[robots]  [slow]", hit[6])
        done = app.p_canary(web({"PATH": "/backup/a/<b>", "METHOD": "GET", "HP_DRIP": "done", "HP_DRIP_SECS": 5.04}))
        gone = app.p_canary(web({"PATH": "/backup/a/x", "METHOD": "GET", "HP_DRIP": "gone", "HP_DRIP_SECS": 1.2}))
        self.assertEqual((done[3], done[6], gone[6]), ("web_drip", "done 5.0", "gone 1.2"))
        self.assertIsNone(app.p_canary(web({"PATH": "/x", "HP_DRIP": "done", "HP_DRIP_SECS": "nan?"})))
        trap = lambda **kw: json.dumps(dict({"src_ip": IP, "ts": iso, "service": "smtp", "event": "end"}, **kw))
        end = app.p_traps(trap(secs=12.5, mails=3, waited=5.1))
        self.assertEqual((end[3], end[5], end[6]), ("trap_end", "smtp", "12.5 3 5.1"))
        self.assertIsNone(app.p_traps(trap(service="pop3", secs=1, mails=0, waited=0)))
        self.assertIsNone(app.p_traps(trap(secs="x")))
        empty = app.p_traps(trap(secs=2, mails=0, waited=0))
        import hashlib
        rows = [hit, done, gone, end, empty]
        app.store(self.con, [(hashlib.sha1(repr(r).encode()).hexdigest(),) + r for r in rows])
        camp = app.v_campaigns()
        self.assertIn("Slow replies", camp)
        self.assertIn("2 slow exports (robots paths, about 5 s), 1 read to the end, 1 left early, 3.1 s on average", camp)
        self.assertIn("1 sessions that sent mail, from 1 IPs, 3.0 messages and 12 s per session, 5 s of it waiting", camp)
        self.assertEqual(app.board_text("web_drip", "/backup/a/x", "gone 1.2"), "slow export /backup/a/x left after 1.2 s")
        self.assertEqual(app.board_text("trap_end", "smtp", "12.5 3 5.1"), "mail session ended after 12.5 s, 3 message(s)")
        self.assertNotIn("/backup/a/<b>", app.v_ip(IP) + app.v_campaigns())


if __name__ == "__main__":
    unittest.main()
