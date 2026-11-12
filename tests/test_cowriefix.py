# 0.27.1 Cowrie fixes: ping accepts "-c N", and a file uploaded over SFTP/scp stays for the next command.
import getopt, os, shutil, tempfile, unittest

from tests.helpers import ROOT

import importlib.machinery, importlib.util

_spec = importlib.util.spec_from_loader("hp_patches_fix", importlib.machinery.SourceFileLoader("hp_patches_fix", os.path.join(ROOT, "honeypot", "patches.py")))
patches = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(patches)

PING = '''import getopt
class Ping:
    def start(self):
        try:
''' + patches.PING_OLD + '''
        except getopt.GetoptError as err:
            return str(err)
        return optlist, args
'''

# The upstream shape around each anchor (Cowrie 3.1.6).
UPSTREAM = {
    "shell/server.py": '''class CowrieServer:
    def __init__(self, realm):
        self.fs = None
        self.arch = "linux-x64-lsb"
        self.made = 0

    def initFileSystem(self, home: str) -> None:
''' + patches.UPLOAD["shell/server.py"][0][0] + '''        self.made += 1
''',
    "shell/session.py": '''class SSHSessionForCowrieUser:
    def __init__(self, server, avatar):
        self.server, self.avatar = server, avatar
        self.server.initFileSystem(self.avatar.home)
''' + patches.UPLOAD["shell/session.py"][0][0] + '''self.avatar.home, 0, 0, 4096, 0o40755)
''',
    "commands/scp.py": '''import posixpath
class Command_scp:
    def start(self, optlist, args):
''' + patches.UPLOAD["commands/scp.py"][0][0] + '''
    def errorWrite(self, text):
        self.errors.append(text)

    def name(self, r):
        if True:
            if True:
                if True:
''' + patches.UPLOAD["commands/scp.py"][1][0] + '''                    if self.out_dir:
                        fname = posixpath.join(self.out_dir, scpname)
                    else:
''' + patches.UPLOAD["commands/scp.py"][2][0] + '''                    return fname
        return b""
''',
    "shell/fs.py": '''import os
A_REALFILE, A_SIZE = 0, 1
class HoneyPotFilesystem:
    def __init__(self, nodes, filenames):
        self.nodes, self.filenames = nodes, filenames

    def getfile(self, path):
        return self.nodes.get(path)

    def update_realfile(self, f, realfile):
        if f is not None and not f[A_REALFILE]:
            f[A_REALFILE] = realfile

    def close(self, fd, shasumfile):
''' + patches.UPLOAD["shell/fs.py"][0][0],
    "shell/filetransfer.py": '''class CowrieSFTPFile:
    bytesReceivedLimit = 0

    def __init__(self, sftpserver, filename):
        self.sftpserver, self.filename = sftpserver, filename
        self.bytesReceived, self.size, self.written = 0, 0, []

    def writeChunk(self, offset, data):
        self.bytesReceived += len(data)
        self.size = max(self.size, offset + len(data))
''' + patches.UPLOAD["shell/filetransfer.py"][1][0] + '''            raise ValueError("Quota exceeded")
        self.written.append(offset)

''' + patches.UPLOAD["shell/filetransfer.py"][0][0],
}


class Ping(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir)
        self.path = os.path.join(self.dir, "ping.py")
        open(self.path, "w").write(PING)

    def run_ping(self, args):
        ns = {}
        exec(compile(open(self.path).read(), self.path, "exec"), ns)
        p = ns["Ping"]()
        p.args = args
        return p.start()

    def test_count_is_read(self):
        self.assertEqual(self.run_ping(["-c", "1", "8.8.8.8"]), ([("-c", "")], ["1", "8.8.8.8"]))   # the upstream bug
        self.assertEqual(patches.cowrie_ping(self.path), 0)
        self.assertEqual(self.run_ping(["-c", "1", "8.8.8.8"]), ([("-c", "1")], ["8.8.8.8"]))
        self.assertEqual(self.run_ping(["-c4", "-i", "0.2", "host"]), ([("-c", "4"), ("-i", "0.2")], ["host"]))
        self.assertEqual(patches.cowrie_ping(self.path), 3)
        self.assertEqual(open(self.path + ".orig").read(), PING)
        other = os.path.join(self.dir, "x.py")
        open(other, "w").write("x = 1\n")
        self.assertEqual(patches.cowrie_ping(other), 1)


class Upload(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir)
        os.makedirs(os.path.join(self.dir, "shell"))
        os.makedirs(os.path.join(self.dir, "commands"))
        for rel, text in UPSTREAM.items():
            open(os.path.join(self.dir, rel), "w").write(text)

    def read(self, rel):
        return open(os.path.join(self.dir, rel)).read()

    def load(self, rel, **ns):
        exec(compile(self.read(rel), rel, "exec"), ns)
        return ns

    def test_all_or_nothing(self):
        open(os.path.join(self.dir, "shell/session.py"), "w").write("changed upstream\n")
        self.assertEqual(patches.cowrie_upload(self.dir), 1)
        self.assertEqual(self.read("shell/server.py"), UPSTREAM["shell/server.py"])
        self.assertFalse(os.path.exists(os.path.join(self.dir, "shell/server.py.orig")))

    def test_one_file_system_per_connection(self):
        self.assertEqual(patches.cowrie_upload(self.dir), 0)
        self.assertEqual(patches.cowrie_upload(self.dir), 3)
        made = []

        class FS:
            def __init__(self, arch, home):
                self.dirs, self.modes = [], {}
                made.append(self)

            def exists(self, p):
                return p in self.dirs

            def mkdir(self, p, *a):
                self.dirs.append(p)

            def chmod(self, p, mode):
                self.modes[p] = mode

        fsmod = type("fs", (), {"HoneyPotFilesystem": FS})
        server = self.load("shell/server.py", fs=fsmod)["CowrieServer"](None)
        avatar = type("A", (), {"home": "/home/admin", "temporary": True})()
        Session = self.load("shell/session.py")["SSHSessionForCowrieUser"]
        Session(server, avatar)
        first = server.fs
        Session(server, avatar)                              # a second channel: same file system, home made once
        self.assertIs(server.fs, first)
        self.assertEqual(len(made), 1)
        self.assertEqual(first.dirs, ["/home/admin"])
        sftp = type("S", (), {"_setAttrs": lambda self, p, a: server.fs.chmod(p, a["permissions"])})()
        F = self.load("shell/filetransfer.py")["CowrieSFTPFile"]
        F(sftp, "/root/.16").setAttrs({"permissions": 0o100755})       # scp's fsetstat no longer fails
        self.assertEqual(first.modes, {"/root/.16": 0o100755})
        FSys = self.load("shell/fs.py")["HoneyPotFilesystem"]
        saved = os.path.join(self.dir, "abc123")
        open(saved, "w").write("#!/bin/sh\n")
        node, big = ["downloads/sftp_tmp", 10], ["downloads/sftp_big", 30000000]    # temp names while uploading
        FSys({"/root/.16": node, "/root/.big": big}, {7: "/root/.16", 8: "/root/.big"}).close(7, saved)
        self.assertEqual(node, [saved, 10])                               # now the saved copy, so cat/run can read it
        FSys({"/root/.big": big}, {8: "/root/.big"}).close(8, saved)
        self.assertEqual(big[0], "downloads/sftp_big")                    # over 25 MB: never read whole, as upstream
        up = F(sftp, "/root/.18")
        up.writeChunk(0, b"x" * 1000)
        with self.assertRaises(ValueError):
            up.writeChunk(2 ** 40, b"x")                                  # one byte far past the end: refused
        with self.assertRaises(ValueError):
            F(sftp, "/root/.19").writeChunk(patches.UPLOAD_LIMIT, b"x")   # 10 MB applies with no limit configured
        Scp = self.load("commands/scp.py")["Command_scp"]
        rec = lambda name: type("R", (), {"group": lambda self, i: name.encode()})()
        for target, name, want in (("/tmp/.x", ".e2e", "/tmp/.x"), ("/tmp", ".e2e", "/tmp/.e2e"), ("", ".e2e", ".e2e"),
                                   ("/tmp/ny/", ".e2e", "/tmp/ny/.e2e"), ("/tmp", "../x", b""), ("/tmp", "/etc/x", b""), ("/tmp", "..", b"")):
            c = Scp()
            c.cwd, c.errors = "/root", []
            c.fs = type("F", (), {"isdir": lambda self, p: p == "/tmp", "resolve_path": lambda self, p, cwd: p})()
            c.start([("-t", "")] if target else [("-f", "")], [target] if target else [])
            self.assertEqual(c.name(rec(name)), want)                 # "scp -t TARGET" decides where the file goes
            self.assertEqual(bool(c.errors), want == b"")             # a name with a slash or ".." is refused
        bad = type("S", (), {"_setAttrs": lambda self, p, a: 1 / 0})()
        F(bad, "/root/.17").setAttrs({"permissions": 0o644})             # never an error to the client

    def test_write_group_is_all_or_nothing(self):
        from unittest import mock
        a, b = os.path.join(self.dir, "a.py"), os.path.join(self.dir, "b.py")
        open(a, "w").write("A\n")
        open(b, "w").write("B\n")
        real = os.replace
        calls = []

        def flaky(src, dst):
            calls.append(dst)
            if dst == b:
                raise OSError("disk full")
            return real(src, dst)
        with mock.patch("os.replace", flaky):
            self.assertEqual(patches.write_group({a: ("A\n", "A2\n"), b: ("B\n", "B2\n")}), 1)
        self.assertEqual((open(a).read(), open(b).read()), ("A\n", "B\n"))   # a was swapped in, then put back
        self.assertEqual([f for f in os.listdir(self.dir) if f.startswith(".huginn-") or f.endswith(".orig")], [])
        self.assertEqual(patches.write_group({a: ("changed meanwhile\n", "A2\n")}), 1)
        os.symlink(a, os.path.join(self.dir, "link.py"))
        self.assertEqual(patches.write_group({os.path.join(self.dir, "link.py"): ("A\n", "X\n")}), 1)
        self.assertEqual(open(a).read(), "A\n")
        os.symlink(os.path.join(self.dir, "victim"), b + ".orig")          # a planted .orig link is replaced, not followed
        self.assertEqual(patches.write_group({b: ("B\n", "B2\n")}), 0)
        self.assertFalse(os.path.exists(os.path.join(self.dir, "victim")))
        self.assertEqual((open(b).read(), open(b + ".orig").read()), ("B2\n", "B\n"))


if __name__ == "__main__":
    unittest.main()
