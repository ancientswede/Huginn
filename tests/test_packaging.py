# The files built for a GitHub release: exactly what goes in, and that they work without the repository.
import os, re, shutil, subprocess, tempfile, unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VERSION = re.search(r'^HUGINN_VERSION = "([^"]+)"', open(os.path.join(ROOT, "app.py"), encoding="utf-8").read(), re.M).group(1)


@unittest.skipUnless(shutil.which("dpkg-deb"), "needs dpkg-deb")
class Release(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.out = cls.tmp.name
        subprocess.run([os.path.join(ROOT, "tools", "build-release.sh"), cls.out], check=True, capture_output=True)
        cls.deb = os.path.join(cls.out, "huginn_all.deb")
        cls.listing = subprocess.run(["dpkg-deb", "-c", cls.deb], check=True, capture_output=True, text=True).stdout.splitlines()

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def files(self):
        return sorted(x.split()[-1].lstrip(".") for x in self.listing if not x.startswith("d"))

    def field(self, name):
        return subprocess.run(["dpkg-deb", "-f", self.deb, name], check=True, capture_output=True, text=True).stdout.strip()

    def test_version_comes_from_the_code(self):
        self.assertEqual(self.field("Version"), VERSION)

    def test_package_holds_exactly_the_expected_files(self):
        static = ["/usr/share/huginn/static/" + x for x in os.listdir(os.path.join(ROOT, "static"))]
        expected = ["/usr/sbin/huginn-rollback", "/usr/sbin/huginn-setup", "/usr/share/doc/huginn/copyright", "/usr/share/huginn/app.py",
                    "/usr/share/huginn/install-huginn.sh", "/usr/share/huginn/systemd/huginn.service", "/usr/share/huginn/update-huginn.sh"] + static
        self.assertEqual(self.files(), sorted(expected))

    def test_files_belong_to_root(self):
        for line in self.listing:
            self.assertIn(" root/root ", line, line)

    def test_no_folder_is_private(self):
        for line in self.listing:
            if line.startswith("d"):
                self.assertTrue(line.startswith("drwxr-xr-x"), line)

    def test_compose_file_needs_no_repository(self):
        text = open(os.path.join(self.out, "docker-compose.yml"), encoding="utf-8").read()
        self.assertNotRegex(text, r"(?m)^\s+build:")
        self.assertIn("image: ghcr.io/ancientswede/huginn:", text)
        self.assertIn("cp huginn.env.example .env", text)

    def test_checksums_cover_every_file(self):
        subprocess.run(["sha256sum", "-c", "--quiet", "SHA256SUMS"], cwd=self.out, check=True, capture_output=True)
        names = [x.split()[-1] for x in open(os.path.join(self.out, "SHA256SUMS"))]
        self.assertEqual(sorted(names), ["docker-compose.yml", "huginn.env.example", "huginn_all.deb"])
