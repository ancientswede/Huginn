# Run with: python3 -B -m unittest discover -s ut/tests -v
import ast
import importlib.machinery
import importlib.util
import io
import json
import os
from pathlib import Path
import runpy
import subprocess
import tempfile
import types
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
TASK = ROOT.parent


def load(path, name):
    spec = importlib.util.spec_from_loader(name, importlib.machinery.SourceFileLoader(name, str(path)))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


w = load(ROOT / 'honeypot/webreply.py', 'webreply')
p = load(ROOT / 'honeypot/patches.py', 'hp_patches')
identity = load(ROOT / 'honeypot/hp-identity', 'hp_identity')


class WorkspaceTest(unittest.TestCase):
    def setUp(self):
        # All test writes stay in this task folder, never the system temporary directory.
        self.tmp = tempfile.TemporaryDirectory(dir=TASK)
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        self.bait = self.dir / 'bait.json'
        self.values = {'server_env_db': 'Test-Bait-Database-0001', 'server_redis': 'Test-Bait-Redis-0002',
                       'server_aws_key_id': 'Test-Bait-Key-0003', 'server_aws_secret': 'Test-Bait-Cloud-0004'}
        self.bait.write_text(json.dumps(self.values))
        bait_patch = mock.patch.object(w, 'HPW_BAIT', str(self.bait))
        bait_patch.start()
        self.addCleanup(bait_patch.stop)
        self.ident = identity.IDENTITIES['qnap']
        self.skin = self.dir / 'skin'
        self.skin.mkdir()
        w.hpw_write_skin(str(self.skin), self.ident, self.bait)
        self.factory = types.SimpleNamespace(skindir=str(self.skin))

    def reply(self, path, method=b'GET', body=b''):
        return w.hpw_reply(self.factory, path, method, body)


class Replies(WorkspaceTest):
    def test_route_matrix(self):
        paths = {'/.env': 'env', '/api/.env.local': 'env', '/.env.bak': 'env', '/.env.production.local': 'env',
                 '/.git/config': 'git', '/.git/HEAD': 'git_head', '/.aws/credentials': 'aws', '/.aws/config': 'aws_config',
                 '/phpinfo.php': 'phpinfo', '/info.php': 'phpinfo', '/../../etc/passwd': 'traversal',
                 '/?file=/etc/passwd': 'traversal', '/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php': 'phpunit',
                 '/mcp': 'mcp', '/actuator/env': 'actuator', '/%252e%252e/%252e%252e/etc/passwd': 'traversal'}
        for path, kind in paths.items():
            with self.subTest(path=path):
                result = self.reply(path.encode())
                self.assertEqual(result[0], kind)
                self.assertLessEqual(len(result[1]), w.HPW_MAX_BODY)
                self.assertFalse(result[3])

    def test_no_broad_matches_or_proxy(self):
        for path in (b'/', b'/index.html', b'/normal.env', b'/news/.environment', b'/wp-config.php',
                     b'/SDK/webLanguage', b'/sse', b'/etc/passwd', b'/webreply.json', b'example.com:443',
                     b'http://example.com/.env', b'//example.com/.env', b'/.env%00', b'/.env' + b'x' * 3000):
            with self.subTest(path=path[:60]):
                self.assertIsNone(self.reply(path)[1])
        for method in (b'CONNECT', b'DELETE', b'TRACE', b'PATCH'):
            self.assertIsNone(self.reply(b'/.env', method)[1])

    def test_missing_empty_invalid_and_placeholder_bait(self):
        for raw in (None, '{}', '[]', '{broken', '{"db":"replace-with-a-unique-random-string-1"}',
                    json.dumps({'db': '<script>bad</script>'}), json.dumps({'db': 'x' * 200}),
                    json.dumps({'db': 'line\nbreak-password'}), json.dumps({'db': 'https://outside.example/key'}),
                    'x' * (w.HPW_MAX_BUNDLE + 1)):
            if raw is None:
                self.bait.unlink(missing_ok=True)
            else:
                self.bait.write_text(raw)
            obj = w.hpw_build(self.ident, self.bait)
            self.assertEqual(obj['replies'], {})
            w.hpw_write_skin(self.skin, self.ident, self.bait)
            self.factory = types.SimpleNamespace(skindir=str(self.skin))
            self.assertIsNone(self.reply(b'/.env')[1])
            self.assertIsNotNone(self.reply(b'/robots.txt')[1])
            probe = obj['robots'][0].encode()
            self.assertEqual(self.reply(probe), (None, None, None, True))

    def test_credentials_are_exact_bait_and_stable(self):
        first = self.reply(b'/.env')[1]
        self.assertIn(self.values['server_env_db'].encode(), first)
        self.assertIn(self.values['server_redis'].encode(), first)
        for _ in range(10):
            self.assertEqual(self.reply(b'/api/.env.bak?foo=bar')[1], first)
            self.assertEqual(w.hpw_build(self.ident, self.bait), w.hpw_build(self.ident, self.bait))
        aws = self.reply(b'/.aws/credentials')[1]
        self.assertIn(self.values['server_aws_key_id'].encode(), aws)
        self.assertIn(self.values['server_aws_secret'].encode(), aws)

    def test_all_identities_robots_unique_and_not_elsewhere(self):
        seen = set()
        for ident in identity.IDENTITIES.values():
            obj = w.hpw_build(ident, self.bait)
            self.assertEqual(len(obj['robots']), 4)
            self.assertEqual(obj['robots'], w.hpw_robots(ident))
            for path in obj['robots']:
                self.assertNotIn(path, seen)
                seen.add(path)
                for ctype, text in obj['replies'].values():
                    self.assertNotIn(path, text)
                    self.assertNotIn('http://', text)
                    self.assertNotIn('https://', text)
                    self.assertNotIn('<?', text)
                    self.assertNotIn('<script', text)
            self.assertLessEqual(len(json.dumps(obj).encode()), w.HPW_MAX_BUNDLE)

    def test_robots_hit_and_head(self):
        robots = self.reply(b'/robots.txt')[1].decode()
        self.assertEqual(robots.count('Disallow:'), 4)
        for path in w.hpw_robots(self.ident):
            result = self.reply((path + '?x=1').encode(), b'HEAD')
            self.assertEqual(result[0], 'robots_backup')
            self.assertTrue(result[3])
        self.assertFalse(self.reply(b'/robots.txt')[3])
        self.assertFalse(self.reply(b'/.env')[3])

    def test_bounded_cache_and_corrupt_bundle(self):
        with mock.patch('builtins.open', wraps=open) as opened:
            self.reply(b'/.env')
            for _ in range(30):
                self.reply(b'/.env')
            self.assertEqual(opened.call_count, 2)
        bundle = self.skin / w.HPW_BUNDLE
        for data in ('{broken', '[]', 'x' * (w.HPW_MAX_BUNDLE + 1), json.dumps({'version': 1, 'robots': [], 'replies': {}})):
            bundle.write_text(data)
            self.factory = types.SimpleNamespace(skindir=str(self.skin))
            self.assertIsNone(self.reply(b'/.env')[1])
        bundle.unlink()
        self.factory = types.SimpleNamespace(skindir=str(self.skin))
        self.assertIsNone(self.reply(b'/.env')[1])

    def test_running_service_sees_deleted_changed_and_unreadable_bait(self):
        self.assertIn(self.values['server_env_db'].encode(), self.reply(b'/.env')[1])
        self.bait.unlink()
        self.assertIsNone(self.reply(b'/.env')[1])
        self.bait.write_text(json.dumps({'db': 'Changed-Test-Bait-0005'}))
        self.assertIn(b'Changed-Test-Bait-0005', self.reply(b'/.env')[1])
        self.assertNotIn(self.values['server_env_db'].encode(), self.reply(b'/.env')[1])
        self.factory._hpw_cache = None
        real_open = open
        def inaccessible(path, *args, **kwargs):
            if str(path) == str(self.bait):
                raise PermissionError('test-only unreadable bait')
            return real_open(path, *args, **kwargs)
        with mock.patch('builtins.open', side_effect=inaccessible):
            self.assertIsNone(self.reply(b'/.env')[1])

    def test_mcp_discovery_only(self):
        for method in ('initialize', 'tools/list', 'tools/call'):
            body = json.dumps({'jsonrpc': '2.0', 'id': 'probe-1', 'method': method, 'params': {'name': 'any'}}).encode()
            result = self.reply(b'/mcp', b'POST', body)
            data = json.loads(result[1])
            self.assertEqual(data['id'], 'probe-1')
            if method == 'tools/call':
                self.assertEqual(data['error']['code'], -32601)
            else:
                self.assertIn('result', data)
        self.assertIsNone(self.reply(b'/mcp', b'POST', b'{broken')[1])
        self.assertIsNone(self.reply(b'/mcp', b'POST', b'[]')[1])
        self.assertIsNone(self.reply(b'/mcp', b'POST', b'{"jsonrpc":"2.0","method":"tools/list"}')[1])


class Patch(WorkspaceTest):
    def setUp(self):
        super().setUp()
        fixture = TASK / 'underlag/http.py'
        if fixture.is_file():
            self.upstream = fixture.read_text()
        else:
            # Standalone stdlib fallback after these files are merged into a repository.
            # The supplied 0.9.10 source is used whenever the task fixture is present.
            self.upstream = (
                'import os\nclass Error(Resource):\n'
                '    def __init__(self, factory, error_code="404"):\n'
                '        self.factory = factory\n'
                '        self.error_code = error_code\n'
                '    def err_page(self, request):\n'
                '        return "error"\n' + p.HTTP_OLD + '\n'
                '    def render_GET(self, request):\n'
                '        return self.err_page(request).encode()\n'
                '    render_POST = render_GET\n'
                '    render_PUT = render_GET\n'
                '    render_HEAD = render_GET\n'
                '    render_CONNECT = render_GET\n'
                '    render_DELETE = render_GET\n'
                'class CanaryHTTP:\n'
                '    def getService(self):\n'
                '        root = object()\n'
                '        root.putChild(b"index.html", page)\n')
        self.target = self.dir / 'http.py'
        self.target.write_text(self.upstream)

    def test_upstream_patch_and_idempotence(self):
        self.assertEqual(p.opencanary_http(str(self.target)), 0)
        code = self.target.read_text()
        compile(code, str(self.target), 'exec')
        self.assertIn('root.putChild(b"robots.txt", Error(factory=self))', code)
        self.assertIn(w.__file__ and (ROOT / 'honeypot/webreply.py').read_text(), code)
        self.assertEqual(self.target.with_suffix('.py.orig').read_text(), self.upstream)
        self.assertEqual(p.opencanary_http(str(self.target)), 3)
        self.assertEqual(self.target.read_text(), code)

    def test_migration_from_exact_live_legacy_patch(self):
        legacy_path = TASK / 'kod/honeypot/patches.py'
        if legacy_path.is_file():
            legacy = runpy.run_path(str(legacy_path))
            self.assertEqual(legacy['opencanary_http'](str(self.target)), 0)
        else:
            self.target.with_suffix('.py.orig').write_text(self.upstream)
            self.target.write_text(self.upstream.replace(p.HTTP_OLD, p.HTTP_LEGACY))
        self.assertEqual(p.opencanary_http(str(self.target)), 0)
        self.assertIn('Huginn webreply v1', self.target.read_text())
        self.assertEqual(self.target.with_suffix('.py.orig').read_text(), self.upstream)

    def test_unknown_patch_or_missing_backup_is_not_overwritten(self):
        for current, backup in ((self.upstream.replace(p.HTTP_OLD, p.HTTP_LEGACY), None),
                                (self.upstream.replace(p.HTTP_OLD, p.HTTP_LEGACY) + '\n# local change\n', self.upstream),
                                (self.upstream.replace('def render(self, request):', 'def altered(self, request):'), None)):
            self.target.write_text(current)
            orig = self.target.with_suffix('.py.orig')
            orig.unlink(missing_ok=True)
            if backup:
                orig.write_text(backup)
            self.assertEqual(p.opencanary_http(str(self.target)), 1)
            self.assertEqual(self.target.read_text(), current)

    def test_stale_backup_after_package_upgrade_is_refreshed(self):
        self.target.with_suffix('.py.orig').write_text('old upstream')
        self.assertEqual(p.opencanary_http(str(self.target)), 0)
        self.assertEqual(self.target.with_suffix('.py.orig').read_text(), self.upstream)

    def error_class(self):
        self.assertEqual(p.opencanary_http(str(self.target)), 0)
        # Execute the real upstream Error class and injected helper with a tiny Resource stand-in.
        tree = ast.parse(self.target.read_text())
        error = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == 'Error')
        class Resource:
            def render(self, request):
                return getattr(self, 'render_' + request.method.decode())(request)
        env = {'Resource': Resource, 'os': os}
        exec(p.HTTP_HELPER, env)
        env['HPW_BAIT'] = str(self.bait)
        exec(compile(ast.Module(body=[error], type_ignores=[]), str(self.target), 'exec'), env)
        for code in ('404', '403'):
            (self.skin / (code + '.html')).write_text('error [[URL]] [[BANNER]]')
        self.factory.banner = b'nginx'
        self.factory.skin = 'qnap'
        self.factory.logger = types.SimpleNamespace(LOG_HTTP_GET=1000)
        self.factory.logs = []
        self.factory.log = lambda data, **kw: self.factory.logs.append(data)
        return env['Error']

    def request(self, uri=b'/.env', method=b'GET', body=b''):
        req = types.SimpleNamespace(uri=uri, path=uri.split(b'?')[0], method=method, content=io.BytesIO(body),
                                    transport=object(), headers={}, status=None)
        req.getHeader = lambda name: 'test-agent'
        req.setHeader = lambda name, value: req.headers.update({name: value})
        req.setResponseCode = lambda status: setattr(req, 'status', status)
        return req

    def test_render_status_body_headers_logging_and_head(self):
        Error = self.error_class()
        for method in (b'GET', b'HEAD', b'POST', b'PUT'):
            req = self.request(b'/api/.env.local?x=1', method, b'A' * 1000)
            result = Error(self.factory).render(req)
            self.assertEqual(req.status, 200)
            self.assertEqual(result == b'', method == b'HEAD')
            log = self.factory.logs[-1]
            self.assertEqual(log['STATUS'], req.status)
            self.assertEqual(log['HP_REPLY'], 'env')
            self.assertEqual(log['PATH'], '/api/.env.local?x=1')
            self.assertNotIn('HP_ROBOTS', log)
            self.assertEqual(req.headers[b'X-Content-Type-Options'], b'nosniff')
            if method in (b'POST', b'PUT'):
                self.assertEqual(len(log['BODY']), 500)
                self.assertEqual(req.content.tell(), 0)
        req = self.request(b'/not-known')
        self.assertIn(b'error', Error(self.factory).render(req))
        self.assertEqual(req.status, 404)
        self.assertNotIn('HP_REPLY', self.factory.logs[-1])
        req = self.request()
        Error(self.factory, '403').render(req)
        self.assertEqual(req.status, 403)
        self.assertNotIn('HP_REPLY', self.factory.logs[-1])

    def test_render_robots_and_inert_input(self):
        Error = self.error_class()
        req = self.request(b'/robots.txt')
        body = Error(self.factory).render(req)
        self.assertEqual(req.status, 200)
        self.assertEqual(body.count(b'Disallow:'), 4)
        self.assertNotIn('HP_REPLY', self.factory.logs[-1])
        probe = w.hpw_robots(self.ident)[0].encode()
        Error(self.factory).render(self.request(probe))
        self.assertEqual(self.factory.logs[-1]['HP_ROBOTS'], '1')
        req = self.request(b'/.env', b'CONNECT')
        Error(self.factory).render(req)
        self.assertEqual(req.status, 404)
        req = self.request(b'/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php', b'POST', b'<?php system("touch should-not-exist"); ?>')
        self.assertIn(b'uid=33', Error(self.factory).render(req))
        self.assertFalse((self.dir / 'should-not-exist').exists())
        self.assertEqual(len(self.factory.logs), 4)


    def test_robots_prefix_and_non_get_logged(self):
        Error = self.error_class()
        path = next(p for p in w.hpw_robots(self.ident) if p.endswith('/')).encode()
        req = self.request(path + b'export.ini')
        Error(self.factory).render(req)
        self.assertEqual(req.status, 200)
        self.assertEqual(self.factory.logs[-1]['HP_ROBOTS'], '1')
        req = self.request(path, b'DELETE')
        Error(self.factory).render(req)
        self.assertEqual(req.status, 404)
        self.assertEqual(self.factory.logs[-1]['HP_ROBOTS'], '1')
        self.assertNotIn('HP_REPLY', self.factory.logs[-1])

    def test_missing_bundle_and_logger_failure_keep_response(self):
        Error = self.error_class()
        (self.skin / w.HPW_BUNDLE).unlink()
        req = self.request()
        Error(self.factory).render(req)
        self.assertEqual(req.status, 404)
        self.assertNotIn('HP_REPLY', self.factory.logs[-1])
        w.hpw_write_skin(self.skin, self.ident, self.bait)
        self.factory._hpw_cache = None
        self.factory.log = mock_log = mock.Mock(side_effect=RuntimeError('logging unavailable'))
        req = self.request()
        body = Error(self.factory).render(req)
        self.assertEqual(req.status, 200)
        self.assertIn(self.values['server_env_db'].encode(), body)
        mock_log.assert_called_once()


class Identity(WorkspaceTest):
    def test_every_skin_including_builtin_has_artifacts(self):
        with mock.patch.object(identity, 'hpw_write_skin', side_effect=lambda folder, ident: w.hpw_write_skin(folder, ident, self.bait)):
            for ident in identity.IDENTITIES.values():
                folder = Path(identity.build_skin(ident, ident['models'][0], str(self.dir)))
                self.assertTrue((folder / 'robots.txt').is_file())
                self.assertTrue((folder / w.HPW_BUNDLE).is_file())
                self.assertIn('name="username"', (folder / 'index.html').read_text())
                self.assertEqual(os.stat(folder / w.HPW_BUNDLE).st_mode & 0o777, 0o644)

    def setup_identity(self):
        skins = self.dir / 'skins'
        skins.mkdir()
        state = self.dir / 'state'
        state.mkdir()
        conf = {'http.port': 8080, 'http.skin': 'nasLogin', 'http.banner': 'nginx', 'http.skindir': '', 'https.skin': 'nasLogin'}
        for key, value in (('OC_HOME', str(self.dir)), ('SKINS', str(skins)), ('STATE', str(state)), ('HISTORY', str(state / 'history')), ('PENDING', str(state / 'pending'))):
            patcher = mock.patch.object(identity, key, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        for name, kw in [('read_conf', {'side_effect': lambda: dict(conf)}), ('write_conf', {'side_effect': lambda change: conf.update(change)}),
                         ('ensure_cert', {'return_value': ('/fake/cert', '/fake/key')}), ('restart', {}), ('serving', {'return_value': True}),
                         ('hpw_write_skin', {'side_effect': lambda folder, ident: w.hpw_write_skin(folder, ident, self.bait)})]:
            patcher = mock.patch.object(identity, name, **kw)
            patcher.start()
            self.addCleanup(patcher.stop)
        original = identity.build_skin
        patcher = mock.patch.object(identity, 'build_skin', side_effect=lambda ident, model: original(ident, model, str(skins)))
        patcher.start()
        self.addCleanup(patcher.stop)
        identity.add_history(1700000000, self.ident, 'QNAP TS-264')
        return conf

    def test_refresh_preserves_history_label_and_updates_bait(self):
        conf = self.setup_identity()
        before = Path(identity.HISTORY).read_bytes()
        identity.apply_identity(self.ident, refresh=True)
        self.assertEqual(Path(identity.HISTORY).read_bytes(), before)
        self.assertIn('TS-264', Path(conf['http.skindir'], 'index.html').read_text())
        first = Path(conf['http.skindir'], 'robots.txt').read_bytes()
        self.bait.unlink()
        identity.apply_identity(self.ident, refresh=True)
        self.assertEqual(Path(identity.HISTORY).read_bytes(), before)
        self.assertEqual(Path(conf['http.skindir'], 'robots.txt').read_bytes(), first)
        self.assertEqual(json.loads(Path(conf['http.skindir'], w.HPW_BUNDLE).read_text())['replies'], {})
        self.assertFalse(Path(identity.PENDING).exists())

    def test_refresh_failure_rolls_back_and_keeps_old_skin(self):
        conf = self.setup_identity()
        identity.apply_identity(self.ident, refresh=True)
        old = dict(conf)
        before = Path(identity.HISTORY).read_bytes()
        with mock.patch.object(identity, 'serving', side_effect=[False, True]):
            with self.assertRaises(SystemExit):
                identity.apply_identity(self.ident, refresh=True)
        self.assertEqual(conf, old)
        self.assertEqual(Path(identity.HISTORY).read_bytes(), before)
        self.assertTrue(Path(conf['http.skindir']).is_dir())

    def test_scripts_apply_patch_without_package_upgrade(self):
        update = (ROOT / 'update-honeypot.sh').read_text()
        self.assertIn('if [ "$UP_CANARY" = 0 ]', update)
        self.assertIn('honeypot/webreply.py', update)
        setup = (ROOT / 'honeypot/setup-identity.sh').read_text()
        self.assertIn('/usr/local/sbin/hp-identity refresh', setup)
        self.assertIn('webreply.py', setup)
        for path in (ROOT / 'install-honeypot.sh', ROOT / 'update-honeypot.sh', ROOT / 'honeypot/setup-identity.sh'):
            subprocess.run(['bash', '-n', str(path)], check=True)


    def test_interrupted_refresh_same_second_as_history_is_undone(self):
        conf = self.setup_identity()
        stamp = identity.history()[-1][0]
        before = dict(conf)
        identity.save_pending(before, stamp, self.ident['id'], refresh=True)
        conf['http.banner'] = 'half changed'
        identity.recover()
        self.assertEqual(conf, before)

    def test_committed_refresh_is_not_undone(self):
        conf = self.setup_identity()
        identity.save_pending(dict(conf), 1700000100, self.ident['id'], refresh=True, committed=True)
        conf['http.banner'] = 'committed'
        identity.recover()
        self.assertEqual(conf['http.banner'], 'committed')
        self.assertFalse(Path(identity.PENDING).exists())


if __name__ == '__main__':
    unittest.main()
