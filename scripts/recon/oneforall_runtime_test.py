#!/usr/bin/env python3
"""Offline fixtures only: no scanner binary, DNS, HTTP, SSH or service actions."""
import contextlib
import errno
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import uuid

try:
    from . import oneforall_prepare as prepare
    from . import oneforall_runner as runtime
except ImportError:
    import oneforall_prepare as prepare
    import oneforall_runner as runtime


UTILS = '''import platform
from stat import S_IXUSR
from config import settings

def unrelated_chmod(path):
    path.chmod(S_IXUSR)

def get_massdns_path(massdns_dir):
    path = settings.brute_massdns_path
    if path:
        return path
    system = platform.system().lower()
    machine = platform.machine().lower()
    name = f'massdns_{system}_{machine}'
    path = massdns_dir.joinpath(name)
    path.chmod(S_IXUSR)
    return path
'''
DEFAULT = '''import pathlib
relative_directory = pathlib.Path(__file__).parent.parent
data_storage_dir = relative_directory.joinpath('data')
result_save_dir = relative_directory.joinpath('results')
temp_save_dir = result_save_dir.joinpath('temp')
authoritative_dns_path = data_storage_dir.joinpath('authoritative_dns.txt')
brute_massdns_path = None
'''
SETTING = '''import pathlib
relative_directory = pathlib.Path(__file__).parent.parent
data_storage_dir = relative_directory.joinpath('data')
operator_setting = 'preserve-me'
'''
LOG = '''import pathlib
relative_directory = pathlib.Path(__file__).parent.parent
result_save_dir = relative_directory.joinpath('results')
log_path = result_save_dir.joinpath('oneforall.log')
log_path.write_text('fixture log', encoding='utf-8')
'''
CONFIG = '''from types import SimpleNamespace
from . import default, setting
settings = SimpleNamespace()
for module in (default, setting):
    for key in dir(module):
        if not key.startswith('__'):
            setattr(settings, key, getattr(module, key))
'''
ENTRY = '''import json
import pathlib
import sys
from config import settings
from config import log
from common.utils import get_massdns_path
get_massdns_path(pathlib.Path(__file__).parent / 'thirdparty' / 'massdns')
(settings.result_save_dir / 'result.sqlite3').write_bytes(b'fixture only')
(settings.data_storage_dir / 'authoritative_dns.txt').write_text('fixture only')
print(json.dumps({'argv': sys.argv[1:], 'cwd': str(pathlib.Path.cwd()),
                  'results': str(settings.result_save_dir),
                  'data': str(settings.data_storage_dir), 'operator': settings.operator_setting}))
print('Finished OneForAll', file=sys.stderr)
raise SystemExit(2)
'''


class OneForAllRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name).resolve()
        self.installation = self.base / 'OneForAll'
        self.installation.mkdir()
        self.launcher = self.base / 'bin' / 'oneforall'
        self.launcher.parent.mkdir()
        self.execution = str(uuid.uuid4())
        self.artifacts = self.base / 'executions' / self.execution
        self.artifacts.mkdir(mode=0o700, parents=True)
        self.env = {'CSAI_WORKSPACE_SANDBOX': '1', 'CSAI_EXECUTION_ID': self.execution,
                    'CSAI_ARTIFACT_DIR': str(self.artifacts)}
        for relative, content in {
            'common/__init__.py': '', 'common/utils.py': UTILS,
            'config/__init__.py': CONFIG, 'config/default.py': DEFAULT,
            'config/setting.py': SETTING, 'config/log.py': LOG,
            'config/api.py': "secret = 'must-not-be-copied'\n", 'oneforall.py': ENTRY,
            'data/subdomains.txt': 'www\napi\n', 'data/public_suffix_list.dat': 'fixture suffixes',
            'thirdparty/massdns/massdns_linux_x86_64': 'offline placeholder, never executed',
        }.items():
            path = self.installation / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding='utf-8')
        # Portable fixtures use a Linux layout; no foreign binary is executed.
        for name, value in [('system', 'Linux'), ('machine', 'x86_64')]:
            patcher = mock.patch.object(runtime.platform, name, return_value=value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def prepare(self):
        prepare.prepare(self.installation, Path(sys.executable), self.launcher)

    def test_preparation_is_idempotent_and_preserves_operator_configuration(self):
        original_api = (self.installation / 'config/api.py').read_bytes()
        self.prepare()
        before = {name: (self.installation / name).read_bytes() for name in runtime.MANAGED_FILES}
        self.prepare()
        prepare.prepare(self.installation, Path(sys.executable), self.launcher, check=True)
        self.assertEqual(before, {name: (self.installation / name).read_bytes() for name in runtime.MANAGED_FILES})
        self.assertEqual(original_api, (self.installation / 'config/api.py').read_bytes())
        self.assertIn("operator_setting = 'preserve-me'", (self.installation / 'config/setting.py').read_text())
        self.assertEqual(UTILS, (self.installation / 'common/utils.py.csai-original').read_text())
        self.assertIn('path.chmod(S_IXUSR)', (self.installation / 'common/utils.py').read_text())  # unrelated function unchanged
        self.assertIn(str(Path(sys.executable).absolute()), self.launcher.read_text())
        self.assertIn(' "$@"', self.launcher.read_text())
        if os.name == 'posix':
            self.assertEqual(0o755, stat.S_IMODE(runtime.massdns_path(self.installation).stat().st_mode))

    def test_unknown_upstream_shape_is_rejected_before_any_write(self):
        path = self.installation / 'common/utils.py'
        path.write_text(UTILS.replace('    path.chmod(S_IXUSR)\n    return path', '    path.chmod(0o777)\n    return path'))
        before = (self.installation / 'config/default.py').read_bytes()
        with self.assertRaisesRegex(runtime.AdapterError, 'unsupported_massdns_chmod'):
            self.prepare()
        self.assertEqual(before, (self.installation / 'config/default.py').read_bytes())
        self.assertFalse(self.launcher.exists())
        self.assertFalse((self.installation / runtime.MANIFEST).exists())

    def test_custom_storage_is_not_silently_overwritten(self):
        path = self.installation / 'config/setting.py'
        path.write_text(SETTING.replace("relative_directory.joinpath('data')", "pathlib.Path('/operator/data')"))
        with self.assertRaisesRegex(runtime.AdapterError, 'refusing to overwrite'):
            self.prepare()
        self.assertIn('/operator/data', path.read_text())

    def test_changed_source_fails_runtime_check(self):
        self.prepare()
        path = self.installation / 'common/utils.py'
        path.write_text(path.read_text() + '\n# operator edit\n')
        with self.assertRaisesRegex(runtime.AdapterError, 'prepared_source_changed'):
            runtime.validate_installation(self.installation)

    def test_runtime_permissions_never_chmod_even_on_read_only_filesystem(self):
        self.prepare()
        binary = runtime.massdns_path(self.installation)
        with mock.patch.object(Path, 'chmod', side_effect=OSError(errno.EROFS, 'Read-only file system')):
            self.assertEqual(binary, runtime.require_massdns_executable(binary))
            runtime.validate_installation(self.installation)
            prepare.prepare(self.installation, Path(sys.executable), self.launcher, check=True)

    def test_missing_or_nonexecutable_binary_has_clear_failure(self):
        with self.assertRaisesRegex(runtime.AdapterError, 'massdns_missing_or_not_executable'):
            runtime.require_massdns_executable(self.installation / 'missing')
        with mock.patch.object(runtime.os, 'access', return_value=False):
            with self.assertRaisesRegex(runtime.AdapterError, 'rerun oneforall_prepare.py'):
                runtime.require_massdns_executable(runtime.massdns_path(self.installation))

    def test_execution_requires_service_bound_artifact_root(self):
        for patch, message in [({'CSAI_WORKSPACE_SANDBOX': ''}, 'sandbox_required'),
                               ({'CSAI_EXECUTION_ID': '../escape'}, 'uuid_required'),
                               ({'CSAI_ARTIFACT_DIR': str(self.base)}, 'artifact_directory_required'),
                               ({'CSAI_ARTIFACT_DIR': 'relative'}, 'absolute_path')]:
            with self.subTest(patch=patch), self.assertRaisesRegex(runtime.AdapterError, message):
                runtime.artifact_root(dict(self.env, **patch))

    def test_symlink_artifact_and_data_are_rejected(self):
        link = self.base / 'linked'
        try:
            link.symlink_to(self.artifacts, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest('symlink creation unavailable on this platform')
        with self.assertRaisesRegex(runtime.AdapterError, 'symlink_path_rejected'):
            runtime.artifact_root(dict(self.env, CSAI_ARTIFACT_DIR=str(link)))
        (self.installation / 'data/leak').symlink_to(self.installation / 'config/api.py')
        self.prepare()
        with self.assertRaisesRegex(runtime.AdapterError, 'data_symlink_rejected'):
            runtime.prepare_run(self.installation, self.env)
        self.assertEqual([], list(self.artifacts.iterdir()))

    def test_distinct_runs_copy_only_data_and_preserve_originals(self):
        self.prepare()
        first = runtime.prepare_run(self.installation, self.env)
        second = runtime.prepare_run(self.installation, self.env)
        self.assertNotEqual(first, second)
        self.assertEqual({'data', 'results'}, {p.name for p in first.iterdir()})
        (first / 'data/subdomains.txt').write_text('modified fixture')
        self.assertEqual('www\napi\n', (self.installation / 'data/subdomains.txt').read_text())
        self.assertEqual('www\napi\n', (second / 'data/subdomains.txt').read_text())
        self.assertFalse(any('must-not-be-copied' in p.read_text(errors='ignore') for p in first.rglob('*') if p.is_file()))

    def test_copy_size_limit_fails_and_cleans_partial_run(self):
        self.prepare()
        with mock.patch.object(runtime, 'MAX_DATA_BYTES', 3):
            with self.assertRaisesRegex(runtime.AdapterError, 'data_size'):
                runtime.prepare_run(self.installation, self.env)
        self.assertEqual([], list(self.artifacts.iterdir()))

    def test_fixture_entry_preserves_exit_two_arguments_and_relative_path_semantics(self):
        self.prepare()
        argv = ['--target', 'example.invalid', '--path', 'explicit relative.csv', 'run']
        stdout, stderr = io.StringIO(), io.StringIO()
        old_path, old_argv, old_bytecode = sys.path[:], sys.argv[:], sys.dont_write_bytecode
        old_umask = os.umask(0o077)
        before = {p: p.read_bytes() for p in self.installation.rglob('*') if p.is_file()}
        try:
            with mock.patch.dict(os.environ, self.env), mock.patch.object(runtime, '__file__', str(self.installation / 'oneforall_runner.py')):
                with mock.patch.dict(sys.modules, {'oneforall_runner': runtime}), contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                    with mock.patch.object(Path, 'chmod', side_effect=OSError(errno.EROFS, 'read only')):
                        with self.assertRaises(SystemExit) as caught:
                            runtime.main(argv)
            self.assertEqual(2, caught.exception.code)  # Finished is not success.
            record = json.loads(stdout.getvalue())
            self.assertEqual(argv, record['argv'])
            self.assertEqual(str(Path.cwd()), record['cwd'])
            self.assertEqual('preserve-me', record['operator'])
            results = Path(record['results'])
            self.assertTrue(results.is_relative_to(self.artifacts))
            self.assertTrue((results / 'result.sqlite3').is_file())
            self.assertTrue((results / 'oneforall.log').is_file())
            self.assertIn('Finished OneForAll', stderr.getvalue())
            self.assertEqual(before, {p: p.read_bytes() for p in before})
        finally:
            for name in list(sys.modules):
                if name in ('config', 'common') or name.startswith(('config.', 'common.')):
                    sys.modules.pop(name, None)
            sys.path[:], sys.argv[:], sys.dont_write_bytecode = old_path, old_argv, old_bytecode
            os.umask(old_umask)

    def test_unmanaged_execution_fails_without_importing_upstream(self):
        self.prepare()
        with mock.patch.dict(os.environ, {}, clear=True), mock.patch.object(runtime, '__file__', str(self.installation / 'oneforall_runner.py')):
            with mock.patch.object(runtime.runpy, 'run_path') as upstream, mock.patch.object(runtime.os, 'umask'):
                with contextlib.redirect_stderr(io.StringIO()) as diagnostic:
                    self.assertEqual(78, runtime.main(['--target', 'example.invalid', 'run']))
                upstream.assert_not_called()
                self.assertIn('sandbox_required', diagnostic.getvalue())

    def test_upstream_oserror_keeps_original_meaning(self):
        # The adapter must not turn an upstream network error into a fabricated
        # filesystem diagnosis. No upstream code or network is executed here.
        old_path, old_argv, old_bytecode = sys.path[:], sys.argv[:], sys.dont_write_bytecode
        try:
            with mock.patch.dict(os.environ, self.env), mock.patch.object(runtime, 'prepare_run', return_value=self.artifacts / 'oneforall-fixture'):
                with mock.patch.object(runtime.os, 'umask'), mock.patch.object(runtime.runpy, 'run_path', side_effect=ConnectionRefusedError(errno.ECONNREFUSED, 'fixture')):
                    with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(ConnectionRefusedError):
                        runtime.main(['--target', 'example.invalid', 'run'])
        finally:
            sys.path[:], sys.argv[:], sys.dont_write_bytecode = old_path, old_argv, old_bytecode

    def test_help_is_offline_without_artifact_environment(self):
        result = subprocess.run([sys.executable, '-B', str(Path(runtime.__file__)), '--help'],
                                capture_output=True, text=True, check=False, timeout=10)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn('--target', result.stdout)
        self.assertIn('--check-runtime', result.stdout)

    def test_venv_python_symlink_is_not_resolved_in_launcher(self):
        python = self.base / 'venv/bin/python'
        python.parent.mkdir(parents=True)
        try:
            python.symlink_to(sys.executable)
        except (OSError, NotImplementedError):
            self.skipTest('symlink creation unavailable on this platform')
        prepare.prepare(self.installation, python, self.launcher)
        self.assertIn(str(python), self.launcher.read_text())

    def test_installer_has_pinned_official_jsluice_cgo_dependency(self):
        installer = Path(__file__).resolve().parents[2] / 'install-tools-ubuntu24.sh'
        text = installer.read_text(encoding='utf-8')
        self.assertIn('v0.0.0-20240110145140-0ddfab153e06', text)
        self.assertIn('jsluice|jsluice|script|install_jsluice', text)
        function = text.split('install_jsluice() {', 1)[1].split('\n}\n', 1)[0]
        for expected in ('github.com/BishopFox/jsluice/cmd/jsluice@', 'build-essential', 'CGO_ENABLED=1'):
            self.assertIn(expected, function)
        oneforall = text.split('install_oneforall() {', 1)[1].split('\n}\n', 1)[0]
        self.assertNotIn('already_ok', oneforall)  # old launcher must receive fix
        self.assertNotIn('rm -rf', oneforall)
        self.assertIn('--python "$python"', oneforall)


if __name__ == '__main__':
    unittest.main()
