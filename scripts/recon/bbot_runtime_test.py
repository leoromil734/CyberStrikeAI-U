#!/usr/bin/env python3
"""Offline fixtures only: no BBOT binary, DNS, HTTP, SSH or service actions.

Covers the managed launcher contract: sandbox-only execution, managed BBOT home
layout, argument injection/expansion, and the runtime synopsis that
``csai-bbot --check-runtime`` prints for tool-doctor flag checks.
"""
import os
import re
import unittest
from pathlib import Path
import tempfile
from unittest import mock
import uuid

try:
    from . import bbot_runner as runner
except ImportError:
    import bbot_runner as runner


REPO_ROOT = Path(__file__).resolve().parents[2]
BBOT_YAML = REPO_ROOT / "tools" / "bbot.yaml"


def symlinks_supported(directory):
    """Windows without developer mode cannot create symlinks; skip there."""
    link = Path(directory) / ".symlink-probe"
    try:
        link.symlink_to(Path(directory))
    except (OSError, NotImplementedError):
        return False
    link.unlink()
    return True


class AdapterErrorMessagesTests(unittest.TestCase):
    def test_sandbox_marker_is_required(self):
        with self.assertRaises(runner.AdapterError):
            runner.artifact_root({})


class ManagedArgTests(unittest.TestCase):
    def test_multi_value_flags_expand_to_separate_tokens(self):
        argv = runner.expand_multi_value_args(
            ["-t", "a.example, b.example", "-p", "subdomain-enum web", "-rf", "passive", "--json"]
        )
        self.assertEqual(
            argv,
            ["-t", "a.example", "b.example", "-p", "subdomain-enum", "web", "-rf", "passive", "--json"],
        )

    def test_config_values_are_never_split(self):
        argv = runner.expand_multi_value_args(["-c", "modules.foo.bar_key=x,y", "speculate=False"])
        self.assertEqual(argv, ["-c", "modules.foo.bar_key=x,y", "speculate=False"])

    def test_managed_options_are_injected_once(self):
        home = Path("/home/.bbot")
        out = Path("/artifact/bbot-out")
        argv = runner.inject_managed_args(["-t", "example.com"], home, out)
        self.assertEqual(argv.count("--no-deps"), 1)
        self.assertEqual(argv.count("-y"), 1)
        self.assertEqual(argv.count("--no-color"), 1)
        self.assertIn("home=" + str(home), argv)
        self.assertEqual(argv[argv.index("-o") + 1], str(out))

    def test_caller_options_win(self):
        argv = runner.inject_managed_args(
            ["-t", "example.com", "-c", "home=/custom", "--no-deps", "-o", "/custom-out", "-y", "--no-color"],
            Path("/home/.bbot"),
            Path("/artifact/bbot-out"),
        )
        self.assertEqual(argv.count("home=/custom"), 1)
        self.assertNotIn("home=/home/.bbot", argv)
        self.assertEqual(argv.count("--no-deps"), 1)
        self.assertEqual(argv.count("-o"), 1)
        self.assertEqual(argv[argv.index("-o") + 1], "/custom-out")
        self.assertEqual(argv.count("--no-color"), 1)

    def test_deps_config_disables_forced_no_deps(self):
        argv = runner.inject_managed_args(
            ["-t", "example.com", "-c", "deps.behavior=ignore_failed"],
            Path("/home/.bbot"),
            Path("/artifact/bbot-out"),
        )
        self.assertNotIn("--no-deps", argv)


class ArtifactRootTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="csai-bbot-artifact-"))
        self.execution = str(uuid.uuid4())
        self.artifact = self.root / "executions" / self.execution
        self.artifact.mkdir(parents=True, mode=0o700)

    def base_env(self):
        return {
            "CSAI_WORKSPACE_SANDBOX": "1",
            "CSAI_EXECUTION_ID": self.execution,
            "CSAI_ARTIFACT_DIR": str(self.artifact),
        }

    def test_sandbox_marker_is_required(self):
        env = self.base_env()
        env.pop("CSAI_WORKSPACE_SANDBOX")
        with self.assertRaises(runner.AdapterError):
            runner.artifact_root(env)

    def test_service_execution_uuid_is_required(self):
        env = self.base_env()
        env["CSAI_EXECUTION_ID"] = "not-a-uuid"
        with self.assertRaises(runner.AdapterError):
            runner.artifact_root(env)

    def test_execution_scoped_artifact_directory_is_required(self):
        env = self.base_env()
        env["CSAI_ARTIFACT_DIR"] = str(self.root / "executions")
        with self.assertRaises(runner.AdapterError):
            runner.artifact_root(env)

    @unittest.skipUnless(os.name == "posix", "POSIX permission bits are required")
    def test_group_or_world_writable_artifact_directory_is_rejected(self):
        self.artifact.chmod(0o777)
        with self.assertRaises(runner.AdapterError):
            runner.artifact_root(self.base_env())

    def test_valid_execution_artifact_directory_is_accepted(self):
        self.assertEqual(runner.artifact_root(self.base_env()), self.artifact)


class ManagedHomeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="csai-bbot-home-"))
        if not symlinks_supported(self.tmp):
            self.skipTest("symlinks unavailable on this platform")
        self.prepared = self.tmp / "prepared"
        self.prepared_tools = self.prepared / "tools"
        self.prepared_cache = self.prepared / "cache"
        self.prepared_config = self.prepared / "config"
        for path in (self.prepared_tools, self.prepared_cache, self.prepared_config):
            path.mkdir(parents=True)
        (self.prepared_tools / "massdns").write_text("fixture", encoding="utf-8")
        (self.prepared_cache / "cached-model").write_text("fixture", encoding="utf-8")
        (self.prepared_config / "secrets.yml").write_text("modules: {}", encoding="utf-8")
        self.home = self.tmp / "workspace-home"
        self.home.mkdir()
        patches = [
            mock.patch.object(runner, "PREPARED_HOME", self.prepared),
            mock.patch.object(runner, "PREPARED_TOOLS", self.prepared_tools),
            mock.patch.object(runner, "PREPARED_CACHE", self.prepared_cache),
            mock.patch.object(runner, "PREPARED_CONFIG", self.prepared_config),
            mock.patch.dict(os.environ, {"HOME": str(self.home)}),
        ]
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)

    def test_tools_are_seeded_into_a_writable_workspace_directory(self):
        bbot_home = runner.prepare_home(self.home / ".bbot")
        tools = bbot_home / "tools"
        self.assertTrue(tools.is_dir())
        self.assertFalse(tools.is_symlink(), "BBOT requires a writable tools directory")
        seeded = tools / "massdns"
        self.assertTrue(seeded.is_file() and not seeded.is_symlink())
        self.assertEqual(seeded.read_text(encoding="utf-8"), "fixture")
        self.assertTrue((bbot_home / runner.TOOLS_SEED_MARKER).is_file())

    def test_large_prepared_tools_are_linked_instead_of_copied(self):
        with mock.patch.object(runner, "TOOLS_COPY_LIMIT", 1):
            bbot_home = runner.prepare_home(self.home / ".bbot")
        seeded = bbot_home / "tools" / "massdns"
        self.assertTrue(seeded.is_symlink())
        self.assertEqual(os.path.realpath(seeded), os.path.realpath(self.prepared_tools / "massdns"))

    def test_cache_is_seeded_once_and_keeps_local_changes(self):
        bbot_home = runner.prepare_home(self.home / ".bbot")
        cache = bbot_home / "cache"
        self.assertTrue((cache / "cached-model").is_file())
        self.assertTrue((cache / runner.CACHE_SEED_MARKER).is_file())
        local = cache / "runtime-download"
        local.write_text("local", encoding="utf-8")
        runner.prepare_home(bbot_home)
        self.assertTrue(local.is_file(), "re-seeding must not wipe workspace state")

    def test_prepared_config_is_linked_when_workspace_has_none(self):
        runner.prepare_home(self.home / ".bbot")
        linked = self.home / ".config" / "bbot" / "secrets.yml"
        self.assertTrue(linked.is_symlink())
        self.assertEqual(os.path.realpath(linked), os.path.realpath(self.prepared_config / "secrets.yml"))

    def test_existing_workspace_config_is_kept(self):
        existing = self.home / ".config" / "bbot" / "secrets.yml"
        existing.parent.mkdir(parents=True)
        existing.write_text("modules: {custom: yes}", encoding="utf-8")
        runner.prepare_home(self.home / ".bbot")
        self.assertFalse(existing.is_symlink())
        self.assertIn("custom", existing.read_text(encoding="utf-8"))

    def test_tools_symlink_is_rejected(self):
        bbot_home = self.home / ".bbot"
        bbot_home.mkdir(parents=True)
        (bbot_home / "tools").symlink_to(self.prepared_tools)
        with self.assertRaises(runner.AdapterError):
            runner.prepare_home(bbot_home)

    def test_missing_prepared_cache_is_survivable(self):
        import shutil

        shutil.rmtree(self.prepared_cache)
        bbot_home = runner.prepare_home(self.home / ".bbot")
        self.assertTrue((bbot_home / "cache" / runner.CACHE_SEED_MARKER).is_file())

    def test_seed_skips_ansible_scratch_but_keeps_nested_state(self):
        scratch = self.prepared_cache / "depsinstaller" / "playbook_deadbeef" / "artifacts"
        scratch.mkdir(parents=True)
        (scratch / "root-only-log").write_text("fixture", encoding="utf-8")
        status = self.prepared_cache / "depsinstaller" / "command_status"
        status.mkdir()
        (status / "pip-marker").write_text("fixture", encoding="utf-8")
        bbot_home = runner.prepare_home(self.home / ".bbot")
        cache = bbot_home / "cache"
        self.assertFalse((cache / "depsinstaller" / "playbook_deadbeef").exists())
        self.assertTrue((cache / "depsinstaller" / "command_status" / "pip-marker").is_file())
        self.assertTrue((cache / "cached-model").is_file())

    def test_seed_failure_keeps_workspace_cache_without_marker(self):
        import shutil

        with mock.patch.object(runner, "copy_prepared_cache", return_value=["cached-model: denied"]):
            bbot_home = runner.prepare_home(self.home / ".bbot")
        cache = bbot_home / "cache"
        self.assertFalse((cache / runner.CACHE_SEED_MARKER).exists())
        self.assertEqual(list(cache.iterdir()), [])
        shutil.rmtree(self.prepared_cache, ignore_errors=True)


class RuntimeCheckTests(unittest.TestCase):
    def test_check_runtime_reports_missing_entrypoint(self):
        with mock.patch.object(runner, "BBOT_ENTRY", Path("/nonexistent/bbot")):
            with mock.patch("sys.stdout") as stdout, mock.patch("sys.stderr") as stderr:
                self.assertEqual(runner.check_runtime(), 1)
        printed = "".join(call.args[0] for call in stdout.write.call_args_list if call.args)
        self.assertIn("managed BBOT launcher", printed)
        problems = "".join(call.args[0] for call in stderr.write.call_args_list if call.args)
        self.assertIn("missing bbot entrypoint", problems)

    def test_synopsis_covers_every_declared_yaml_flag(self):
        text = BBOT_YAML.read_text(encoding="utf-8")
        flags = set(re.findall(r'^\s*flag:\s*"([^"]+)"', text, flags=re.MULTILINE))
        self.assertTrue(flags, "tools/bbot.yaml declares no flags")
        missing = sorted(
            flag
            for flag in flags
            if not re.search(r"(?:^|[\s,])" + re.escape(flag) + r"(?:[\s,=:\[\]]|$)", runner.RUNTIME_SYNOPSIS)
        )
        self.assertEqual(missing, [], "runtime synopsis must document declared flags: %s" % missing)

    def test_yaml_declares_sandbox_launcher_and_no_extra_args_escape(self):
        text = BBOT_YAML.read_text(encoding="utf-8")
        self.assertIn('command: "/usr/local/bin/csai-bbot"', text)
        self.assertIn('name: "additional_args"', text)


if __name__ == "__main__":
    unittest.main()
