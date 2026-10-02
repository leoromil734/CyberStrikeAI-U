import importlib.util
import io
from contextlib import redirect_stderr, redirect_stdout
from types import SimpleNamespace
from unittest.mock import patch
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("jsapiscan_runner", ROOT / "scripts" / "recon" / "jsapiscan_runner.py")
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


class JSAPIscanRunnerTests(unittest.TestCase):
    def args(self, *values):
        with redirect_stderr(io.StringIO()):
            return runner.make_parser().parse_args(list(values))

    def test_default_mapping_is_bounded_get_only_without_unsupported_flag(self):
        args = self.args("-u", "https://app.example.test", "-savejs", "-tlsverify")
        targets = runner.prepare_targets(args)
        command = runner.build_upstream_args(args, targets)
        for flag, value in [("-t", "1"), ("-ft", "2"), ("-d", "8"), ("-time", "8"), ("-maxreq", "1000"), ("-maxhtml", "40"), ("-maxapi", "200"), ("-o", "txt"), ("-op", "scan.txt")]:
            self.assertEqual(command[command.index(flag) + 1], value)
        self.assertIn("-aget", command)
        self.assertIn("-savejs", command)
        self.assertNotIn("-api", command)
        self.assertNotIn("-Ineedparms", command)
        self.assertNotIn("-gorog", command)
        self.assertNotIn("-extlink", command)

    def test_target_selection_requires_exactly_one_input(self):
        for values in [[], ["-u", "https://a.example", "-f", "targets.txt"]]:
            with self.subTest(values=values), self.assertRaises(SystemExit):
                self.args(*values)

    def test_zero_unlimited_and_excessive_limits_are_rejected(self):
        for flag, value in [("-maxapi", "0"), ("-maxreq", "-1"), ("-ft", "11"), ("-t", "6"), ("--total-timeout", "1801")]:
            with self.subTest(flag=flag), self.assertRaises(SystemExit):
                self.args("-u", "https://app.example", flag, value)

    def test_invalid_target_schemes_credentials_and_controls_are_rejected(self):
        for url in ["file:///etc/passwd", "javascript:alert(1)", "https://user:pass@app.example", "https://app.example/\nsecret", "https://app.example/a b"]:
            with self.subTest(url=url), self.assertRaises(ValueError):
                runner.prepare_targets(self.args("-u", url))

    def test_target_file_is_deduplicated_and_has_size_and_count_limits(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "targets.txt"
            path.write_text("# allowed targets\nhttps://a.example\nhttps://a.example\nhttps://b.example\n", encoding="utf-8")
            args = self.args("-f", str(path))
            self.assertEqual(runner.prepare_targets(args), ["https://a.example", "https://b.example"])
            path.write_text("\n".join(f"https://target{i}.example" for i in range(21)), encoding="utf-8")
            with self.assertRaises(ValueError):
                runner.prepare_targets(args)
            path.write_bytes(b"a" * (runner.MAX_INPUT_BYTES + 1))
            with self.assertRaises(ValueError):
                runner.read_input(path)

    def test_post_fallback_requires_explicit_api_mode_and_no_get_only_flag(self):
        with self.assertRaises(ValueError):
            runner.prepare_targets(self.args("-u", "https://a.example", "--allow-post-retry"))
        with self.assertRaises(ValueError):
            runner.prepare_targets(self.args("-u", "https://a.example", "-api", "-aget", "--allow-post-retry"))
        args = self.args("-u", "https://a.example", "-api", "--allow-post-retry")
        command = runner.build_upstream_args(args, runner.prepare_targets(args))
        self.assertIn("-api", command)
        self.assertNotIn("-aget", command)
        args = self.args("-u", "https://a.example", "-api")
        self.assertIn("-aget", runner.build_upstream_args(args, runner.prepare_targets(args)))

    def test_output_filename_cannot_escape_run_directory(self):
        for name in ["../config.yaml", "/etc/cron.d/task", "folder/report.txt", "bad name.txt", ".hidden"]:
            with self.subTest(name=name), self.assertRaises(ValueError):
                runner.prepare_targets(self.args("-u", "https://a.example", "-op", name))

    def test_headers_proxy_and_extended_supported_flags_are_preserved(self):
        args = self.args("-u", "https://a.example", "-api", "-pa", "-p", "http://127.0.0.1:8080", "-gjca", "secret,key", "-sc", "404,429", "-person", "-ey", "-scan-libs", "-wl", "-baseapipath", "/v1")
        command = runner.build_upstream_args(args, runner.prepare_targets(args), headers_path=Path("/private/job/headers.txt"))
        for flag in ["-api", "-pa", "-person", "-ey", "-scan-libs", "-wl", "-header-file"]:
            self.assertIn(flag, command)
        self.assertEqual(command[command.index("-sc") + 1], "404,429")
        self.assertEqual(command[command.index("-gjca") + 1], "secret,key")
        with self.assertRaises(ValueError):
            runner.prepare_targets(self.args("-u", "https://a.example", "-pa"))

    def test_sandbox_properties_isolate_production_and_bound_resources(self):
        command = runner.sandbox_command(Path("/opt/jsapiscan/bin"), ["-u", "https://a.example"], Path("/private/work"), "test-unit", 300)
        self.assertIn("User=csai-jsapiscan", command)
        self.assertIn("NoNewPrivileges=yes", command)
        self.assertIn("ProtectSystem=strict", command)
        self.assertIn("ProtectHome=yes", command)
        self.assertIn("RuntimeMaxSec=300", command)
        self.assertIn("MemoryMax=512M", command)
        self.assertIn("CapabilityBoundingSet=", command)
        self.assertTrue(any("InaccessiblePaths=" in item and "/opt/CyberStrikeAI-U" in item for item in command))
        self.assertEqual(command[-3:], [str(Path("/opt/jsapiscan/bin")), "-u", "https://a.example"])

    def test_csv_artifacts_are_candidates_and_do_not_echo_response_bodies(self):
        with tempfile.TemporaryDirectory() as temp:
            work = Path(temp)
            (work / "api.csv").write_text('\ufeffURL,Method,Length,Body,Status\nhttps://a.example/api,GET,12,secret-body,200\nhttps://a.example/api,GET,12,secret-body,200\n', encoding="utf-8")
            (work / "app.js").write_text('fetch("/api");', encoding="utf-8")
            artifacts, candidates = runner.collect_artifacts(work)
            self.assertEqual(len(artifacts), 2)
            self.assertEqual(len(candidates), 1)
            self.assertTrue(candidates[0]["candidate_only"])
            self.assertNotIn("secret-body", json.dumps(candidates))
            self.assertTrue(all("sha256" in item for item in artifacts))

    def test_systemd_timeout_is_recorded_and_header_copy_is_cleaned(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            binary = root / "verified-binary"
            binary.write_bytes(b"fixture binary")
            headers = root / "original-headers.txt"
            headers.write_text("X-Audit: fixture\n", encoding="utf-8")
            args = self.args("-u", "https://a.example", "-header-file", str(headers))
            replies = [SimpleNamespace(returncode=143), SimpleNamespace(stdout="timeout\n"), SimpleNamespace(returncode=0), SimpleNamespace(returncode=0)]
            account = SimpleNamespace(pw_uid=997, pw_gid=997)
            with patch.object(runner, "BINARY", binary), patch.object(runner, "BINARY_SHA256", hashlib.sha256(binary.read_bytes()).hexdigest()), patch.object(runner, "RUN_ROOT", root / "runs"), patch.object(runner.sys, "platform", "linux"), patch.object(runner, "pwd", SimpleNamespace(getpwnam=lambda _name: account)), patch.object(runner.os, "geteuid", return_value=0, create=True), patch.object(runner.os, "chown", create=True), patch.object(runner.subprocess, "run", side_effect=replies) as calls, redirect_stdout(io.StringIO()):
                self.assertEqual(runner.run(args), 143)
            job = next((root / "runs").iterdir())
            manifest = json.loads((job / "manifest.json").read_text("utf-8"))
            self.assertTrue(manifest["timed_out"])
            self.assertEqual(manifest["systemd_result"], "timeout")
            self.assertFalse((job / "work" / "headers.txt").exists())
            self.assertEqual(headers.read_text("utf-8"), "X-Audit: fixture\n")
            self.assertEqual(calls.call_args_list[2].args[0][1], "stop")
            self.assertEqual(calls.call_args_list[3].args[0][1], "reset-failed")

    def test_artifact_symlinks_do_not_read_outside_run_directory(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            work = root / "work"
            work.mkdir()
            outside = root / "outside.csv"
            outside.write_text("URL,Method\nhttps://outside.example,GET\n", encoding="utf-8")
            try:
                (work / "linked.csv").symlink_to(outside)
            except OSError:
                self.skipTest("symlink privileges are unavailable")
            self.assertEqual(runner.collect_artifacts(work), ([], []))


if __name__ == "__main__":
    unittest.main()
