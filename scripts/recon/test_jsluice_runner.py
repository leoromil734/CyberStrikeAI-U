"""Offline fixture tests: no scanner binary, installation or network required."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch
import uuid

from scripts.recon import jsluice_runner as runner


class JSLuiceRunnerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.source = self.root / "download.js"
        self.source.write_bytes(b'fetch("/api/users/" + id, {method:"POST"});\n')
        self.execution_id = str(uuid.uuid4())
        self.artifacts = self.root / "executions" / self.execution_id
        self.artifacts.mkdir(parents=True)
        self.job = self.artifacts / "jsluice" / ("execution-" + self.execution_id)
        self.args = argparse.Namespace(mode="urls", file=str(self.source), source_url="https://app.example.test/static/app.js", timeout=5, validate_only=False)
        env = patch.dict(os.environ, {"CSAI_EXECUTION_ID": self.execution_id, "CSAI_ARTIFACT_DIR": str(self.artifacts)})
        env.start()
        self.addCleanup(env.stop)
        network = patch("socket.socket", side_effect=AssertionError("network forbidden"))
        network.start()
        self.addCleanup(network.stop)

    def fake_process(self, row, stderr=b"", returncode=0):
        def spawn(argv, **kwargs):
            self.assertEqual(argv[0], "/fixture/jsluice")
            self.assertEqual(argv[-2], "--")
            self.assertEqual(argv[-1], str(self.job / "source.js"))
            self.assertNotIn(self.args.source_url, argv)
            self.assertFalse(kwargs["shell"])
            if self.args.mode == "urls":
                self.assertEqual(argv[1:3], ["urls", "--include-source"])
            else:
                self.assertEqual(argv[1:2], ["secrets"])
                self.assertNotIn("--include-source", argv)
            kwargs["stdout"].write(row)
            kwargs["stderr"].write(stderr)
            kwargs["stdout"].flush()
            kwargs["stderr"].flush()
            return Mock(poll=Mock(return_value=returncode), wait=Mock(return_value=returncode))
        return spawn

    def invoke(self, row, stderr=b"", returncode=0):
        with patch.object(runner.shutil, "which", return_value="/fixture/jsluice"), patch.object(runner.subprocess, "Popen", side_effect=self.fake_process(row, stderr, returncode)):
            return runner.run(self.args)

    def test_local_urls_preserve_method_relative_url_source_and_hash(self):
        raw = b'{"url":"/api/users/EXPR?route=detail","method":"POST","type":"fetch","queryParams":["route"],"bodyParams":[],"source":"fetch(...)"}\n'
        summary, code = self.invoke(raw)
        self.assertEqual(code, 0)
        self.assertTrue(summary["complete"])
        self.assertFalse(summary["coverage_complete"])
        self.assertNotIn(self.args.source_url, json.dumps(summary))
        row = json.loads((self.job / "urls.jsonl").read_text())
        self.assertEqual(row["relativeURL"], "/api/users/EXPR?route=detail")
        self.assertEqual(row["url"], row["relativeURL"])
        self.assertEqual(row["method"], "POST")
        self.assertEqual(row["source_js"], self.args.source_url)
        self.assertEqual(row["source_sha256"], hashlib.sha256(self.source.read_bytes()).hexdigest())
        self.assertTrue(row["candidate_only"])
        self.assertEqual((self.job / "raw.jsonl").read_bytes(), raw)
        manifest = json.loads((self.job / "manifest.json").read_text())
        self.assertEqual(manifest["execution_id"], self.execution_id)
        for name, meta in manifest["files"].items():
            self.assertEqual(meta["sha256"], hashlib.sha256((self.job / name).read_bytes()).hexdigest())
        with self.assertRaises(FileExistsError):
            runner.run(self.args)

    def test_secret_values_stay_only_in_private_raw_original(self):
        self.args.mode = "secrets"
        summary, code = self.invoke(b'{"kind":"testKey","severity":"critical","data":{"value":"SECRET_FIXTURE"},"context":{"token":"SECRET_FIXTURE"}}\n')
        self.assertEqual(code, 0)
        output = (self.job / "secrets.jsonl").read_text()
        self.assertNotIn("SECRET_FIXTURE", output + json.dumps(summary))
        self.assertIn("SECRET_FIXTURE", (self.job / "raw.jsonl").read_text())
        self.assertEqual(json.loads(output)["severity"], "tentative")

    def test_exit_zero_with_stderr_is_partial(self):
        summary, code = self.invoke(b"", stderr=b"error: could not parse local file")
        self.assertEqual(code, 1)
        self.assertFalse(summary["complete"])
        self.assertIn("upstream_stderr_requires_review", summary["blocked_reasons"])

    def test_invalid_json_keeps_valid_prefix_and_marks_partial(self):
        summary, code = self.invoke(b'{"url":"/ok","method":"GET"}\nnot-json\n')
        self.assertEqual(code, 1)
        self.assertEqual(summary["counts"], {"raw": 2, "exported": 1, "parse_errors": 1})
        self.assertIn("invalid_upstream_jsonl", summary["blocked_reasons"])

    def test_missing_dependency_keeps_source_and_failure_manifest(self):
        with patch.object(runner.shutil, "which", return_value=None), patch.object(runner.subprocess, "Popen") as launch:
            summary, code = runner.run(self.args)
        launch.assert_not_called()
        self.assertEqual(code, 1)
        self.assertIn("jsluice_not_installed", summary["blocked_reasons"])
        self.assertTrue((self.job / "source.js").exists())
        self.assertTrue((self.job / "manifest.json").exists())

    def test_validate_only_is_offline_and_never_launches(self):
        self.args.validate_only = True
        with patch.object(runner.subprocess, "Popen") as launch:
            summary, code = runner.run(self.args)
        launch.assert_not_called()
        self.assertEqual(code, 0)
        self.assertEqual(summary["network_requests"], 0)
        self.assertFalse(self.job.exists())

    def test_url_input_and_unbound_artifacts_rejected(self):
        self.args.file = "https://app.example.test/app.js"
        with self.assertRaisesRegex(runner.InputError, "local_file_required"):
            runner.run(self.args)
        self.args.file = str(self.source)
        with patch.dict(os.environ, {"CSAI_EXECUTION_ID": str(uuid.uuid4())}):
            with self.assertRaisesRegex(runner.InputError, "binding_mismatch"):
                runner.run(self.args)

    def test_hardlink_source_is_rejected(self):
        alias = self.root / "alias.js"
        try:
            os.link(self.source, alias)
        except OSError as exc:
            self.skipTest(str(exc))
        self.args.file = str(alias)
        with self.assertRaisesRegex(runner.InputError, "single_link"):
            runner.run(self.args)

    def test_export_bounds_remain_partial(self):
        with patch.object(runner, "MAX_RECORDS", 1):
            summary, code = self.invoke(b'{"url":"/one"}\n{"url":"/two"}\n')
        self.assertEqual(code, 1)
        self.assertEqual(summary["counts"]["exported"], 1)
        self.assertIn("export_limit", summary["blocked_reasons"])

    def test_fast_exit_stderr_size_is_still_bounded(self):
        with patch.object(runner, "MAX_OUTPUT", 64):
            summary, code = self.invoke(b"", stderr=b"x" * 65)
        self.assertEqual(code, 1)
        self.assertIn("output_size_limit", summary["blocked_reasons"])
        manifest = json.loads((self.job / "manifest.json").read_text())
        self.assertFalse(manifest["raw_complete"])

    def test_export_metadata_expansion_obeys_output_limit(self):
        with patch.object(runner, "MAX_OUTPUT", 64):
            summary, code = self.invoke(b'{"url":"/small"}\n')
        self.assertEqual(code, 1)
        self.assertEqual(summary["counts"]["exported"], 0)
        self.assertIn("export_limit", summary["blocked_reasons"])
        self.assertEqual((self.job / "urls.jsonl").stat().st_size, 0)

    def test_invalid_utf8_is_not_a_success(self):
        summary, code = self.invoke(b'\xff\xfe\n')
        self.assertEqual(code, 1)
        self.assertEqual(summary["counts"]["parse_errors"], 1)


if __name__ == "__main__":
    unittest.main()
