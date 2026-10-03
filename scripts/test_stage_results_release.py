import os
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import yaml
from stage_results_release import activate, assert_idle, merge_recipe


class ResultsReleaseTests(unittest.TestCase):
    def test_busy_production_refuses_before_any_copy_or_restart(self):
        args = SimpleNamespace(maintenance_confirmed=True)
        with patch("stage_results_release.db_count", return_value=1), patch("stage_results_release.command") as calls, patch("stage_results_release.prepare") as prepare:
            with self.assertRaisesRegex(RuntimeError, "tools are active"):
                activate(args)
            calls.assert_not_called()
            prepare.assert_not_called()

    def test_missing_administrator_token_is_fail_closed(self):
        with patch("stage_results_release.db_count", return_value=0), patch.dict(os.environ, {}, clear=True), patch("stage_results_release.urllib.request.urlopen") as requests:
            with self.assertRaisesRegex(RuntimeError, "CSAI_ADMIN_BEARER"):
                assert_idle(SimpleNamespace(api="http://127.0.0.1:8080"))
            requests.assert_not_called()

    def test_js_recipe_preserves_operator_dispatch_defaults_and_credentials(self):
        with TemporaryDirectory() as temporary:
            current, proposed = Path(temporary) / "current.yaml", Path(temporary) / "proposed.yaml"
            original = {"name": "jsapiscan", "command": "private-wrapper", "args": ["private-credential"], "enabled": False,
                        "parameters": [{"name": "threads", "default": 7, "flag": "--threads", "type": "int"}]}
            update = {"name": "jsapiscan", "command": "jsapiscan", "enabled": True,
                      "parameters": [{"name": "threads", "default": 12, "minimum": 1, "maximum": 50}, {"name": "heartbeat", "default": 20}]}
            current.write_text(yaml.safe_dump(original), encoding="utf-8")
            proposed.write_text(yaml.safe_dump(update), encoding="utf-8")
            merged = merge_recipe(current, proposed, "jsapiscan")
            self.assertEqual(merged["command"], "private-wrapper")
            self.assertEqual(merged["args"], ["private-credential"])
            self.assertFalse(merged["enabled"])
            self.assertEqual(merged["parameters"][0]["default"], 7)
            self.assertEqual(merged["parameters"][0]["maximum"], 50)
            self.assertEqual(len(merged["parameters"]), 2)

    def test_fofa_field_patch_preserves_existing_private_script_values(self):
        with TemporaryDirectory() as temporary:
            current, proposed = Path(temporary) / "current.yaml", Path(temporary) / "proposed.yaml"
            script = "FOFA_API_KEY = 'private-fixture'\noutput = {\n    \"results_count\": len(result_data.get('results', [])),\n    \"results\": result_data.get('results', []),\n}\n"
            original = {"name": "fofa_search", "command": "/usr/bin/python3", "enabled": True, "args": ["-c", script]}
            current.write_text(yaml.safe_dump(original), encoding="utf-8")
            proposed.write_text(yaml.safe_dump({"name": "fofa_search"}), encoding="utf-8")
            merged = merge_recipe(current, proposed, "fofa_search")
            self.assertEqual(merged["command"], original["command"])
            self.assertIn("private-fixture", merged["args"][1])
            self.assertLess(merged["args"][1].index('"fields":'), merged["args"][1].index('"results":'))
            self.assertEqual(yaml.safe_load(current.read_text()), original)


if __name__ == "__main__":
    unittest.main()
