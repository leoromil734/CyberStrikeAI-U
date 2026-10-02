"""Execute the documented GNU grep examples against offline JavaScript fixtures."""

import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
REFERENCE = ROOT / "skills" / "attack-surface-recon" / "references" / "comprehensive-recon.md"
HAS_TOOLS = os.name == "posix" and shutil.which("bash") and shutil.which("grep")


@unittest.skipUnless(HAS_TOOLS, "requires Linux/POSIX bash and GNU grep; run in the server validation snapshot")
class JSSourceExtractionTests(unittest.TestCase):
    def run_example(self, fixtures):
        text = REFERENCE.read_text(encoding="utf-8")
        section = text.split("### 源码命令检索示例", 1)[1]
        command = re.search(r"```bash\n(.*?)```", section, re.S).group(1)
        self.assertIn("js_dir=/path/to/assessment/js-sources", command)
        with tempfile.TemporaryDirectory(prefix="cyberstrike-js-fixture-") as temp:
            work = Path(temp)
            source = work / "sources"
            source.mkdir()
            for name, content in fixtures.items():
                (source / name).write_text(content, encoding="utf-8")
            command = command.replace("js_dir=/path/to/assessment/js-sources", "js_dir=" + shlex.quote(str(source)))
            result = subprocess.run(["bash", "-c", command], cwd=work, text=True, capture_output=True, timeout=10)
            return result, (work / "js-strings.raw.txt").read_text(), (work / "js-calls.raw.txt").read_text()

    def test_urls_relative_templates_workers_and_map_sources(self):
        result, candidates, contexts = self.run_example({
            "app.js": 'const baseURL="/gateway";axios.post("/session/token",{});fetch(\'/v2/users?limit=1\');new WebSocket("wss://socket.example.test/feed");xhr.open("GET","../audit");api.get(`/orders/${id}`);fetch("https://api.example.test/v3");axios.get("users/list");',
            "worker.mjs": 'fetch("./worker/status");',
            "map-source.ts": 'axios.get("/v4/typescript");',
        })
        self.assertEqual(result.returncode, 0, result.stderr)
        for value in ["/gateway", "/session/token", "/v2/users?limit=1", "wss://socket.example.test/feed", "../audit", "/orders/${id}", "https://api.example.test/v3", "./worker/status", "/v4/typescript"]:
            with self.subTest(value=value):
                self.assertIn(value, candidates)
        for value in ["baseURL", "axios", "fetch", "WebSocket", "xhr.open", "api.get", "users/list"]:
            with self.subTest(call=value):
                self.assertIn(value, contexts)
        self.assertIn("app.js:1:", candidates)
        self.assertIn("map-source.ts:1:", candidates)

    def test_zero_matches_save_empty_artifacts_instead_of_errors(self):
        result, candidates, contexts = self.run_example({"empty.js": "const answer = 42;"})
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stderr, "")
        self.assertEqual(candidates, "")
        self.assertEqual(contexts, "")


if __name__ == "__main__":
    unittest.main()
