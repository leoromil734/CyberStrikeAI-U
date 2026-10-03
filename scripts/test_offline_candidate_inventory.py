"""Network-free URL semantics and streaming JS/source-map candidate extraction tests."""

import io
import json
from contextlib import redirect_stdout
from pathlib import Path
import socket
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from scripts.recon import candidate_inventory as inventory
from scripts.recon import js_candidate_extract as extractor
from scripts.recon import url_inventory


class OfflineInventoryTests(unittest.TestCase):
    def records(self, manifest):
        with Path(manifest["inventory_file"]).open(encoding="utf-8") as stream:
            return [json.loads(line) for line in stream]

    def test_normalization_keeps_scheme_host_port_route_and_parameter_names(self):
        record = inventory.normalize_candidate("https://APP.example:8443/users/1234/report.pdf?action=download&method=GET&operation=list&p_p_resource_id=fetchRecord&p_p_id=portlet_27&do=read&route=%2Fusers%2Fshow&controller=account&resource=invoice&page=5&token=private-token", "GET")
        self.assertEqual((record["scheme"], record["host"], record["port"]), ("https", "app.example", 8443))
        self.assertEqual(record["path_template"], "/users/{id}/report.pdf")
        routing = {item["name"]: item["value"] for item in record["routing_parameters"]}
        self.assertEqual(routing, {"action": "download", "method": "GET", "operation": "list", "p_p_resource_id": "fetchRecord", "p_p_id": "portlet_27", "do": "read", "route": "/users/show", "controller": "account", "resource": "invoice"})
        self.assertIn("page", record["parameter_names"])
        self.assertIn("token", record["parameter_names"])
        self.assertNotIn("private-token", json.dumps(record))
        self.assertEqual(record["resource_type"], "download")
        self.assertTrue(record["candidate_only"])

    def test_distinct_route_values_survive_but_query_values_and_pii_do_not(self):
        left = inventory.normalize_candidate("https://a.example/gateway?p_p_resource_id=view&p_p_id=27&action=list&page=1&email=alice@example.test")
        right = inventory.normalize_candidate("https://a.example/gateway?p_p_resource_id=delete&p_p_id=27&action=list&page=2&email=bob@example.test")
        self.assertNotEqual(left["url"], right["url"])
        copy = inventory.normalize_candidate("https://a.example/gateway?p_p_resource_id=view&p_p_id=27&action=list&page=100&email=bob@example.test")
        self.assertEqual(left["url"], copy["url"])
        pii = inventory.normalize_candidate("https://a.example/users/alice%40example.test/12345678901/file.pdf?route=alice%40example.test")
        self.assertNotIn("alice", json.dumps(pii))
        self.assertNotIn("12345678901", json.dumps(pii))
        self.assertIn("{redacted}", pii["url"])

    def test_route_values_are_not_double_decoded_and_numeric_routing_ids_survive(self):
        encoded = inventory.normalize_candidate("https://a.example/gateway?route=a%252Fb&p_p_id=123&action=download")
        slash = inventory.normalize_candidate("https://a.example/gateway?route=a%2Fb&p_p_id=123&action=download")
        self.assertNotEqual(encoded["url"], slash["url"])
        self.assertIn("p_p_id=123", encoded["url"])
        self.assertIn("route=a%252Fb", encoded["url"])
        self.assertEqual(encoded["resource_type"], "download")

    def test_fragment_routes_are_retained_as_client_candidates_without_secret_values(self):
        first = inventory.normalize_candidate("https://a.example/#/users/123?action=view&token=private")
        second = inventory.normalize_candidate("https://a.example/#/users/123?action=edit&token=other")
        self.assertNotEqual(first["url"], second["url"])
        self.assertEqual(first["fragment_route"]["path_template"], "/users/{id}")
        self.assertIn("fragment_route_not_server_endpoint", first["uncertainty"])
        self.assertNotIn("private", json.dumps(first))
        self.assertTrue(first["candidate_only"])

    def test_candidate_index_initialization_failure_has_partial_manifest(self):
        with tempfile.TemporaryDirectory() as temp:
            root, source = Path(temp), Path(temp) / "urls.txt"
            source.write_text("https://a.example/api\n", encoding="utf-8")
            with patch.object(inventory.sqlite3, "connect", side_effect=RuntimeError("private-error")):
                manifest = url_inventory.run([source], root / "out")
            self.assertFalse(manifest["complete"])
            self.assertFalse(manifest["export_complete"])
            self.assertEqual(manifest["counts"]["raw"], 0)
            self.assertIn("inventory_initialization_failed", manifest["blocked_reasons"])
            self.assertFalse(list((root / "out").glob("candidate-index-*")))

    def test_relative_templates_and_explicit_base_are_never_fetched(self):
        record = inventory.normalize_candidate("../api/orders/${id}?action=read&limit=${limit}", "GET")
        self.assertIsNone(record["host"])
        self.assertIn("relative_base_unresolved", record["uncertainty"])
        self.assertIn("template_expression_not_evaluated", record["uncertainty"])
        resolved = inventory.normalize_candidate("../api/orders/${id}?action=read", "GET", base_url="https://a.example/app/index.html")
        self.assertEqual(resolved["url"], "https://a.example/api/orders/{value}?action=read")
        ipv6 = inventory.normalize_candidate("https://[2001:db8::1]:8443/api")
        self.assertEqual(ipv6["host"], "2001:db8::1")
        self.assertIn("[2001:db8::1]:8443", ipv6["url"])

    def test_credentials_and_unacceptable_url_types_are_rejected(self):
        for value in [[], 17, "file:///tmp/app.js", "javascript:alert(1)", "https://user:pass@app.example", "https://a.example:wrong", "https://a.example/a b"]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                inventory.normalize_candidate(value)

    def test_url_inventory_preserves_js_map_download_queues_without_network(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "urls.txt"
            source.write_text("\n".join(["https://a.example/app.js?token=private", "https://a.example/app.js?token=other", "https://a.example/app.js.map", "https://a.example/files/report.pdf", "https://a.example/export?operation=all", "https://a.example/api?action=list", "https://a.example/api?action=delete"]), encoding="utf-8")
            with patch.object(socket, "socket", side_effect=AssertionError("network forbidden")), patch.object(subprocess, "Popen", side_effect=AssertionError("process forbidden")):
                manifest = url_inventory.run([source], root / "out")
            self.assertTrue(manifest["complete"])
            self.assertTrue(manifest["export_complete"])
            self.assertFalse(manifest["coverage_complete"])
            self.assertEqual(manifest["counts"], {"raw": 7, "unique": 6, "exported": 6, "skipped": 1, "parse_errors": 0, "duplicates": 1})
            for kind, expected in [("javascript", 1), ("source_map", 1), ("download", 2)]:
                with Path(manifest["queues"][kind]).open(encoding="utf-8") as stream:
                    self.assertEqual(sum(1 for _ in stream), expected)
            self.assertEqual(len(self.records(manifest)), 6)
            self.assertEqual(manifest["network_requests"], 0)

    def test_ndjson_errors_and_large_record_are_explicitly_partial(self):
        with tempfile.TemporaryDirectory() as temp:
            root, source = Path(temp), Path(temp) / "urls.ndjson"
            source.write_text('{"url":"https://a.example/api","method":"POST","headers":"private-header"}\n{"url":17}\ninvalid-json\n', encoding="utf-8")
            manifest = url_inventory.run([source], root / "ndjson-out")
            self.assertFalse(manifest["complete"])
            self.assertFalse(manifest["export_complete"])
            self.assertTrue(manifest["raw_complete"])
            self.assertEqual(manifest["counts"]["raw"], 3)
            self.assertEqual(manifest["counts"]["exported"], 1)
            self.assertEqual(manifest["counts"]["parse_errors"], 2)
            self.assertNotIn("private-header", json.dumps(self.records(manifest)))
            source.write_text("https://a.example/" + "x" * 100, encoding="utf-8")
            with patch.object(url_inventory, "MAX_RECORD_CHARS", 32):
                manifest = url_inventory.run([source], root / "long-out", input_format="text")
            self.assertFalse(manifest["raw_complete"])
            self.assertFalse(manifest["export_complete"])

    def test_offline_timeout_and_existing_output_never_claim_completion_or_overwrite(self):
        with tempfile.TemporaryDirectory() as temp:
            root, source = Path(temp), Path(temp) / "urls.txt"
            source.write_text("https://a.example/api\n", encoding="utf-8")
            with patch.object(inventory.time, "monotonic", side_effect=[0, 10]):
                manifest = url_inventory.run([source], root / "out", timeout=1)
            self.assertFalse(manifest["complete"])
            self.assertFalse(manifest["raw_complete"])
            self.assertIn("export_timeout", manifest["blocked_reasons"])
            with self.assertRaises(ValueError):
                url_inventory.run([source], root / "out")

    def test_offline_cli_returns_only_paths_counts_and_candidate_status(self):
        with tempfile.TemporaryDirectory() as temp:
            root, source = Path(temp), Path(temp) / "urls.txt"
            source.write_text("https://private-host.example/api?token=secret\n", encoding="utf-8")
            with redirect_stdout(io.StringIO()) as output:
                self.assertEqual(url_inventory.main(["--input", str(source), "--output-dir", str(root / "out")]), 0)
            self.assertNotIn("private-host", output.getvalue())
            self.assertNotIn("secret", output.getvalue())
            self.assertEqual(json.loads(output.getvalue())["network_requests"], 0)

    def test_static_calls_keep_methods_base_hints_parameters_and_structural_context(self):
        with tempfile.TemporaryDirectory() as temp:
            root, source = Path(temp), Path(temp) / "app.js"
            source.write_text('const baseURL="https://api.example/gateway";axios.post("/session/login?token=private-token",{params:{tenant:"private-tenant"}});\nfetch(`/orders/${id}?action=view`,{method:"PUT",headers:{Authorization:"private-header"}});xhr.open("DELETE","../audit");new Worker("./worker.js");const download="/files/report.pdf";\n//# sourceMappingURL=app.js.map\n', encoding="utf-8")
            with patch.object(socket, "socket", side_effect=AssertionError("network forbidden")), patch.object(subprocess, "Popen", side_effect=AssertionError("JS execution forbidden")), patch.object(Path, "read_bytes", side_effect=AssertionError("whole-file reads forbidden")):
                manifest = extractor.run([source], root / "out")
            records = self.records(manifest)
            self.assertTrue(manifest["complete"])
            self.assertFalse(manifest["js_executed"])
            login = next(item for item in records if item["path_template"] == "/session/login")
            self.assertEqual(login["method"], "POST")
            self.assertIn("tenant", login["parameter_names"])
            self.assertEqual(login["base_url_candidates"], ["https://api.example/gateway"])
            self.assertIn("base_url_binding_unresolved", login["uncertainty"])
            orders = next(item for item in records if item["path_template"] == "/orders/{value}")
            self.assertEqual(orders["method"], "PUT")
            self.assertEqual(orders["source"]["line"], 2)
            self.assertTrue(orders["context"]["raw_context_omitted"])
            self.assertTrue(any(item["method"] == "DELETE" for item in records))
            self.assertTrue(any(item["resource_type"] == "javascript" for item in records))
            self.assertTrue(any(item["resource_type"] == "source_map" for item in records))
            self.assertTrue(any(item["resource_type"] == "download" for item in records))
            exported = json.dumps(records)
            for secret in ["private-token", "private-header", "private-tenant"]:
                self.assertNotIn(secret, exported)

    def test_concatenations_keep_known_methods_and_private_url_shaped_literals_are_omitted(self):
        with tempfile.TemporaryDirectory() as temp:
            root, source = Path(temp), Path(temp) / "app.js"
            source.write_text('const baseURL="https://a.example/gateway";axios.post(baseURL + "/orders",{params:{id:1}});fetch(baseURL + "/status");xhr.open("PATCH",apiBase + "/audit");const token="private/token";fetch("/safe",{headers:{"X-Audit":"https://private-header.example/value"}});', encoding="utf-8")
            manifest = extractor.run([source], root / "out")
            records = self.records(manifest)
            for path, method in [("/orders", "POST"), ("/status", "GET"), ("/audit", "PATCH")]:
                item = next(record for record in records if record["path_template"] == path)
                self.assertEqual(item["method"], method)
                self.assertIn("concatenation_not_evaluated", item["uncertainty"])
                self.assertTrue(item["context"]["dynamic_prefix"])
            self.assertNotIn("private/token", json.dumps(records))
            self.assertNotIn("private-header.example", json.dumps(records))
            self.assertEqual(manifest["counts"]["skipped"], 2)
            self.assertFalse(manifest["coverage_complete"])

    def test_source_map_embedded_sources_are_streamed_and_have_provenance(self):
        with tempfile.TemporaryDirectory() as temp:
            root, source = Path(temp), Path(temp) / "app.js.map"
            content = 'axios.get("/source-map/api?action=list");' + " " * 24000 + 'fetch("/after-window?operation=read");'
            source.write_text(json.dumps({"version": 3, "sources": ["webpack:///src/api.ts"], "sourceRoot": "src", "sourcesContent": [content], "mappings": "A" * 100000}), encoding="utf-8")
            with patch.object(Path, "read_bytes", side_effect=AssertionError("whole-file reads forbidden")), patch.object(extractor.json, "load", side_effect=AssertionError("whole-map JSON parsing forbidden")):
                manifest = extractor.run([source], root / "out")
            self.assertTrue(manifest["complete"])
            records = self.records(manifest)
            self.assertEqual(len(records), 2)
            self.assertTrue(any(item["path_template"] == "/after-window" for item in records))
            for item in records:
                self.assertEqual(item["source"]["map_source_index"], 0)
                self.assertEqual(item["source"]["map_source"], "webpack:///src/api.ts")
                self.assertEqual(item["source"]["path"], str(source))
                self.assertIn("sha256", item["source"])

    def test_missing_indexed_or_truncated_maps_and_oversize_files_are_gaps(self):
        maps = [
            (json.dumps({"version": 3, "sources": ["app.ts"]}), "source_map_sources_not_embedded"),
            (json.dumps({"version": 3, "sections": [{"map": {"sources": []}}]}), "indexed_source_map_not_supported"),
            ('{"version":3,"sources":["a.ts"],"sourcesContent":["fetch(\\"/api\\");', "truncated_source_map"),
        ]
        for text, reason in maps:
            with self.subTest(reason=reason), tempfile.TemporaryDirectory() as temp:
                root, source = Path(temp), Path(temp) / "app.js.map"
                source.write_text(text, encoding="utf-8")
                manifest = extractor.run([source], root / "out")
                self.assertFalse(manifest["complete"])
                self.assertIn(reason, manifest["blocked_reasons"])
        with tempfile.TemporaryDirectory() as temp:
            root, source = Path(temp), Path(temp) / "app.js"
            source.write_text('fetch("/api");', encoding="utf-8")
            manifest = extractor.run([source], root / "out", max_source_bytes=2)
            self.assertFalse(manifest["complete"])
            self.assertFalse(manifest["export_complete"])
            self.assertFalse(manifest["raw_complete"])
            self.assertIn("source_size_limit", manifest["blocked_reasons"])

    def test_map_unicode_escapes_and_window_boundaries_do_not_duplicate_candidates(self):
        with tempfile.TemporaryDirectory() as temp:
            root, source = Path(temp), Path(temp) / "unicode.js.map"
            text = " " * (extractor.WINDOW_CHARS - extractor.OVERLAP_CHARS - 10) + 'fetch("/edge");\nconst x="😀";fetch("/end");'
            source.write_text(json.dumps({"version": 3, "sources": ["app.js"], "sourcesContent": [text]}), encoding="utf-8")
            manifest = extractor.run([source], root / "out")
            records = self.records(manifest)
            self.assertTrue(manifest["complete"])
            self.assertEqual([item["path_template"] for item in records], ["/edge", "/end"])
            self.assertEqual(records[1]["source"]["line"], 2)

    def test_repeated_paths_keep_distinct_source_locations(self):
        with tempfile.TemporaryDirectory() as temp:
            root, source = Path(temp), Path(temp) / "sources"
            source.mkdir()
            (source / "one.js").write_text('fetch("/api");', encoding="utf-8")
            (source / "two.js").write_text('fetch("/api");', encoding="utf-8")
            manifest = extractor.run([source], root / "out")
            records = self.records(manifest)
            self.assertEqual(manifest["counts"]["unique"], 2)
            self.assertEqual(len({item["source"]["path"] for item in records}), 2)
            self.assertFalse(manifest["coverage_complete"])


if __name__ == "__main__":
    unittest.main()
