"""Offline crt.sh tests: fixed JSON, mocked HTTP, and no target/network access."""

from contextlib import redirect_stdout
from datetime import datetime, timezone
from email.utils import format_datetime
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import re
import socket
import ssl
import unittest
from unittest.mock import patch
import urllib.error
import urllib.parse

SPEC = importlib.util.spec_from_file_location("crtsh_recon", Path(__file__).with_name("crtsh-recon.py"))
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


def cert(name="www.example.test", identifier=123, **fields):
    return dict(id=identifier, name_value=name, entry_timestamp="2020-01-02T03:04:05",
                not_before="2020-01-01T00:00:00", not_after="2021-01-01T00:00:00", **fields)


class Response(io.BytesIO):
    def __init__(self, data=b"[]", content_type="application/json", url=None, **headers):
        super().__init__(data)
        self.headers = {"Content-Type": content_type, **headers}
        self.url, self.status = url, 200
        self.bytes_read = 0

    def geturl(self):
        return self.url

    def read1(self, size):
        data = super().read1(size)
        self.bytes_read += len(data)
        return data


class Opener:
    def __init__(self, outcomes):
        self.outcomes, self.calls = iter(outcomes), []

    def open(self, request, timeout):
        self.calls.append((request, timeout))
        result = next(self.outcomes)
        if isinstance(result, Exception):
            raise result
        if result.url is None:
            result.url = request.full_url
        return result


class CrtshTests(unittest.TestCase):
    def setUp(self):
        # Even an accidental unmocked path must not resolve or contact a target.
        for name in ("getaddrinfo", "create_connection"):
            guard = patch.object(socket, name, side_effect=AssertionError("real network forbidden"))
            guard.start()
            self.addCleanup(guard.stop)

    def run_fixture(self, rows, second=None, **kwargs):
        outcomes = [Response(runner.json_bytes(rows)), Response(runner.json_bytes([] if second is None else second))]
        opener = Opener(outcomes)
        with patch.object(runner.urllib.request, "build_opener", return_value=opener):
            result = runner.collect("example.test", **kwargs)
        return result, opener

    def test_dns_normalization_idna_and_trailing_dot(self):
        for raw, expected in [(" EXAMPLE.COM. ", "example.com"), ("BÜCHER.example", "xn--bcher-kva.example"),
                              ("例子。测试.", "xn--fsqu00a.xn--0zwm56d"), ("xn--bcher-kva.example", "xn--bcher-kva.example")]:
            with self.subTest(raw=raw):
                self.assertEqual(runner.normalize_domain(raw), expected)
        self.assertEqual(runner.normalize_domain("DnS: *.EXAMPLE.COM.", certificate=True), "example.com")

    def test_url_ip_query_injection_and_bad_dns_rejected_before_http(self):
        bad = [None, [], "", "com", "localhost", "https://example.com", "http://user@example.com/x", "//example.com", "example.com:443",
               "127.0.0.1", "2001:db8::1", "[::1]", "127.1", "0x7f.1", "1.2.3.999", "*.example.com", "%25.example.com", "example.com?output=json",
               "example.com&exclude=expired", "example.com/foo", "example.com\\x", "example.com#fragment", "a,b.example", "a;b.example",
               "a b.example", "a\n.example", "example.com\n", "x\x00.example", "a..example", ".example.com", "example.com..", "_srv.example",
               "-x.example", "x-.example", "a" * 64 + ".example", "xn--.example", "xn--a.example", "a\u200b.example", "example．com％25"]
        with patch.object(runner.urllib.request, "build_opener") as network:
            for value in bad:
                with self.subTest(value=value), self.assertRaises(runner.InputError):
                    runner.collect(value)
            network.assert_not_called()

    def test_multiline_san_wildcards_dedup_strict_suffix_and_traceability(self):
        rows = [cert("example.test\n*.example.test\r\nWWW.EXAMPLE.TEST.\nwww.example.test\nnotexample.test\nexample.test.evil.test",
                     common_name="www.example.test", san=["DNS: api.example.test, DNS: mail.example.test", "outside.test"]),
                cert("www.example.test", identifier=456, serial_number="abc123", issuer_ca_id=42)]
        result, _ = self.run_fixture(rows, second=rows)
        self.assertEqual([record["host"] for record in result["records"]],
                         ["example.test", "www.example.test", "api.example.test", "mail.example.test"])
        self.assertEqual(result["status"], "success")
        self.assertFalse(result["partial"])
        self.assertFalse(result["coverage_complete"])
        self.assertEqual(result["coverage"], "unknown")
        self.assertTrue(result["historical_certificates_included"])
        self.assertEqual(result["counts"]["unique_hosts"], 4)
        self.assertEqual(result["counts"]["out_of_domain_names"], 6)
        self.assertGreater(result["counts"]["duplicate_names"], 0)
        apex = result["records"][0]
        self.assertEqual({c["wildcard"] for c in apex["certificates"]}, {True, False})
        www = result["records"][1]
        self.assertEqual({c["id"] for c in www["certificates"]}, {"123", "456"})
        for record in result["records"]:
            self.assertTrue(record["candidate_only"])
            self.assertEqual(record["verification"], "unverified")
            self.assertNotIn("ip", record)
            self.assertNotIn("port", record)
            self.assertNotIn("alive", record)
            for c in record["certificates"]:
                self.assertEqual(c["time_status"], "expired")
                self.assertEqual(c["entry_timestamp"], "2020-01-02T03:04:05")
                self.assertEqual(c["url"], "https://crt.sh/?id=" + c["id"])

    def test_idna_san_matches_only_same_query_domain(self):
        rows = [cert("*.BÜCHER.example\nshop.bücher.example\nxn--bcher-kva.example.evil.test\nbücher.other")]
        opener = Opener([Response(runner.json_bytes(rows)), Response()])
        with patch.object(runner.urllib.request, "build_opener", return_value=opener):
            result = runner.collect("BÜCHER.example")
        self.assertEqual(result["query_domain"], "xn--bcher-kva.example")
        self.assertEqual([r["host"] for r in result["records"]], ["xn--bcher-kva.example", "shop.xn--bcher-kva.example"])

    def test_fixed_https_queries_no_expiry_filter_no_proxy_or_recursion(self):
        result, opener = self.run_fixture([cert("other.test\nexample.test")])
        self.assertEqual(len(opener.calls), 2)
        for index, (request, timeout) in enumerate(opener.calls):
            url = urllib.parse.urlsplit(request.full_url)
            self.assertEqual((url.scheme, url.netloc, url.path), ("https", "crt.sh", "/"))
            self.assertEqual(urllib.parse.parse_qs(url.query), {"q": ["example.test" if index == 0 else "%.example.test"], "output": ["json"]})
            self.assertLessEqual(timeout, 20)
            self.assertEqual(request.get_header("Accept-encoding"), "identity")
        self.assertEqual(len(result["queries"]), 2)
        with patch.object(runner.urllib.request, "build_opener", return_value=Opener([Response(), Response()])) as factory:
            runner.collect("example.test")
        handlers = factory.call_args.args
        self.assertEqual(handlers[0].proxies, {})
        self.assertIsInstance(handlers[1], runner.NoRedirect)

    def test_fixed_subdomain_scope_does_not_expand_to_parent_or_siblings(self):
        rows = [cert("example.test\nsibling.example.test\napi.example.test\nadmin.api.example.test")]
        opener = Opener([Response(runner.json_bytes(rows)), Response()])
        with patch.object(runner.urllib.request, "build_opener", return_value=opener):
            result = runner.collect("api.example.test")
        self.assertEqual([r["host"] for r in result["records"]], ["api.example.test", "admin.api.example.test"])
        self.assertEqual([q["query"] for q in result["queries"]], ["api.example.test", "%.api.example.test"])

    def test_zero_results_never_establish_coverage(self):
        result, _ = self.run_fixture([])
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["records"], [])
        self.assertFalse(result["partial"])
        self.assertFalse(result["truncated"])
        self.assertFalse(result["coverage_complete"])
        self.assertEqual(result["counts"]["certificates_received"], 0)
        self.assertEqual(result["queries"][0]["response_sha256"], hashlib.sha256(b"[]").hexdigest())

    def test_no_json_html_error_object_invalid_utf8_not_empty_success(self):
        for body, content_type, reason in [(b"<html>rate limit</html>", "text/html", "non_json_response"),
                                           (b"<html>failed</html>", "application/json", "invalid_json"),
                                           (b'{"error":"busy"}', "application/json", "invalid_json_envelope"),
                                           (b"null", "application/json", "invalid_json_envelope"),
                                           (b"", "application/json", "invalid_json"), (b"[", "application/json", "invalid_json"),
                                           (b"[NaN]", "application/json", "invalid_json"), (b"[\xff]", "application/json", "invalid_json")]:
            with self.subTest(reason=reason, body=body):
                opener = Opener([Response(body, content_type), Response(body, content_type)])
                with patch.object(runner.urllib.request, "build_opener", return_value=opener):
                    result = runner.collect("example.test")
                self.assertEqual(result["status"], "error")
                self.assertTrue(result["partial"])
                self.assertIn(reason, result["reasons"])
                self.assertEqual(result["records"], [])
                self.assertEqual(len(opener.calls), 2)  # No retry of invalid documents.

    def test_redirects_are_never_followed_even_to_same_host(self):
        fp = io.BytesIO(b"redirect")
        with self.assertRaisesRegex(runner.QueryError, "redirect_not_allowed"):
            runner.NoRedirect().redirect_request(None, fp, 302, "Found", {}, "https://target.example.test")
        self.assertTrue(fp.closed)
        opener = Opener([Response(url="https://other.test"), Response(url="http://crt.sh/")])
        with patch.object(runner.urllib.request, "build_opener", return_value=opener):
            result = runner.collect("example.test")
        self.assertEqual(result["status"], "error")
        self.assertIn("redirect_not_allowed", result["reasons"])

    def test_compressed_response_is_rejected_without_unbounded_decompression(self):
        opener = Opener([Response(**{"Content-Encoding": "gzip"}), Response(**{"Content-Encoding": "gzip"})])
        with patch.object(runner.urllib.request, "build_opener", return_value=opener):
            result = runner.collect("example.test")
        self.assertIn("unexpected_content_encoding", result["reasons"])

    def test_incomplete_http_body_even_valid_json_is_not_empty_success(self):
        opener = Opener([Response(**{"Content-Length": "10"}), Response(**{"Content-Length": "10"})])
        with patch.object(runner.urllib.request, "build_opener", return_value=opener):
            result = runner.collect("example.test")
        self.assertEqual(result["status"], "partial")
        self.assertTrue(result["truncated"])
        self.assertIn("incomplete_response", result["reasons"])
        self.assertTrue(all(not q["response_complete"] for q in result["queries"]))
        self.assertEqual(len(opener.calls), 2)

    def test_rate_limit_server_failure_timeout_bounded_retry_then_success(self):
        failures = [urllib.error.HTTPError(runner.UPSTREAM, 429, "rate", {"Retry-After": "999"}, None),
                    urllib.error.HTTPError(runner.UPSTREAM, 503, "busy", {}, None),
                    urllib.error.URLError(TimeoutError())]
        for failure in failures:
            with self.subTest(failure=failure):
                opener = Opener([failure, Response(runner.json_bytes([cert()])), Response()])
                with patch.object(runner.urllib.request, "build_opener", return_value=opener), patch.object(runner.time, "sleep") as sleep:
                    result = runner.collect("example.test", max_retries=1)
                self.assertEqual(result["status"], "success")
                self.assertEqual(result["queries"][0]["attempts"], 2)
                self.assertEqual(result["queries"][0]["http_status"], 200)
                self.assertEqual(sleep.call_count, 1)
                self.assertLessEqual(sleep.call_args.args[0], 5)

    def test_retry_exhaustion_and_permanent_error_have_truthful_state(self):
        for code, retry, total in [(429, 2, 6), (500, 1, 4), (599, 1, 4), (403, 3, 2), (404, 3, 2)]:
            with self.subTest(code=code):
                errors = [urllib.error.HTTPError(runner.UPSTREAM, code, "fixture", {}, None) for _ in range(total)]
                opener = Opener(errors)
                with patch.object(runner.urllib.request, "build_opener", return_value=opener), patch.object(runner.time, "sleep"):
                    result = runner.collect("example.test", max_retries=retry)
                self.assertEqual(result["status"], "error")
                self.assertEqual(len(opener.calls), total)
                self.assertIn("http_" + str(code), result["reasons"])
                self.assertFalse(result["coverage_complete"])
        opener = Opener([urllib.error.URLError(ssl.SSLError()) for _ in range(2)])
        with patch.object(runner.urllib.request, "build_opener", return_value=opener):
            self.assertIn("tls_error", runner.collect("example.test")["reasons"])
        self.assertEqual(len(opener.calls), 2)

    def test_retry_after_numeric_date_and_budget(self):
        self.assertEqual(runner.retry_delay({"Retry-After": "0"}, 0), 0)
        self.assertEqual(runner.retry_delay({"Retry-After": "10000"}, 0), 5)
        self.assertEqual(runner.retry_delay({"Retry-After": "NaN"}, 0), 1)
        stamp = format_datetime(datetime(2099, 1, 1, tzinfo=timezone.utc))
        self.assertEqual(runner.retry_delay({"Retry-After": stamp}, 0), 5)
        opener = Opener([urllib.error.HTTPError(runner.UPSTREAM, 429, "rate", {"Retry-After": "5"}, None) for _ in range(2)])
        with patch.object(runner.urllib.request, "build_opener", return_value=opener), patch.object(runner.time, "sleep") as sleep:
            result = runner.collect("example.test", timeout_seconds=1)
        sleep.assert_not_called()
        self.assertEqual(result["status"], "error")
        self.assertIn("timeout", result["reasons"])

    def test_deadline_checked_while_reading_and_before_new_queries(self):
        with patch.object(runner.time, "monotonic", return_value=10), self.assertRaisesRegex(runner.QueryError, "timeout"):
            runner.read_bounded(Response(), 1024, 9)
        opener = Opener([])
        with patch.object(runner.urllib.request, "build_opener", return_value=opener), patch.object(runner.time, "monotonic", side_effect=[0, 2, 3]):
            result = runner.collect("example.test", timeout_seconds=1)
        self.assertEqual(opener.calls, [])
        self.assertEqual(result["status"], "error")
        self.assertTrue(all(q["state"] == "not_attempted" for q in result["queries"]))

    def test_response_limit_drops_incomplete_json_not_prior_complete_candidates(self):
        first = Response(runner.json_bytes([cert()]))
        second = Response(b"[" + b" " * 10000)
        opener = Opener([first, second])
        with patch.object(runner.urllib.request, "build_opener", return_value=opener):
            result = runner.collect("example.test", max_response_bytes=1024)
        self.assertEqual(result["status"], "partial")
        self.assertTrue(result["truncated"])
        self.assertIn("response_limit", result["reasons"])
        self.assertEqual([r["host"] for r in result["records"]], ["www.example.test"])
        self.assertEqual(first.bytes_read + second.bytes_read, 1025)
        self.assertEqual(result["queries"][1]["state"], "error")
        self.assertFalse(result["queries"][1]["response_complete"])
        self.assertEqual(result["queries"][1]["response_sha256_scope"], "captured_prefix")
        self.assertEqual(result["queries"][0]["response_sha256_scope"], "complete_response")

    def test_first_response_oversize_and_cumulative_response_budget(self):
        opener = Opener([Response(b"[" + b" " * 2000)])
        with patch.object(runner.urllib.request, "build_opener", return_value=opener):
            result = runner.collect("example.test", max_response_bytes=1024)
        self.assertEqual(len(opener.calls), 1)
        self.assertEqual(result["status"], "partial")
        self.assertTrue(result["truncated"])
        self.assertEqual(result["queries"][1]["state"], "not_attempted")
        self.assertEqual(result["records"], [])

    def test_record_cap_and_exact_boundary_are_distinguished(self):
        result, opener = self.run_fixture([cert("a.example.test\nb.example.test\nc.example.test")], max_records=2)
        self.assertEqual(len(result["records"]), 2)
        self.assertIn("record_limit", result["reasons"])
        self.assertTrue(result["truncated"])
        self.assertEqual(len(opener.calls), 1)
        result, _ = self.run_fixture([cert("a.example.test\nb.example.test")], max_records=2)
        self.assertFalse(result["partial"])

    def test_certificate_name_reference_and_output_limits_are_visible(self):
        with patch.object(runner, "MAX_CERTIFICATES", 1):
            result, _ = self.run_fixture([cert(), cert("a.example.test")])
        self.assertIn("certificate_limit", result["reasons"])
        with patch.object(runner, "MAX_NAMES", 1):
            result, _ = self.run_fixture([cert("a.example.test\nb.example.test")])
        self.assertIn("name_limit", result["reasons"])
        with patch.object(runner, "MAX_CERTIFICATES_PER_HOST", 1):
            result, _ = self.run_fixture([cert(), cert(identifier=456)])
        self.assertIn("certificate_reference_limit", result["reasons"])
        self.assertEqual(len(result["records"][0]["certificates"]), 1)
        with patch.object(runner, "MAX_OUTPUT_BYTES", 65536 + 800):
            result, _ = self.run_fixture([cert("a.example.test\nb.example.test\nc.example.test")])
            self.assertLess(len(runner.json_bytes(result)), runner.MAX_OUTPUT_BYTES)
        self.assertIn("output_limit", result["reasons"])
        self.assertTrue(result["truncated"])

    def test_invalid_certificate_rows_and_names_remain_explicit_gaps(self):
        rows = [None, {}, cert(identifier=True), cert(identifier="x"), cert("https://example.test\n192.0.2.1\na..example.test"),
                {"id": 3}, cert(san=[123]), cert("good.example.test")]
        result, _ = self.run_fixture(rows)
        self.assertEqual(result["status"], "partial")
        self.assertIn("invalid_certificates", result["reasons"])
        self.assertIn("missing_certificate_names", result["reasons"])
        self.assertIn("invalid_names", result["reasons"])
        self.assertEqual({r["host"] for r in result["records"]}, {"www.example.test", "good.example.test"})
        self.assertGreater(result["counts"]["rejected_names"], 0)

    def test_missing_or_malformed_certificate_dates_are_unknown_not_live(self):
        row = cert()
        row["not_after"] = "invalid"
        self.assertEqual(runner.certificate_metadata(row, datetime.now(timezone.utc))["time_status"], "unknown")
        row["not_after"] = None
        self.assertEqual(runner.certificate_metadata(row, datetime.now(timezone.utc))["time_status"], "unknown")
        row["entry_timestamp"] = "\n"
        with self.assertRaises(ValueError):
            runner.certificate_metadata(row, datetime.now(timezone.utc))

    def test_mixed_case_dns_wildcard_and_all_san_fields(self):
        row = cert("example.test", san="DnS: *.example.test", sans="DNS:a.example.test", subject_alt_name="DNS:b.example.test", subject_alt_names=["DNS:c.example.test"])
        result, _ = self.run_fixture([row])
        self.assertEqual(len(result["records"]), 4)
        self.assertTrue(result["records"][0]["certificates"][1]["wildcard"])

    def test_failure_after_success_retains_candidates_as_partial(self):
        opener = Opener([Response(runner.json_bytes([cert()])), urllib.error.HTTPError(runner.UPSTREAM, 503, "busy", {}, None)])
        with patch.object(runner.urllib.request, "build_opener", return_value=opener):
            result = runner.collect("example.test", max_retries=0)
        self.assertEqual(result["status"], "partial")
        self.assertEqual(len(result["records"]), 1)
        self.assertIn("http_503", result["reasons"])

    def test_runtime_and_cli_parameter_bounds_reject_before_network(self):
        for key, value in [("timeout_seconds", 0), ("timeout_seconds", 181), ("max_retries", 4), ("max_retries", -1),
                           ("max_records", 0), ("max_records", 50001), ("max_response_bytes", 1023),
                           ("max_response_bytes", 33554433), ("max_records", True), ("max_retries", "2")]:
            with self.subTest(key=key, value=value), patch.object(runner.urllib.request, "build_opener") as network:
                with self.assertRaises(runner.InputError):
                    runner.collect("example.test", **{key: value})
                network.assert_not_called()
        for arguments in [[], ["--domain", "https://private.invalid"], ["--domain", "example.test", "--upstream", "https://private.invalid"],
                          ["--domain", "example.test", "--max-retries", "9"], ["--domain", "example.test", "--timeout-seconds", "nan"]]:
            with self.subTest(arguments=arguments), redirect_stdout(io.StringIO()) as stdout, patch.object(runner.urllib.request, "build_opener") as network:
                self.assertEqual(runner.main(arguments), 2)
                result = json.loads(stdout.getvalue())
                self.assertEqual(result["status"], "error")
                self.assertNotIn("private.invalid", stdout.getvalue())
                network.assert_not_called()

    def test_stdout_is_one_full_json_original_not_summary_or_preview(self):
        opener = Opener([Response(runner.json_bytes([cert()])), Response()])
        with patch.object(runner.urllib.request, "build_opener", return_value=opener), redirect_stdout(io.StringIO()) as stdout:
            self.assertEqual(runner.main(["--domain", "example.test"]), 0)
        result = json.loads(stdout.getvalue())
        self.assertEqual(len(stdout.getvalue().splitlines()), 1)
        self.assertEqual(result["schema"], "csai.crtsh.v1")
        self.assertEqual(result["records"][0]["certificates"][0]["id"], "123")
        self.assertNotIn("preview", result)
        self.assertNotIn("output_file", result)
        for key in ("schema", "query_domain", "status", "partial", "truncated", "coverage_complete", "candidate_only", "verification"):
            self.assertLess(stdout.getvalue().index('"' + key + '"'), stdout.getvalue().index('"records"'))

    def test_yaml_parameters_match_parser_and_no_arbitrary_query_escape(self):
        text = (Path(__file__).resolve().parents[1] / "tools" / "crtsh_search.yaml").read_text("utf-8")
        parser = runner.make_parser()
        args = parser.parse_args(["--domain", "example.test"])
        flags = {flag for action in parser._actions for flag in action.option_strings}
        for flag in re.findall(r'^\s+flag: "([^"\n]+)"$', text, re.M):
            self.assertIn(flag, flags)
        sections = re.split(r'(?m)^  - name: "([\w_]+)"$', text)
        for name, description in zip(sections[1::2], sections[2::2]):
            default = re.search(r"    default: (\d+)", description)
            if default:
                self.assertEqual(int(default[1]), getattr(args, name))
        self.assertNotIn("additional_args", text)
        self.assertIn("coverage_complete 永远 false", text)
        self.assertIn("scripts/crtsh-recon.py", text)


if __name__ == "__main__":
    unittest.main()
