"""Offline crt.sh tests: fixed JSON, mocked transport, and no target/network access.

The tool no longer goes through urllib's opener: it opens a socket itself and
speaks HTTPS to crt.sh (optionally through a declared SOCKS5/HTTP CONNECT proxy).
The transport seam this file patches is therefore `build_connection`. The fake
socket still exposes `makefile("rb")`, which is what the production code asks for,
so the real response parsing, header handling and Content-Length checks all run.
"""

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
import tempfile
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


def raw_response(body=b"[]", status=200, content_type="application/json", **headers):
    """Build the bytes a real crt.sh response would put on the wire."""
    if isinstance(body, str):
        body = body.encode()
    head = ["HTTP/1.1 %d OK" % status, "Content-Type: %s" % content_type]
    for name, value in headers.items():
        head.append("%s: %s" % (name.replace("_", "-"), value))
    return ("\r\n".join(head) + "\r\n\r\n").encode("ascii") + body


class FakeSocket:
    """A socket-shaped object limited to what fetch_query actually uses.

    `makefile("rb")` must return a readable stream for the response, and
    `makefile("wb")` a writable one for the request that HTTPSConnection writes.
    A real socket provides both, so the fake wires itself to an in-memory buffer
    rather than pretending makefile has one mode.
    """

    def __init__(self, payload=b"", error=None):
        self.payload = payload
        self.error = error
        self.bytes_read = 0
        self.closed = False
        self.timeouts = []
        self.sent = b""

    def makefile(self, mode):
        if "r" in mode:
            if self.error is not None:
                raise self.error
            return io.BytesIO(self.payload)
        # Writable side: HTTPSConnection.putrequest appends to this buffer, so it
        # must be a real bytearray, not a BytesIO.
        writer = self

        class Sink(io.RawIOBase):
            def writable(self):
                return True

            def write(self, data):
                writer.sent += bytes(data)
                return len(data)

        return io.BufferedWriter(Sink())

    def sendall(self, data):
        self.sent += data

    def recv(self):
        raise AssertionError("recv must not be used once a file object exists")

    def settimeout(self, value):
        self.timeouts.append(value)

    def close(self):
        self.closed = True


class FakeConnection:
    """Stands in for DirectConnection/ProxiedConnection."""

    def __init__(self, outcomes):
        self.outcomes = iter(outcomes)
        self.calls = []
        self.label = "direct"
        self.opened = 0

    def open(self):
        self.opened += 1
        outcome = next(self.outcomes)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


class CrtshTests(unittest.TestCase):
    def setUp(self):
        # Even an accidental unmocked path must not resolve or contact a target.
        for name in ("getaddrinfo", "create_connection"):
            guard = patch.object(socket, name, side_effect=AssertionError("real network forbidden"))
            guard.start()
            self.addCleanup(guard.stop)

    def connect(self, outcomes):
        fake = FakeConnection(outcomes)
        patcher = patch.object(runner, "build_connection", return_value=fake)
        patcher.start()
        self.addCleanup(patcher.stop)
        return fake

    def run_fixture(self, rows, second=None, **kwargs):
        outcomes = [FakeSocket(raw_response(runner.json_bytes(rows))),
                    FakeSocket(raw_response(runner.json_bytes([] if second is None else second)))]
        fake = self.connect(outcomes)
        result = runner.collect("example.test", state_path=self.state_path(), **kwargs)
        return result, fake

    def state_path(self):
        # The health short-circuit keeps durable state; a test must never inherit
        # or leave behind the operator's real one.
        if not hasattr(self, "_state_path"):
            handle = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
            handle.close()
            self._state_path = handle.name
        return self._state_path

    # ------------------------------------------------------------------
    # Input validation
    # ------------------------------------------------------------------

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
        with patch.object(runner, "build_connection") as network:
            for value in bad:
                with self.subTest(value=value), self.assertRaises(runner.InputError):
                    runner.collect(value, state_path=self.state_path())
            network.assert_not_called()

    # ------------------------------------------------------------------
    # Extraction
    # ------------------------------------------------------------------

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
        self.connect([FakeSocket(raw_response(runner.json_bytes(rows))), FakeSocket(raw_response())])
        result = runner.collect("BÜCHER.example", state_path=self.state_path())
        self.assertEqual(result["query_domain"], "xn--bcher-kva.example")
        self.assertEqual([r["host"] for r in result["records"]], ["xn--bcher-kva.example", "shop.xn--bcher-kva.example"])

    def test_fixed_https_queries_and_no_direct_egress_without_declared_proxy(self):
        result, fake = self.run_fixture([cert("other.test\nexample.test")])
        self.assertEqual(fake.opened, 2)
        # Exactly two queries, in a fixed order, against the fixed upstream.
        self.assertEqual([q["query"] for q in result["queries"]], ["example.test", "%.example.test"])
        for query in result["queries"]:
            parsed = urllib.parse.urlsplit(query["url"])
            self.assertEqual((parsed.scheme, parsed.netloc, parsed.path), ("https", "crt.sh", "/"))
            self.assertEqual(urllib.parse.parse_qs(parsed.query)["output"], ["json"])
        # Ambient proxy environment variables are ignored; egress is direct unless
        # the caller declared one.
        self.assertEqual(result["egress"]["mode"], "direct")
        with patch.dict("os.environ", {"HTTPS_PROXY": "http://ambient.invalid:8080", "ALL_PROXY": "socks5://ambient.invalid:1080"}):
            _, ambient = self.run_fixture([cert()])
        self.assertEqual(ambient.opened, 2)

    def test_fixed_subdomain_scope_does_not_expand_to_parent_or_siblings(self):
        rows = [cert("example.test\nsibling.example.test\napi.example.test\nadmin.api.example.test")]
        self.connect([FakeSocket(raw_response(runner.json_bytes(rows))), FakeSocket(raw_response())])
        result = runner.collect("api.example.test", state_path=self.state_path())
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

    # ------------------------------------------------------------------
    # Response handling
    # ------------------------------------------------------------------

    def test_no_json_html_error_object_invalid_utf8_not_empty_success(self):
        for body, content_type, reason in [(b"<html>rate limit</html>", "text/html", "non_json_response"),
                                           (b"<html>failed</html>", "application/json", "invalid_json"),
                                           (b'{"error":"busy"}', "application/json", "invalid_json_envelope"),
                                           (b"null", "application/json", "invalid_json_envelope"),
                                           (b"", "application/json", "invalid_json"), (b"[", "application/json", "invalid_json"),
                                           (b"[NaN]", "application/json", "invalid_json"), (b"[\xff]", "application/json", "invalid_json")]:
            with self.subTest(reason=reason, body=body):
                self.connect([FakeSocket(raw_response(body, content_type=content_type)),
                              FakeSocket(raw_response(body, content_type=content_type))])
                result = runner.collect("example.test", state_path=self.state_path())
                self.assertEqual(result["status"], "error")
                self.assertTrue(result["partial"])
                self.assertIn(reason, result["reasons"])
                self.assertEqual(result["records"], [])

    def test_non_200_redirect_and_encoding_are_never_treated_as_data(self):
        # A redirect is reported, never followed: the tool reads only the answer
        # for the URL it asked about.
        self.connect([FakeSocket(raw_response(b"moved", status=302, Location="https://other.test/")),
                      FakeSocket(raw_response(b"moved", status=302, Location="https://other.test/"))])
        result = runner.collect("example.test", state_path=self.state_path())
        self.assertEqual(result["status"], "error")
        self.assertIn("redirect_not_allowed", result["reasons"])
        self.assertEqual(result["queries"][0]["http_status"], 302)
        self.assertEqual(result["queries"][0]["attempts"], 1, "a redirect is never retried")
        self.assertEqual(result["records"], [])

        self.connect([FakeSocket(raw_response(**{"Content-Encoding": "gzip"})),
                      FakeSocket(raw_response(**{"Content-Encoding": "gzip"}))])
        result = runner.collect("example.test", state_path=self.state_path())
        self.assertIn("unexpected_content_encoding", result["reasons"])

    def test_incomplete_http_body_even_valid_json_is_not_empty_success(self):
        self.connect([FakeSocket(raw_response(b"[]", Content_Length="10")),
                      FakeSocket(raw_response(b"[]", Content_Length="10"))])
        result = runner.collect("example.test", state_path=self.state_path())
        self.assertEqual(result["status"], "partial")
        self.assertTrue(result["truncated"])
        self.assertIn("incomplete_response", result["reasons"])
        self.assertTrue(all(not q["response_complete"] for q in result["queries"]))

    def test_response_limit_drops_incomplete_json_not_prior_complete_candidates(self):
        first = FakeSocket(raw_response(runner.json_bytes([cert()])))
        second = FakeSocket(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n" + b"[" + b" " * 10000)
        self.connect([first, second])
        result = runner.collect("example.test", max_response_bytes=1024, state_path=self.state_path())
        self.assertEqual(result["status"], "partial")
        self.assertTrue(result["truncated"])
        self.assertIn("response_limit", result["reasons"])
        self.assertEqual([r["host"] for r in result["records"]], ["www.example.test"])
        self.assertEqual(result["queries"][1]["state"], "error")
        self.assertFalse(result["queries"][1]["response_complete"])
        self.assertEqual(result["queries"][1]["response_sha256_scope"], "captured_prefix")
        self.assertEqual(result["queries"][0]["response_sha256_scope"], "complete_response")

    def test_first_response_oversize_and_cumulative_response_budget(self):
        fake = self.connect([FakeSocket(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n" + b"[" + b" " * 2000)])
        result = runner.collect("example.test", max_response_bytes=1024, state_path=self.state_path())
        self.assertEqual(fake.opened, 1)
        self.assertEqual(result["status"], "partial")
        self.assertTrue(result["truncated"])
        self.assertEqual(result["queries"][1]["state"], "not_attempted")
        self.assertEqual(result["records"], [])

    # ------------------------------------------------------------------
    # Retries and failure classification
    # ------------------------------------------------------------------

    def test_rate_limit_server_failure_timeout_bounded_retry_then_success(self):
        failures = [FakeSocket(raw_response(b"slow down", status=429, Retry_After="1")),
                    urllib.error.URLError(TimeoutError()),
                    socket.timeout(), OSError("connection reset")]
        for failure in failures:
            with self.subTest(failure=failure):
                self.connect([failure, FakeSocket(raw_response(runner.json_bytes([cert()]))), FakeSocket(raw_response())])
                with patch.object(runner.time, "sleep") as sleep:
                    result = runner.collect("example.test", max_retries=1, state_path=self.state_path())
                self.assertEqual(result["status"], "success")
                self.assertEqual(result["queries"][0]["attempts"], 2)
                self.assertEqual(result["queries"][0]["http_status"], 200)
                self.assertEqual(sleep.call_count, 1)
                self.assertLessEqual(sleep.call_args.args[0], 5)

    def test_retry_exhaustion_and_permanent_error_have_truthful_state(self):
        # 4xx that is not a rate limit is permanent: exactly one attempt per query.
        # 429/5xx retries up to max_retries extra attempts.
        for code, retry in [(429, 2), (500, 1), (599, 1), (403, 3), (404, 3)]:
            with self.subTest(code=code):
                # Each subtest needs its own breaker file, or a tripped 429 from
                # the previous iteration would short-circuit this one instead of
                # exercising the retry path the subtest is about.
                state = tempfile.NamedTemporaryFile(suffix=".json", delete=False).name
                expected_attempts = retry + 1 if code == 429 or code >= 500 else 1
                sock = FakeSocket(raw_response(b"denied", status=code, content_type="text/html"))
                fake = self.connect([sock for _ in range(expected_attempts * 2)])
                with patch.object(runner.time, "sleep"):
                    result = runner.collect("example.test", max_retries=retry, state_path=state)
                self.assertEqual(result["status"], "error")
                self.assertEqual(result["queries"][0]["attempts"], expected_attempts)
                self.assertEqual(result["queries"][0]["http_status"], code)
                self.assertEqual(fake.opened, expected_attempts * 2)
                self.assertFalse(result["coverage_complete"])
        # A TLS failure is never retried and is recorded as an upstream health
        # signal rather than a network hiccup.
        self.connect([FakeSocket(error=ssl.SSLError("handshake")), FakeSocket(error=ssl.SSLError("handshake"))])
        result = runner.collect("example.test", state_path=tempfile.NamedTemporaryFile(suffix=".json", delete=False).name)
        self.assertIn("tls_error", result["reasons"])
        self.assertEqual(result["queries"][0]["attempts"], 1)

    def test_retry_after_numeric_date_and_budget(self):
        self.assertEqual(runner.retry_delay({"Retry-After": "0"}, 0), 0)
        self.assertEqual(runner.retry_delay({"Retry-After": "10000"}, 0), 5)
        self.assertEqual(runner.retry_delay({"Retry-After": "NaN"}, 0), 1)
        stamp = format_datetime(datetime(2099, 1, 1, tzinfo=timezone.utc))
        self.assertEqual(runner.retry_delay({"Retry-After": stamp}, 0), 5)
        self.connect([FakeSocket(raw_response(b"busy", status=429, Retry_After="5")) for _ in range(2)])
        with patch.object(runner.time, "sleep") as sleep:
            result = runner.collect("example.test", timeout_seconds=1, state_path=self.state_path())
        sleep.assert_not_called()
        self.assertEqual(result["status"], "error")
        self.assertIn("timeout", result["reasons"])

    def test_deadline_checked_while_reading_and_before_new_queries(self):
        with patch.object(runner.time, "monotonic", return_value=10), self.assertRaisesRegex(runner.QueryError, "timeout"):
            runner.read_bounded(FakeSocket(raw_response(b"[]")).makefile("rb"), 1024, 9)
        fake = self.connect([])
        with patch.object(runner.time, "monotonic", side_effect=[0, 2, 3]):
            result = runner.collect("example.test", timeout_seconds=1, state_path=self.state_path())
        self.assertEqual(fake.opened, 0)
        self.assertEqual(result["status"], "error")
        self.assertTrue(all(q["state"] == "not_attempted" for q in result["queries"]))

    # ------------------------------------------------------------------
    # Budgets
    # ------------------------------------------------------------------

    def test_record_cap_and_exact_boundary_are_distinguished(self):
        result, fake = self.run_fixture([cert("a.example.test\nb.example.test\nc.example.test")], max_records=2)
        self.assertEqual(len(result["records"]), 2)
        self.assertIn("record_limit", result["reasons"])
        self.assertTrue(result["truncated"])
        self.assertEqual(fake.opened, 1)
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

    # ------------------------------------------------------------------
    # Upstream health short-circuit
    # ------------------------------------------------------------------

    def test_upstream_failure_is_recorded_and_then_short_circuits(self):
        state = self.state_path()
        # Two consecutive 429s reach the trip threshold, so the next call must not
        # open a connection at all.
        self.connect([FakeSocket(raw_response(b"slow down", status=429)),
                      FakeSocket(raw_response(b"slow down", status=429))])
        with patch.object(runner.time, "sleep"):
            first = runner.collect("example.test", max_retries=0, state_path=state,
                                   health_window_seconds=900, health_trip_failures=2)
        self.assertEqual(first["upstream_health"]["decision"], "recorded")
        self.assertEqual(first["upstream_health"]["consecutive_failures"], 1)

        self.connect([FakeSocket(raw_response(b"slow down", status=429)),
                      FakeSocket(raw_response(b"slow down", status=429))])
        with patch.object(runner.time, "sleep"):
            second = runner.collect("example.test", max_retries=0, state_path=state,
                                    health_window_seconds=900, health_trip_failures=2)
        self.assertEqual(second["upstream_health"]["decision"], "tripped")

        no_network = self.connect([])
        third = runner.collect("another.test", state_path=state,
                               health_window_seconds=900, health_trip_failures=2)
        self.assertEqual(no_network.opened, 0, "a tripped upstream must not be contacted again")
        self.assertTrue(third["short_circuit"])
        self.assertEqual(third["status"], "blocked")
        self.assertEqual(third["records"], [])
        self.assertTrue(third["partial"])
        self.assertFalse(third["coverage_complete"])
        self.assertEqual(third["upstream_health"]["decision"], "blocked")
        # The previous raw error travels with the gap fact.
        self.assertIn("429", str(third["upstream_health"]["last_error"]))
        self.assertIsInstance(third["upstream_health"]["retry_after_ms"], int)
        self.assertTrue(all(q["state"] == "not_attempted" for q in third["queries"]))
        self.assertIn("crtsh_upstream_unhealthy", third["reasons"])

    def test_success_clears_a_recorded_failure(self):
        state = self.state_path()
        self.connect([FakeSocket(raw_response(b"boom", status=500)), FakeSocket(raw_response(b"boom", status=500))])
        runner.collect("example.test", max_retries=0, state_path=state, health_trip_failures=2)
        self.connect([FakeSocket(raw_response(runner.json_bytes([cert()]))), FakeSocket(raw_response())])
        recovered = runner.collect("example.test", max_retries=0, state_path=state, health_trip_failures=2)
        self.assertEqual(recovered["upstream_health"]["decision"], "pass")
        # One successful query is enough to declare the upstream usable again.
        self.connect([FakeSocket(raw_response(runner.json_bytes([cert()]))), FakeSocket(raw_response())])
        after = runner.collect("example.test", state_path=state, health_trip_failures=2)
        self.assertFalse(after.get("short_circuit", False))

    def test_a_malformed_body_never_trips_the_breaker(self):
        state = self.state_path()
        for _ in range(3):
            self.connect([FakeSocket(raw_response(b"<html>oops</html>", content_type="text/html")),
                          FakeSocket(raw_response(b"<html>oops</html>", content_type="text/html"))])
            result = runner.collect("example.test", max_retries=0, state_path=state, health_trip_failures=2)
            self.assertEqual(result["upstream_health"]["decision"], "pass")
            self.assertFalse(result.get("short_circuit", False))

    def test_a_single_slow_response_never_trips_the_breaker(self):
        state = self.state_path()
        for _ in range(3):
            # max_retries=1 means each query opens the connection twice: the
            # original attempt plus one retry. Two queries, so four sockets.
            self.connect([urllib.error.URLError(TimeoutError()) for _ in range(4)])
            with patch.object(runner.time, "sleep"):
                result = runner.collect("example.test", max_retries=1, timeout_seconds=5,
                                        state_path=state, health_trip_failures=2)
            self.assertIn("timeout", result["reasons"])
            self.assertEqual(result["upstream_health"]["decision"], "pass")

    def test_short_circuit_can_be_disabled_and_exits_non_zero(self):
        state = self.state_path()
        self.connect([FakeSocket(raw_response(b"slow", status=429)), FakeSocket(raw_response(b"slow", status=429))])
        runner.collect("example.test", max_retries=0, state_path=state, health_trip_failures=2)
        # --health-trip-failures 0 关闭短路：即使上游刚失败，也会真的再发请求。
        fake = self.connect([FakeSocket(raw_response(runner.json_bytes([cert()]))), FakeSocket(raw_response())])
        with redirect_stdout(io.StringIO()) as stdout:
            with patch.dict("os.environ", {"CYBERSTRIKE_CRTSH_STATE": state}):
                code = runner.main(["--domain", "example.test", "--health-trip-failures", "0"])
        self.assertEqual(code, 0)
        self.assertFalse(json.loads(stdout.getvalue()).get("short_circuit", False))
        self.assertEqual(fake.opened, 2)

    # ------------------------------------------------------------------
    # Proxy egress
    # ------------------------------------------------------------------

    def test_proxy_url_forms_are_parsed_and_bad_ones_refused(self):
        spec = runner.parse_proxy("socks5://user:pass@proxy.example:1080")
        self.assertEqual((spec["scheme"], spec["host"], spec["port"], spec["username"], spec["password"]),
                         ("socks5", "proxy.example", 1080, "user", "pass"))
        # The provider's bare host:port:user:pass form is accepted because that is
        # how rotating residential endpoints are issued.
        bare = runner.parse_proxy("us.mooproxy.net:55688:ipippool:s3cret_country-us_session_abc")
        self.assertEqual((bare["host"], bare["port"], bare["username"]),
                         ("us.mooproxy.net", 55688, "ipippool"))
        self.assertEqual(bare["password"], "s3cret_country-us_session_abc")
        self.assertIsNone(runner.parse_proxy(""))
        self.assertIsNone(runner.parse_proxy(None))
        for value in ["ftp://proxy.example:21", "proxy.example", "proxy.example:0", "proxy.example:70000",
                      "://proxy.example:1080", "http://:8080"]:
            with self.subTest(value=value), self.assertRaises(runner.InputError):
                runner.parse_proxy(value)

    def test_declared_proxy_is_used_and_labelled_without_leaking_credentials(self):
        args = runner.make_parser().parse_args(["--domain", "example.test", "--proxy", "socks5://user:pass@proxy.example:1080"])
        spec = runner.parse_proxy(args.proxy)
        result, fake = self.run_fixture([cert()], proxy=spec, connection_label=spec["raw"])
        self.assertEqual(result["egress"]["mode"], "proxy")
        # The label is the caller's own string, not the environment's; a model
        # reading the envelope must be able to tell which exit was used.
        self.assertIn("proxy.example:1080", result["egress"]["endpoint"])
        self.assertEqual(fake.opened, 2)

    def test_socks5_handshake_sends_credentials_and_rejects_failures(self):
        sent = []

        class Sock:
            def __init__(self, replies):
                self.replies = list(replies)
                self.sent = b""

            def sendall(self, data):
                self.sent += data
                sent.append(data)

            def recv(self, size):
                if not self.replies:
                    return b""
                return self.replies.pop(0)

            def settimeout(self, _value):
                return None

        # Method selection offers username/password, and CONNECT names crt.sh.
        # read_exact() reads a fixed width at a time: greeting, auth status, the
        # four-byte CONNECT reply head, the four address bytes, then the two port
        # bytes. The reply must therefore arrive as its own chunks, exactly as a
        # server writes them.
        good = Sock([b"\x05\x02", b"\x01\x00", b"\x05\x00\x00\x01", b"\x7f\x00\x00\x01", b"\x00\x50"])
        runner._socks5_handshake(good, "crt.sh", 443, "user", "pass", 1e18)
        self.assertIn(b"\x00\x02", good.sent)
        self.assertIn(b"\x01\x04user\x04pass", good.sent)
        self.assertIn(b"\x03\x06crt.sh", good.sent)

        # A rejected credential is an error, not a silent downgrade to direct.
        rejected = Sock([b"\x05\x02", b"\x01\x01"])
        with self.assertRaisesRegex(runner.Socks5Error, "proxy_auth_rejected"):
            runner._socks5_handshake(rejected, "crt.sh", 443, "user", "pass", 1e18)

        # No acceptable method is also an error.
        no_method = Sock([b"\x05\xff"])
        with self.assertRaisesRegex(runner.Socks5Error, "proxy_method_rejected"):
            runner._socks5_handshake(no_method, "crt.sh", 443, "user", "pass", 1e18)

    def test_http_connect_proxy_is_declared_never_ambient(self):
        spec = runner.parse_proxy("http://user:pass@proxy.example:3128")
        connection = runner.build_connection(spec, 1e18)
        self.assertIsInstance(connection, runner.ProxiedConnection)
        self.assertEqual(connection.label, "http://proxy.example:3128")
        self.assertIsInstance(runner.build_connection(None, 1e18), runner.DirectConnection)

    # ------------------------------------------------------------------
    # CLI and contract
    # ------------------------------------------------------------------

    def test_runtime_and_cli_parameter_bounds_reject_before_network(self):
        for key, value in [("timeout_seconds", 0), ("timeout_seconds", 181), ("max_retries", 4), ("max_retries", -1),
                           ("max_records", 0), ("max_records", 50001), ("max_response_bytes", 1023),
                           ("max_response_bytes", 33554433), ("max_records", True), ("max_retries", "2"),
                           ("health_window_seconds", 86401), ("health_trip_failures", 21)]:
            with self.subTest(key=key, value=value), patch.object(runner, "build_connection") as network:
                with self.assertRaises(runner.InputError):
                    runner.collect("example.test", state_path=self.state_path(), **{key: value})
                network.assert_not_called()
        for arguments in [[], ["--domain", "https://private.invalid"], ["--domain", "example.test", "--upstream", "https://private.invalid"],
                          ["--domain", "example.test", "--max-retries", "9"], ["--domain", "example.test", "--timeout-seconds", "nan"],
                          ["--domain", "example.test", "--proxy", "ftp://private.invalid:21"]]:
            with self.subTest(arguments=arguments), redirect_stdout(io.StringIO()) as stdout, patch.object(runner, "build_connection") as network:
                with patch.dict("os.environ", {"CYBERSTRIKE_CRTSH_STATE": self.state_path()}):
                    self.assertEqual(runner.main(arguments), 2)
                result = json.loads(stdout.getvalue())
                self.assertEqual(result["status"], "error")
                self.assertNotIn("private.invalid", stdout.getvalue())
                network.assert_not_called()

    def test_stdout_is_one_full_json_original_not_summary_or_preview(self):
        self.connect([FakeSocket(raw_response(runner.json_bytes([cert()]))), FakeSocket(raw_response())])
        with redirect_stdout(io.StringIO()) as stdout:
            with patch.dict("os.environ", {"CYBERSTRIKE_CRTSH_STATE": self.state_path()}):
                self.assertEqual(runner.main(["--domain", "example.test"]), 0)
        result = json.loads(stdout.getvalue())
        self.assertEqual(len(stdout.getvalue().splitlines()), 1)
        self.assertEqual(result["schema"], "csai.crtsh.v1")
        self.assertEqual(result["records"][0]["certificates"][0]["id"], "123")
        self.assertNotIn("preview", result)
        self.assertNotIn("output_file", result)
        for key in ("schema", "query_domain", "status", "partial", "truncated", "coverage_complete", "candidate_only", "verification"):
            self.assertLess(stdout.getvalue().index('"' + key + '"'), stdout.getvalue().index('"records"'))

    def test_blocked_envelope_exits_non_zero_and_keeps_the_gap(self):
        state = self.state_path()
        # Seed the recorded upstream failure at the trip threshold: this test is
        # about what a short-circuited call returns, not about how many failures
        # it takes to trip (that is covered above).
        runner.record_upstream_failure(runner.load_state(state), state, "crtsh_http_429",
                                       "HTTP 429 from https://crt.sh/?q=example.test&output=json")
        runner.record_upstream_failure(runner.load_state(state), state, "crtsh_http_429",
                                       "HTTP 429 from https://crt.sh/?q=example.test&output=json")
        # No outcome is supplied: a short-circuited call must not open a socket.
        self.connect([])
        with patch.dict("os.environ", {"CYBERSTRIKE_CRTSH_STATE": state}):
            with redirect_stdout(io.StringIO()) as stdout:
                code = runner.main(["--domain", "example.test"])
        result = json.loads(stdout.getvalue())
        self.assertEqual(code, 1, "a short-circuited call is a blocked fact, not a successful empty result")
        self.assertEqual(result["status"], "blocked")
        self.assertTrue(result["short_circuit"])
        self.assertEqual(result["records"], [])
        self.assertEqual([q["state"] for q in result["queries"]], ["not_attempted", "not_attempted"])
        self.assertIn("429", str(result["upstream_health"]["last_error"]))
        self.assertIn("crtsh_upstream_unhealthy", result["reasons"])

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
        # The short-circuit and the proxy option are part of the published contract.
        self.assertIn("short_circuit", text)
        self.assertIn("blocked", text)
        self.assertIn("--proxy", text)


if __name__ == "__main__":
    unittest.main()
