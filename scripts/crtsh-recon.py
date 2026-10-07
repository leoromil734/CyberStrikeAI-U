#!/usr/bin/env python3
"""Bounded, passive crt.sh discovery. Python standard library only.

stdout is one csai.crtsh.v1 JSON original (not a preview/path manifest). The
platform must register it as JSON; certificate evidence remains at each host's
original byte range. Only https://crt.sh/ is contacted, never a discovered host.
IDNA uses Python's standard-library IDNA2003 codec, with strict DNS validation.
"""

import argparse
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import hashlib
import http.client
import ipaddress
import json
import re
import socket
import ssl
import sys
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request

UPSTREAM = "https://crt.sh/"
SCHEMA = "csai.crtsh.v1"
MAX_CERTIFICATES = 20000
MAX_NAMES = 200000
MAX_CERTIFICATES_PER_HOST = 64
MAX_OUTPUT_BYTES = 32 * 1024 * 1024
MAX_RETRY_DELAY = 5.0
LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z", re.ASCII)
DOTS = str.maketrans({"\u3002": ".", "\uff0e": ".", "\uff61": "."})
NAME_FIELDS = ("name_value", "common_name", "san", "sans", "subject_alt_name", "subject_alt_names")


class InputError(ValueError):
    pass


class QueryError(ValueError):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        fp.close()
        raise QueryError("redirect_not_allowed")


def normalize_domain(value, certificate=False):
    """Accept one DNS name, not a URL, IP, pattern, query or hostname:port."""
    if not isinstance(value, str) or len(value) > 1024:
        raise InputError("invalid_domain")
    if not certificate and any(unicodedata.category(ch).startswith("C") for ch in value):
        raise InputError("invalid_domain")
    value = value.strip().translate(DOTS)
    if certificate and value[:4].lower() == "dns:":
        value = value[4:].strip()
    if certificate and value.startswith("*."):
        value = value[2:]
    if not value or any(ch.isspace() or unicodedata.category(ch).startswith("C") for ch in value):
        raise InputError("invalid_domain")
    if any(ch in value for ch in "/\\:@?#&=%*[];,\"'"):
        raise InputError("invalid_domain")
    value = value.removesuffix(".")
    try:
        host = value.encode("idna").decode("ascii").lower()
        labels = host.split(".")
        if len(host) > 253 or len(labels) < 2 or any(not LABEL.fullmatch(label) for label in labels):
            raise InputError("invalid_domain")
        # Validate existing A-labels too; encoding an ASCII xn-- string alone
        # does not check its punycode. Numeric/legacy IP spellings are not DNS.
        if labels[-1].isdigit():
            raise InputError("invalid_domain")
        for label in labels:
            if label.startswith("xn--") and label.encode("ascii").decode("idna").encode("idna").decode("ascii") != label:
                raise InputError("invalid_domain")
    except UnicodeError as exc:
        raise InputError("invalid_domain") from exc
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return host
    raise InputError("invalid_domain")


def in_domain(host, domain):
    return host == domain or host.endswith("." + domain)


def json_bytes(value):
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), allow_nan=False).encode("ascii")


def query_url(query):
    # query is built only from an already validated domain, never user syntax.
    return UPSTREAM + "?" + urllib.parse.urlencode({"q": query, "output": "json"})


def retry_delay(headers, attempt):
    raw = (headers.get("Retry-After") or "").strip() if headers else ""
    try:
        delay = float(raw)
        if delay >= 0:  # also rejects NaN
            return min(delay, MAX_RETRY_DELAY)
    except ValueError:
        try:
            stamp = parsedate_to_datetime(raw)
            return min(MAX_RETRY_DELAY, max(0.0, (stamp - datetime.now(timezone.utc)).total_seconds()))
        except (ValueError, TypeError, OverflowError):
            pass
    return min(2 ** attempt, MAX_RETRY_DELAY)


def read_bounded(response, limit, deadline):
    chunks, size = [], 0
    # read1 returns after one underlying read, so a slow stream cannot reset a
    # whole-body deadline indefinitely. Each socket wait is additionally capped.
    while size <= limit:
        if time.monotonic() >= deadline:
            raise QueryError("timeout")
        chunk = response.read1(min(65536, limit + 1 - size))
        if not chunk:
            break
        chunks.append(chunk)
        size += len(chunk)
    return b"".join(chunks)


def reject_constant(_value):
    raise ValueError("non_json_number")


def fetch_query(opener, query, max_bytes, retries, deadline):
    url = query_url(query)
    meta = {"query": query, "url": url, "state": "error", "attempts": 0,
            "response_bytes": 0, "response_complete": False, "response_sha256": None,
            "response_sha256_scope": None, "retrieved_at": None}
    for attempt in range(retries + 1):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            meta["reason"] = "timeout"
            break
        headers, retry = None, False
        meta["attempts"] += 1
        request = urllib.request.Request(url, headers={"Accept": "application/json", "Accept-Encoding": "identity",
                                                     "User-Agent": "CyberStrikeAI-crtsh-passive/1.0"})
        try:
            with opener.open(request, timeout=min(20.0, remaining)) as response:
                if response.geturl() != url:
                    raise QueryError("redirect_not_allowed")
                meta["http_status"] = response.status
                if response.status != 200:
                    raise QueryError("unexpected_http_status")
                content_type = response.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
                if content_type not in ("application/json", "text/json"):
                    raise QueryError("non_json_response")
                if response.headers.get("Content-Encoding", "identity").lower() not in ("", "identity"):
                    raise QueryError("unexpected_content_encoding")
                data = read_bounded(response, max_bytes, deadline)
                meta["response_bytes"] = len(data)
                meta["response_sha256"] = hashlib.sha256(data).hexdigest()
                meta["response_sha256_scope"] = "captured_prefix"
                meta["retrieved_at"] = datetime.now(timezone.utc).isoformat()
                declared_length = response.headers.get("Content-Length")
                incomplete = False
                if declared_length is not None:
                    if not re.fullmatch(r"[0-9]{1,20}", declared_length.strip()):
                        raise QueryError("invalid_content_length")
                    incomplete = len(data) != int(declared_length)
                meta["response_complete"] = len(data) <= max_bytes and not incomplete
                meta["response_sha256_scope"] = "complete_response" if meta["response_complete"] else "captured_prefix"
                if len(data) > max_bytes:
                    raise QueryError("response_limit")
                if incomplete:
                    raise QueryError("incomplete_response")
                if time.monotonic() >= deadline:
                    raise QueryError("timeout")
                try:
                    payload = json.loads(data.decode("utf-8-sig"), parse_constant=reject_constant)
                except (ValueError, UnicodeError, RecursionError):
                    raise QueryError("invalid_json") from None
                if not isinstance(payload, list):
                    raise QueryError("invalid_json_envelope")
                meta["state"] = "success"
                meta.pop("reason", None)
                return payload, meta
        except urllib.error.HTTPError as exc:
            headers = exc.headers
            meta["http_status"] = exc.code
            meta["reason"] = "http_" + str(exc.code)
            retry = exc.code == 429 or 500 <= exc.code <= 599
            exc.close()
        except QueryError as exc:
            meta["reason"] = str(exc)
            # A consumed/truncated/HTML response is not silently retried or
            # interpreted as an empty result. Only transport failures retry.
            break
        except (urllib.error.URLError, OSError, http.client.HTTPException) as exc:
            reason = getattr(exc, "reason", exc)
            meta["reason"] = "tls_error" if isinstance(reason, ssl.SSLError) else (
                "timeout" if isinstance(reason, (TimeoutError, socket.timeout)) else "network_error")
            retry = meta["reason"] != "tls_error"
        if not retry or attempt == retries:
            break
        delay = retry_delay(headers, attempt)
        if delay >= deadline - time.monotonic():
            meta["reason"] = "timeout"
            break
        time.sleep(delay)
    return None, meta


def certificate_metadata(row, now):
    identifier = row.get("id")
    if isinstance(identifier, bool) or not isinstance(identifier, (int, str)):
        raise ValueError("invalid_certificate_id")
    identifier = str(identifier)
    if not re.fullmatch(r"[1-9][0-9]{0,31}", identifier):
        raise ValueError("invalid_certificate_id")
    result = {"id": identifier, "url": UPSTREAM + "?id=" + identifier}
    for field, limit in (("entry_timestamp", 64), ("not_before", 64), ("not_after", 64),
                         ("issuer_ca_id", 32), ("serial_number", 128)):
        value = row.get(field, "")
        if value is None:
            value = ""
        if field == "issuer_ca_id" and type(value) is int:
            value = str(value)
        if not isinstance(value, str) or len(value) > limit or any(unicodedata.category(ch).startswith("C") for ch in value):
            raise ValueError("invalid_certificate_metadata")
        result[field] = value
    result["time_status"] = "unknown"
    try:
        before = datetime.fromisoformat(result["not_before"].replace("Z", "+00:00"))
        after = datetime.fromisoformat(result["not_after"].replace("Z", "+00:00"))
        before = before.replace(tzinfo=timezone.utc) if before.tzinfo is None else before
        after = after.replace(tzinfo=timezone.utc) if after.tzinfo is None else after
        if before <= after:
            result["time_status"] = "expired" if after < now else ("not_yet_valid" if before > now else "within_certificate_dates")
    except (ValueError, OverflowError):
        pass
    return result


def certificate_names(row):
    """Yield individual CN/SAN values; no URL/IP SAN is turned into a host."""
    for field in NAME_FIELDS:
        value = row.get(field)
        if value is None or value == "":
            continue
        values = value if isinstance(value, list) else [value]
        for item in values:
            if not isinstance(item, str):
                yield None
                continue
            # finditer avoids allocating a large split list on hostile SAN data.
            for match in re.finditer(r"[^\r\n,]+", item):
                if match.group().strip():
                    yield match.group().strip()


def envelope(domain=""):
    return {"schema": SCHEMA, "source": "crt.sh", "query_domain": domain,
            "started_at": datetime.now(timezone.utc).isoformat(), "retrieved_at": None,
            "status": "error", "partial": True, "truncated": False,
            "coverage_complete": False, "coverage": "unknown", "candidate_only": True,
            "verification": "unverified", "historical_certificates_included": True,
            "notes": "Certificate names are candidates only, including expired certificates and wildcard suffixes. "
                     "They do not establish DNS/HTTP liveness, current ownership, authorization or exhaustive coverage. "
                     "Confirm scope and verify separately; no target is contacted by this tool.",
            "reasons": [], "queries": [], "records": []}


def collect(domain, timeout_seconds=60, max_retries=2, max_response_bytes=8 * 1024 * 1024, max_records=10000):
    domain = normalize_domain(domain)
    for value, minimum, maximum in ((timeout_seconds, 1, 180), (max_retries, 0, 3),
                                     (max_response_bytes, 1024, 32 * 1024 * 1024), (max_records, 1, 50000)):
        if type(value) is not int or not minimum <= value <= maximum:
            raise InputError("invalid_limit")
    result = envelope(domain)
    result["limits"] = {"timeout_seconds": timeout_seconds, "max_retries": max_retries,
                        "max_response_bytes": max_response_bytes, "max_records": max_records,
                        "max_certificates": MAX_CERTIFICATES, "max_names": MAX_NAMES,
                        "max_certificates_per_host": MAX_CERTIFICATES_PER_HOST, "max_output_bytes": MAX_OUTPUT_BYTES}
    counts = {"certificates_received": 0, "certificates_processed": 0, "invalid_certificates": 0,
              "names_seen": 0, "rejected_names": 0, "out_of_domain_names": 0,
              "duplicate_names": 0, "certificate_references": 0, "unique_hosts": 0}
    result["counts"] = counts
    hosts, references = {}, {}
    remaining, output_size = max_response_bytes, 0
    deadline, now = time.monotonic() + timeout_seconds, datetime.now(timezone.utc)
    # Environment proxies and all redirects are disabled: input cannot select
    # another upstream or cause this passive tool to contact a candidate host.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    stopped = False

    def gap(reason, truncated=False):
        if reason not in result["reasons"]:
            result["reasons"].append(reason)
        result["truncated"] = result["truncated"] or truncated

    # Exact apex plus descendants. Do not exclude expired certificates, and do
    # not recursively expand into sibling/parent domains from certificate SANs.
    for query in (domain, "%." + domain):
        if stopped or remaining <= 0 or time.monotonic() >= deadline:
            reason = "budget_exhausted" if stopped else ("response_limit" if remaining <= 0 else "timeout")
            gap(reason, reason == "response_limit")
            result["queries"].append({"query": query, "url": query_url(query), "state": "not_attempted", "reason": reason, "attempts": 0})
            continue
        rows, meta = fetch_query(opener, query, remaining, max_retries, deadline)
        result["queries"].append(meta)
        remaining -= meta["response_bytes"]
        if rows is None:
            gap(meta["reason"], meta["reason"] in ("response_limit", "incomplete_response"))
            continue
        counts["certificates_received"] += len(rows)
        for row in rows:
            if time.monotonic() >= deadline:
                gap("timeout")
                stopped = True
                break
            if counts["certificates_processed"] >= MAX_CERTIFICATES:
                gap("certificate_limit", True)
                stopped = True
                break
            counts["certificates_processed"] += 1
            try:
                if not isinstance(row, dict):
                    raise ValueError("invalid_certificate")
                certificate = certificate_metadata(row, now)
            except ValueError:
                counts["invalid_certificates"] += 1
                gap("invalid_certificates")
                continue
            had_name = False
            for name in certificate_names(row):
                had_name = True
                if time.monotonic() >= deadline:
                    gap("timeout")
                    stopped = True
                    break
                if counts["names_seen"] >= MAX_NAMES:
                    gap("name_limit", True)
                    stopped = True
                    break
                counts["names_seen"] += 1
                try:
                    host = normalize_domain(name, certificate=True)
                except InputError:
                    counts["rejected_names"] += 1
                    gap("invalid_names")
                    continue
                if not in_domain(host, domain):
                    counts["out_of_domain_names"] += 1
                    continue
                if host not in hosts and len(hosts) >= max_records:
                    gap("record_limit", True)
                    stopped = True
                    break
                matched = name[4:].strip() if name[:4].lower() == "dns:" else name
                cert = dict(certificate, name=name, wildcard=matched.translate(DOTS).startswith("*."))
                key = json_bytes(cert)
                seen = references.setdefault(host, set())
                if host in hosts:
                    counts["duplicate_names"] += 1
                if key in seen:
                    continue
                if len(seen) >= MAX_CERTIFICATES_PER_HOST:
                    gap("certificate_reference_limit", True)
                    continue
                # Reserve space for the bounded envelope/counters. Bound output
                # expansion from repeated certificate metadata before appending.
                cost = len(key) + len(host) + 256
                if output_size + cost > MAX_OUTPUT_BYTES - 65536:
                    gap("output_limit", True)
                    stopped = True
                    break
                output_size += cost
                record = hosts.setdefault(host, {"host": host, "source": "crt.sh", "candidate_only": True,
                                                  "verification": "unverified", "certificates": []})
                record["certificates"].append(cert)
                seen.add(key)
                counts["certificate_references"] += 1
            if not had_name:
                counts["invalid_certificates"] += 1
                gap("missing_certificate_names")
            if stopped:
                break
    counts["unique_hosts"] = len(hosts)
    result["retrieved_at"] = next((query["retrieved_at"] for query in reversed(result["queries"]) if query.get("retrieved_at")), None)
    result["records"] = list(hosts.values())
    result["partial"] = bool(result["reasons"])
    succeeded = any(query["state"] == "success" for query in result["queries"])
    result["status"] = "success" if not result["partial"] else ("partial" if succeeded or result["truncated"] else "error")
    return result


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise InputError("invalid_arguments")


def bounded_int(minimum, maximum):
    def parse(value):
        number = int(value)
        if not minimum <= number <= maximum:
            raise ValueError("out_of_range")
        return number
    return parse


def make_parser():
    parser = Parser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--domain", required=True)
    parser.add_argument("--timeout-seconds", type=bounded_int(1, 180), default=60)
    parser.add_argument("--max-retries", type=bounded_int(0, 3), default=2)
    parser.add_argument("--max-response-bytes", type=bounded_int(1024, 32 * 1024 * 1024), default=8 * 1024 * 1024)
    parser.add_argument("--max-records", type=bounded_int(1, 50000), default=10000)
    return parser


def main(argv=None):
    try:
        args = make_parser().parse_args(argv)
        result = collect(**vars(args))
    except InputError as exc:
        result = envelope()
        result["reasons"] = [str(exc)]
        print(json_bytes(result).decode("ascii"))
        return 2
    print(json_bytes(result).decode("ascii"))
    return 1 if result["status"] == "error" else 0


if __name__ == "__main__":
    sys.exit(main())
