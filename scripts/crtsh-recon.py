#!/usr/bin/env python3
"""Bounded, passive crt.sh discovery. Python standard library only.

stdout is one csai.crtsh.v1 JSON original (not a preview/path manifest). The
platform must register it as JSON; certificate evidence remains at each host's
original byte range. Only https://crt.sh/ is contacted, never a discovered host.
IDNA uses Python's standard-library IDNA2003 codec, with strict DNS validation.

Two operational safeguards are implemented here:

1. Upstream health short-circuit. Repeated 429/5xx from crt.sh is remembered on
   disk, so the next calls inside the window return a blocked envelope carrying
   the previous raw error instead of waiting out the full retry budget again.
2. Optional explicit proxy egress. crt.sh is a fixed public upstream, so a
   residential/rotating egress is legitimate. Passing --proxy switches the tool
   from "no proxy at all" to exactly that proxy; refusing to run without one is
   not the goal, silently honouring ambient proxies is.
"""

import argparse
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import hashlib
import http.client
import ipaddress
import json
import os
import re
import socket
import ssl
import struct
import sys
import tempfile
import time
import unicodedata
import urllib.error
import urllib.parse

UPSTREAM = "https://crt.sh/"
UPSTREAM_HOST = "crt.sh"
UPSTREAM_PORT = 443
SCHEMA = "csai.crtsh.v1"
MAX_CERTIFICATES = 20000
MAX_NAMES = 200000
MAX_CERTIFICATES_PER_HOST = 64
MAX_OUTPUT_BYTES = 32 * 1024 * 1024
MAX_RETRY_DELAY = 5.0
LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z", re.ASCII)
DOTS = str.maketrans({"\u3002": ".", "\uff0e": ".", "\uff61": "."})
NAME_FIELDS = ("name_value", "common_name", "san", "sans", "subject_alt_name", "subject_alt_names")
USER_AGENT = "CyberStrikeAI-crtsh-passive/1.0"

# Upstream short-circuit defaults. A single crt.sh call can spend 60s of timeout
# budget plus retry backoff; skipping the second and later calls inside the
# window is the whole point of remembering the failure.
DEFAULT_HEALTH_WINDOW_SECONDS = 900
DEFAULT_HEALTH_TRIP_FAILURES = 2
MAX_HEALTH_WINDOW_SECONDS = 86400
MAX_HEALTH_TRIP_FAILURES = 20

# A tripped upstream is a rate limit or an outage, not a permanent condition.
# Cooldown >= window means exactly one probe per window, which bounds the cost
# of the automatic recovery attempt while still allowing recovery.
BREAKER_COOLDOWN_FACTOR = 2


class InputError(ValueError):
    pass


class QueryError(ValueError):
    pass


class UpstreamUnhealthy(QueryError):
    """Raised before any request when the recorded upstream failure is still fresh."""

    def __init__(self, reason, *, retry_after_ms=None, last_error=None):
        super().__init__(reason)
        self.note = reason
        self.retry_after_ms = retry_after_ms
        self.last_error = last_error


# --------------------------------------------------------------------------
# Explicit proxy egress (SOCKS5 with username/password, and HTTP CONNECT)
# --------------------------------------------------------------------------

class Socks5Error(OSError):
    pass


def _socks5_handshake(sock, host, port, username, password, deadline):
    """Negotiate SOCKS5 CONNECT on an already connected socket.

    Only the no-auth (0x00) and username/password (0x02) methods are offered.
    Replies a closed socket rather than a half-open tunnel on any failure.
    """
    methods = b"\x00\x02" if username else b"\x00"
    sock.sendall(b"\x05" + bytes([len(methods)]) + methods)

    def read_exact(count):
        chunks, got = [], 0
        while got < count:
            remaining = min(20.0, deadline - time.monotonic())
            if remaining <= 0:
                raise Socks5Error("proxy_timeout")
            sock.settimeout(remaining)
            chunk = sock.recv(count - got)
            if not chunk:
                raise Socks5Error("proxy_handshake_failed")
            chunks.append(chunk)
            got += len(chunk)
        return b"".join(chunks)

    head = read_exact(2)
    if head[0] != 0x05:
        raise Socks5Error("proxy_bad_version")
    method = head[1]
    if method == 0x02:
        encoded_user = username.encode("utf-8")
        encoded_pass = password.encode("utf-8")
        if len(encoded_user) > 255 or len(encoded_pass) > 255:
            raise Socks5Error("proxy_credentials_too_long")
        sock.sendall(b"\x01" + bytes([len(encoded_user)]) + encoded_user
                     + bytes([len(encoded_pass)]) + encoded_pass)
        if read_exact(2)[1] != 0x00:
            raise Socks5Error("proxy_auth_rejected")
    elif method != 0x00:
        raise Socks5Error("proxy_method_rejected")

    try:
        target = host.encode("idna")
    except UnicodeError:
        raise Socks5Error("proxy_target_invalid") from None
    if len(target) > 255:
        raise Socks5Error("proxy_target_invalid")
    sock.sendall(b"\x05\x01\x00\x03" + bytes([len(target)]) + target + struct.pack("!H", port))

    reply = read_exact(4)
    if reply[1] != 0x00:
        raise Socks5Error("proxy_connect_failed_" + str(reply[1]))
    if reply[3] == 0x01:
        read_exact(4)
    elif reply[3] == 0x03:
        read_exact(read_exact(1)[0])
    elif reply[3] == 0x04:
        read_exact(16)
    else:
        raise Socks5Error("proxy_bad_address_type")
    read_exact(2)


def _http_connect_handshake(sock, host, port, username, password, deadline):
    """Establish a tunnel through an HTTP proxy using CONNECT."""
    authority = "%s:%d" % (host, port)
    lines = ["CONNECT " + authority + " HTTP/1.1", "Host: " + authority,
             "Proxy-Connection: Keep-Alive"]
    if username:
        import base64
        token = base64.b64encode((username + ":" + password).encode("utf-8")).decode("ascii")
        lines.append("Proxy-Authorization: Basic " + token)
    sock.sendall(("\r\n".join(lines) + "\r\n\r\n").encode("ascii"))

    buffer = b""
    while b"\r\n\r\n" not in buffer:
        if len(buffer) > 65536:
            raise Socks5Error("proxy_response_too_large")
        remaining = min(20.0, deadline - time.monotonic())
        if remaining <= 0:
            raise Socks5Error("proxy_timeout")
        sock.settimeout(remaining)
        chunk = sock.recv(4096)
        if not chunk:
            raise Socks5Error("proxy_handshake_failed")
        buffer += chunk
    status_line = buffer.split(b"\r\n", 1)[0].split()
    if len(status_line) < 2 or status_line[1] != b"200":
        code = status_line[1].decode("ascii", "replace") if len(status_line) > 1 else "unknown"
        raise Socks5Error("proxy_connect_failed_" + code)


def parse_proxy(value):
    """Parse a proxy URL or host:port[:user:pass] into connection parameters.

    Returns None for an empty value. Raises InputError for anything unusable, so
    a misconfigured proxy fails loudly instead of silently going direct.
    """
    if value is None:
        return None
    value = value.strip()
    if not value:
        return None
    scheme = "http"
    rest = value
    if "://" in value:
        scheme, rest = value.split("://", 1)
        scheme = scheme.lower()
    if scheme not in ("socks5", "socks5h", "http", "https"):
        raise InputError("invalid_proxy_scheme")
    # A bare "host:port:user:pass" form is accepted because that is how the
    # upstream provider hands out rotating residential endpoints.
    credentials = ""
    if "@" in rest:
        credentials, rest = rest.rsplit("@", 1)
    if ":" in rest and rest.count(":") > 1:
        parts = rest.split(":")
        if len(parts) >= 4:
            rest = parts[0] + ":" + parts[1]
            credentials = parts[2] + ":" + parts[3]
    if not rest or ":" not in rest:
        raise InputError("invalid_proxy_address")
    host, _, port_text = rest.rpartition(":")
    if not host:
        raise InputError("invalid_proxy_address")
    try:
        port = int(port_text)
    except ValueError:
        raise InputError("invalid_proxy_port") from None
    if not 0 < port <= 65535:
        raise InputError("invalid_proxy_port")
    username, password = "", ""
    if credentials:
        if ":" in credentials:
            username, _, password = credentials.partition(":")
        else:
            username = credentials
    return {"scheme": scheme, "host": host, "port": port,
            "username": username, "password": password, "raw": value}


class DirectConnection:
    """A plain TCP/HTTPS connection to crt.sh, i.e. the no-proxy path."""

    label = "direct"

    def __init__(self, deadline):
        self.deadline = deadline

    def open(self):
        return self._wrap(socket.create_connection(
            (UPSTREAM_HOST, UPSTREAM_PORT), timeout=min(20.0, max(0.1, self.deadline - time.monotonic()))))

    def _wrap(self, raw):
        context = ssl.create_default_context()
        tls = context.wrap_socket(raw, server_hostname=UPSTREAM_HOST)
        # The body deadline is enforced by read_bounded; per-read socket waits
        # are capped there too, so a slow stream cannot extend it.
        tls.settimeout(20.0)
        return tls


class ProxiedConnection:
    """A declared tunnel through an HTTP CONNECT or SOCKS5 proxy."""

    def __init__(self, spec, deadline):
        self.spec = spec
        self.deadline = deadline

    @property
    def label(self):
        return "%s://%s:%d" % (self.spec["scheme"], self.spec["host"], self.spec["port"])

    def open(self):
        remaining = min(20.0, max(0.1, self.deadline - time.monotonic()))
        raw = socket.create_connection((self.spec["host"], self.spec["port"]), timeout=remaining)
        try:
            if self.spec["scheme"] in ("socks5", "socks5h"):
                _socks5_handshake(raw, UPSTREAM_HOST, UPSTREAM_PORT,
                                  self.spec["username"], self.spec["password"], self.deadline)
            else:
                _http_connect_handshake(raw, UPSTREAM_HOST, UPSTREAM_PORT,
                                        self.spec["username"], self.spec["password"], self.deadline)
        except Exception:
            raw.close()
            raise
        context = ssl.create_default_context()
        tls = context.wrap_socket(raw, server_hostname=UPSTREAM_HOST)
        tls.settimeout(20.0)
        return tls


def build_connection(proxy, deadline):
    if proxy is None:
        return DirectConnection(deadline)
    return ProxiedConnection(proxy, deadline)


# --------------------------------------------------------------------------
# Upstream short-circuit state
# --------------------------------------------------------------------------

def default_state_path():
    """The breaker file lives per host, not per target or per task.

    crt.sh is one fixed upstream for every task, so its health is shared state.
    Anything wider (Redis, the main config) would be overkill; anything narrower
    would let concurrent tasks each pay the full retry budget again.
    """
    override = os.environ.get("CYBERSTRIKE_CRTSH_STATE", "").strip()
    if override:
        return override
    base = os.environ.get("XDG_CACHE_HOME", "").strip() or os.path.join(
        os.path.expanduser("~"), ".cache")
    return os.path.join(base, "cyberstrike", "crtsh-upstream.json")


def load_state(path):
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        return {}
    if not isinstance(data, dict):
        return {}
    return data


def save_state(path, state):
    """Best-effort persistence. A read-only home directory must not fail the tool."""
    directory = os.path.dirname(path) or "."
    try:
        os.makedirs(directory, exist_ok=True)
        handle = tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=directory,
                                             prefix=".crtsh-upstream-", delete=False)
        try:
            json.dump(state, handle)
            handle.flush()
            os.fsync(handle.fileno())
        finally:
            handle.close()
        os.replace(handle.name, path)
    except OSError:
        return


def health_verdict(state, window_seconds, trip_failures, now=None):
    """Decide whether the recorded upstream failures still block a new call.

    Returns (blocked, entry). Blocked is only true for failures that were
    classified as upstream health failures: 429/5xx and TLS problems. A timeout
    is deliberately NOT recorded, because a slow crt.sh for one large domain
    says nothing about the next domain.
    """
    if window_seconds <= 0 or trip_failures <= 0:
        return False, None
    entry = state.get("failure")
    if not isinstance(entry, dict):
        return False, None
    now = time.time() if now is None else now
    last = entry.get("last_failure_at")
    count = entry.get("consecutive_failures")
    if not isinstance(last, (int, float)) or not isinstance(count, int):
        return False, None
    if count < trip_failures:
        return False, None
    cooldown = window_seconds * BREAKER_COOLDOWN_FACTOR
    if now - last >= cooldown:
        return False, None
    retry_after_ms = max(0, int((last + cooldown - now) * 1000))
    return True, dict(entry, retry_after_ms=retry_after_ms)


def record_upstream_failure(state, path, reason, detail, now=None):
    now = time.time() if now is None else now
    previous = state.get("failure")
    count = 1
    if isinstance(previous, dict) and isinstance(previous.get("consecutive_failures"), int):
        count = previous["consecutive_failures"] + 1
    state["failure"] = {
        "consecutive_failures": count,
        "last_failure_at": now,
        "last_failure_at_iso": datetime.fromtimestamp(now, timezone.utc).isoformat(),
        "reason": reason,
        "detail": detail,
        "upstream": UPSTREAM,
    }
    save_state(path, state)


def clear_upstream_failure(state, path):
    if "failure" not in state:
        return
    state.pop("failure", None)
    save_state(path, state)


# --------------------------------------------------------------------------
# Upstream request
# --------------------------------------------------------------------------

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


def fetch_query(connection, query, max_bytes, retries, deadline):
    url = query_url(query)
    path = urllib.parse.urlsplit(url).path + "?" + urllib.parse.urlsplit(url).query
    meta = {"query": query, "url": url, "state": "error", "attempts": 0,
            "response_bytes": 0, "response_complete": False, "response_sha256": None,
            "response_sha256_scope": None, "retrieved_at": None}
    for attempt in range(retries + 1):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            meta["reason"] = "timeout"
            break
        headers, retry, http_status = None, False, None
        meta["attempts"] += 1
        try:
            sock = connection.open()
            try:
                response = http.client.HTTPSConnection.__new__(http.client.HTTPSConnection)
                response.__init__(UPSTREAM_HOST, UPSTREAM_PORT, timeout=min(20.0, remaining))
                response.sock = sock
                # _buffer stays the list HTTPSConnection.__init__ installed: the
                # request is accumulated there and flushed through sock.sendall
                # by endheaders(). Overwriting it with a file object breaks
                # putrequest, which appends to a list.
                response.putrequest("GET", path, skip_host=True, skip_accept_encoding=True)
                response.putheader("Host", UPSTREAM_HOST)
                response.putheader("Accept", "application/json")
                response.putheader("Accept-Encoding", "identity")
                response.putheader("User-Agent", USER_AGENT)
                response.putheader("Connection", "close")
                response.endheaders()
                result = response.getresponse()
                headers = result.headers
                http_status = result.status
                meta["http_status"] = result.status
                if result.status != 200:
                    result.read()
                    # The body is consumed so the socket is not left with unread
                    # data. A 3xx is terminal here because this tool never follows
                    # a redirect. 429/5xx are upstream health failures and retry;
                    # any other status is permanent for this query.
                    meta["reason"] = "http_" + str(result.status)
                    if 300 <= result.status < 400:
                        meta["reason"] = "redirect_not_allowed"
                        break
                    if not (result.status == 429 or 500 <= result.status <= 599) or attempt == retries:
                        break
                    delay = retry_delay(result.headers, attempt)
                    if delay >= deadline - time.monotonic():
                        meta["reason"] = "timeout"
                        break
                    time.sleep(delay)
                    continue
                content_type = result.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
                if content_type not in ("application/json", "text/json"):
                    raise QueryError("non_json_response")
                if result.headers.get("Content-Encoding", "identity").lower() not in ("", "identity"):
                    raise QueryError("unexpected_content_encoding")
                data = read_bounded(result, max_bytes, deadline)
                meta["response_bytes"] = len(data)
                meta["response_sha256"] = hashlib.sha256(data).hexdigest()
                meta["response_sha256_scope"] = "captured_prefix"
                meta["retrieved_at"] = datetime.now(timezone.utc).isoformat()
                declared_length = result.headers.get("Content-Length")
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
            finally:
                try:
                    sock.close()
                except OSError:
                    pass
        except QueryError as exc:
            meta["reason"] = str(exc)
            # A consumed/truncated/HTML response is not silently retried or
            # interpreted as an empty result. Only transport failures retry.
            break
        except Socks5Error as exc:
            meta["reason"] = str(exc)
            break
        except (urllib.error.URLError, OSError, http.client.HTTPException, ssl.SSLError) as exc:
            reason = getattr(exc, "reason", exc)
            meta["reason"] = "tls_error" if isinstance(reason, ssl.SSLError) else (
                "timeout" if isinstance(reason, (TimeoutError, socket.timeout)) else "network_error")
            retry = meta["reason"] != "tls_error"
        if http_status is not None and (http_status == 429 or 500 <= http_status <= 599):
            meta["reason"] = "http_" + str(http_status)
            retry = True
        if not retry or attempt == retries:
            break
        delay = retry_delay(headers, attempt)
        if delay >= deadline - time.monotonic():
            meta["reason"] = "timeout"
            break
        time.sleep(delay)
    return None, meta


def upstream_failure_class(meta):
    """Classify a finished query for the short-circuit, or None if it is not one.

    Only upstream health signals count. A malformed body, a rejected limit or a
    single slow response must never trip the breaker, or one hostile domain
    could disable crt.sh coverage for every later task in the window.
    """
    status = meta.get("http_status")
    if isinstance(status, int) and (status == 429 or 500 <= status <= 599):
        return "crtsh_http_%d" % status, "HTTP %d from %s" % (status, meta.get("url", UPSTREAM))
    reason = str(meta.get("reason") or "")
    if reason == "tls_error":
        return "crtsh_tls_error", "TLS failure contacting %s" % UPSTREAM
    return None, ""


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


def blocked_envelope(domain, entry, verdict_reason):
    """A short-circuited call: a durable blocked/gap fact plus the prior raw error.

    partial stays true, so the caller keeps every downstream guard that already
    applies to an incomplete crt.sh answer: no covered row, no zero-result claim,
    and the gap must still be reported.
    """
    result = envelope(domain)
    result["status"] = "blocked"
    result["partial"] = True
    result["truncated"] = False
    result["short_circuit"] = True
    result["reasons"] = [verdict_reason]
    result["upstream_health"] = {
        "decision": "blocked",
        "policy": "recorded upstream failure inside the health window; no request attempted",
        "consecutive_failures": entry.get("consecutive_failures"),
        "last_failure_at": entry.get("last_failure_at_iso"),
        "reason": entry.get("reason"),
        "retry_after_ms": entry.get("retry_after_ms"),
        "last_error": entry.get("detail"),
        "state_path": None,
    }
    result["queries"] = [
        {"query": domain, "url": query_url(domain), "state": "not_attempted",
         "reason": verdict_reason, "attempts": 0},
        {"query": "%." + domain, "url": query_url("%." + domain), "state": "not_attempted",
         "reason": verdict_reason, "attempts": 0},
    ]
    result["retrieved_at"] = entry.get("last_failure_at_iso")
    return result


def collect(domain, timeout_seconds=60, max_retries=2, max_response_bytes=8 * 1024 * 1024,
            max_records=10000, proxy=None, connection_label=None,
            state_path=None, health_window_seconds=DEFAULT_HEALTH_WINDOW_SECONDS,
            health_trip_failures=DEFAULT_HEALTH_TRIP_FAILURES):
    domain = normalize_domain(domain)
    for value, minimum, maximum in ((timeout_seconds, 1, 180), (max_retries, 0, 3),
                                     (max_response_bytes, 1024, 32 * 1024 * 1024), (max_records, 1, 50000),
                                     (health_window_seconds, 0, MAX_HEALTH_WINDOW_SECONDS),
                                     (health_trip_failures, 0, MAX_HEALTH_TRIP_FAILURES)):
        if type(value) is not int or not minimum <= value <= maximum:
            raise InputError("invalid_limit")
    state_path = state_path or default_state_path()
    state = load_state(state_path)

    blocked, entry = health_verdict(state, health_window_seconds, health_trip_failures)
    if blocked:
        result = blocked_envelope(domain, entry, "crtsh_upstream_unhealthy")
        result["upstream_health"]["state_path"] = state_path
        result["limits"] = {"timeout_seconds": timeout_seconds, "max_retries": max_retries,
                            "max_response_bytes": max_response_bytes, "max_records": max_records,
                            "max_certificates": MAX_CERTIFICATES, "max_names": MAX_NAMES,
                            "max_certificates_per_host": MAX_CERTIFICATES_PER_HOST,
                            "max_output_bytes": MAX_OUTPUT_BYTES,
                            "health_window_seconds": health_window_seconds,
                            "health_trip_failures": health_trip_failures}
        result["counts"] = {"certificates_received": 0, "certificates_processed": 0,
                            "invalid_certificates": 0, "names_seen": 0, "rejected_names": 0,
                            "out_of_domain_names": 0, "duplicate_names": 0,
                            "certificate_references": 0, "unique_hosts": 0}
        return result

    result = envelope(domain)
    result["limits"] = {"timeout_seconds": timeout_seconds, "max_retries": max_retries,
                        "max_response_bytes": max_response_bytes, "max_records": max_records,
                        "max_certificates": MAX_CERTIFICATES, "max_names": MAX_NAMES,
                        "max_certificates_per_host": MAX_CERTIFICATES_PER_HOST,
                        "max_output_bytes": MAX_OUTPUT_BYTES,
                        "health_window_seconds": health_window_seconds,
                        "health_trip_failures": health_trip_failures}
    counts = {"certificates_received": 0, "certificates_processed": 0, "invalid_certificates": 0,
              "names_seen": 0, "rejected_names": 0, "out_of_domain_names": 0,
              "duplicate_names": 0, "certificate_references": 0, "unique_hosts": 0}
    result["counts"] = counts
    hosts, references = {}, {}
    remaining, output_size = max_response_bytes, 0
    deadline, now = time.monotonic() + timeout_seconds, datetime.now(timezone.utc)
    # Ambient proxies are never honoured: the egress is direct unless the caller
    # named one. Input cannot select another upstream or contact a candidate host.
    connection = build_connection(proxy, deadline)
    result["egress"] = {"mode": "proxy" if proxy else "direct",
                        "endpoint": connection_label or connection.label,
                        "upstream": UPSTREAM}
    stopped, upstream_failure = False, None

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
        rows, meta = fetch_query(connection, query, remaining, max_retries, deadline)
        result["queries"].append(meta)
        remaining -= meta["response_bytes"]
        if rows is None:
            gap(meta["reason"], meta["reason"] in ("response_limit", "incomplete_response"))
            if upstream_failure is None:
                upstream_failure = upstream_failure_class(meta)
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

    # Persist or clear the upstream health verdict for the next call. A single
    # successful query is enough to declare the upstream usable again, including
    # when the answer itself was partial because of a local budget limit.
    health = {"decision": "pass", "window_seconds": health_window_seconds,
              "trip_failures": health_trip_failures, "state_path": state_path,
              "consecutive_failures": 0, "last_failure_at": None, "reason": None,
              "retry_after_ms": 0, "last_error": None}
    if succeeded:
        clear_upstream_failure(state, state_path)
    elif upstream_failure is not None and upstream_failure[0]:
        reason, detail = upstream_failure
        record_upstream_failure(state, state_path, reason, detail)
        saved = load_state(state_path).get("failure") or {}
        health.update({"decision": "recorded", "reason": reason, "last_error": detail,
                       "consecutive_failures": saved.get("consecutive_failures"),
                       "last_failure_at": saved.get("last_failure_at_iso")})
        if isinstance(saved.get("consecutive_failures"), int) and saved["consecutive_failures"] >= health_trip_failures:
            health["decision"] = "tripped"
            health["note"] = ("next crtsh_search call inside %ds will short-circuit until %s"
                              % (health_window_seconds, saved.get("last_failure_at_iso")))
    result["upstream_health"] = health

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
    parser.add_argument("--proxy", default="",
                        help="显式出口代理，如 socks5://user:pass@host:port；留空为直连，环境代理始终忽略")
    parser.add_argument("--health-window-seconds", type=bounded_int(0, MAX_HEALTH_WINDOW_SECONDS),
                        default=DEFAULT_HEALTH_WINDOW_SECONDS)
    parser.add_argument("--health-trip-failures", type=bounded_int(0, MAX_HEALTH_TRIP_FAILURES),
                        default=DEFAULT_HEALTH_TRIP_FAILURES)
    return parser


def main(argv=None):
    result = None
    try:
        args = make_parser().parse_args(argv)
        proxy = os.environ.get("CYBERSTRIKE_CRTSH_PROXY", "") if not args.proxy else args.proxy
        spec = parse_proxy(proxy)
        result = collect(domain=args.domain, timeout_seconds=args.timeout_seconds,
                         max_retries=args.max_retries, max_response_bytes=args.max_response_bytes,
                         max_records=args.max_records, proxy=spec,
                         connection_label=None if spec is None else spec["raw"],
                         state_path=default_state_path(),
                         health_window_seconds=args.health_window_seconds,
                         health_trip_failures=args.health_trip_failures)
    except (InputError, SystemExit) as exc:
        # Bad arguments are an input fact, not a crash: emit the same envelope
        # contract every other rejection uses and exit 2 so the caller can tell
        # "you asked for something invalid" from "the query failed".
        # argparse also exits 0 for --help/--version; that is a request the
        # caller made on purpose, so it keeps its own exit code and output.
        if isinstance(exc, SystemExit) and exc.code == 0:
            raise
        reason = "invalid_arguments" if isinstance(exc, SystemExit) else str(exc)
        result = envelope()
        result["reasons"] = [reason or "invalid_arguments"]
        print(json_bytes(result).decode("ascii"))
        return 2
    if result.get("short_circuit"):
        # A short-circuited call is a blocked fact, not a successful empty result:
        # exit non-zero so the platform keeps the gap instead of covered/zero.
        print(json_bytes(result).decode("ascii"))
        return 1
    print(json_bytes(result).decode("ascii"))
    return 1 if result["status"] == "error" else 0


if __name__ == "__main__":
    sys.exit(main())
