#!/usr/bin/env python3
"""Shared, network-free candidate normalization and bounded streaming helpers."""

import csv
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import tempfile
import time
from urllib.parse import parse_qsl, quote, unquote, urljoin, urlsplit, urlunsplit

SCHEMA_VERSION = 2
ROUTING_PARAMETERS = frozenset((
    "action", "method", "operation", "p_p_resource_id", "p_p_id", "do", "route",
    "controller", "resource",
))
MAX_URL_CHARS = 8192
MAX_CSV_FIELD_CHARS = 1024 * 1024
MAX_CSV_LINE_CHARS = 4 * 1024 * 1024
MAX_CSV_RECORD_CHARS = 8 * 1024 * 1024
MAX_CSV_COLUMNS = 256
CHUNK_BYTES = 64 * 1024
SENSITIVE_NAME = re.compile(r"(?:token|secret|password|passwd|authorization|cookie|session|email|phone|mobile|credential|api.?key)", re.I)
EMAIL = re.compile(r"[\w.+%-]+@[\w.-]+\.[A-Za-z]{2,}")
UUID = re.compile(r"^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$", re.I)
OPAQUE = re.compile(r"^(?:[0-9a-f]{16,}|[A-Za-z0-9_+=-]{32,})$", re.I)
TEMPLATE = re.compile(r"\$\{[^}]*\}|\{[^}]*\}")


class InputError(ValueError):
    """A controlled diagnostic. Messages must never contain the rejected input."""

    def __init__(self, code, field=None):
        self.code = code
        self.field = field
        super().__init__(code + (":" + field if field else ""))


class BudgetExceeded(RuntimeError):
    pass


def emit_json(value):
    """A closed outer stdout must not prevent private manifest finalization."""
    try:
        print(json.dumps(value, ensure_ascii=True), flush=True)
    except (OSError, UnicodeError):
        pass


def atomic_json(path, value):
    path = Path(path)
    temporary = path.with_name(path.name + ".tmp")
    try:
        with temporary.open("w", encoding="utf-8") as stream:
            os.chmod(temporary, 0o600)
            json.dump(value, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


@contextmanager
def open_regular(path, mode="rb", root=None, **kwargs):
    """Reject links/FIFOs, including parent-component link races inside an untrusted run."""
    path = Path(path)
    fd, directories = None, []
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        if root is not None and os.open in os.supports_dir_fd:
            relative = path.relative_to(root)
            if not relative.parts or any(part in (".", "..") for part in relative.parts):
                raise InputError("artifact_path_outside_run")
            directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
            directory = os.open(root, directory_flags)
            directories.append(directory)
            for component in relative.parts[:-1]:
                directory = os.open(component, directory_flags, dir_fd=directory)
                directories.append(directory)
            fd = os.open(relative.name, flags, dir_fd=directory)
        else:
            if path.is_symlink() or (root is not None and not path.resolve().is_relative_to(Path(root).resolve())):
                raise InputError("symlink_or_outside_artifact_rejected")
            fd = os.open(path, flags)
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise InputError("regular_file_required")
        stream = os.fdopen(fd, mode, **kwargs)
        fd = None  # The stream now owns it.
        with stream:
            yield stream
    finally:
        if fd is not None:
            os.close(fd)
        for directory in reversed(directories):
            os.close(directory)


def stream_sha256(path, check=lambda: None, root=None):
    digest = hashlib.sha256()
    with open_regular(path, root=root) as stream:
        while True:
            check()
            chunk = stream.read(CHUNK_BYTES)
            if not chunk:
                return digest.hexdigest()
            digest.update(chunk)


def file_paths(root):
    """Walk without following symlink files or directories; no whole-tree list."""
    root = Path(root).resolve()
    def traversal_failed(error):
        raise error
    for directory, dirs, files in os.walk(root, followlinks=False, onerror=traversal_failed):
        dirs[:] = sorted(name for name in dirs if not (Path(directory) / name).is_symlink())
        for name in sorted(files):
            path = Path(directory) / name
            if not path.is_symlink() and path.is_file() and path.resolve().is_relative_to(root):
                yield path


def check_budget(deadline=None, tick=None, cancelled=None):
    if tick:
        tick()
    if cancelled and cancelled():
        raise BudgetExceeded("cancelled")
    if deadline is not None and time.monotonic() >= deadline:
        raise BudgetExceeded("export_timeout")


def template_path(path):
    """Keep static routes/extensions, replace likely identifiers and PII."""
    parts = []
    for segment in (path or "/").split("/"):
        decoded = unquote(segment)
        decoded = TEMPLATE.sub("{value}", decoded)
        stem, dot, extension = decoded.rpartition(".")
        identifier = stem if dot and re.fullmatch(r"[A-Za-z]{1,8}", extension) else decoded
        if EMAIL.search(decoded) or "@" in decoded or any(ord(c) < 32 for c in decoded):
            decoded = "{redacted}"
        elif UUID.fullmatch(identifier) or identifier.isdecimal() or OPAQUE.fullmatch(identifier):
            decoded = "{id}" + ("." + extension if identifier == stem else "")
        elif SENSITIVE_NAME.match(decoded) and ("=" in decoded or ":" in decoded):
            decoded = "{redacted}"
        parts.append(quote(decoded, safe="{}:@!$&'()*+,;=-._~"))
    return "/".join(parts)


def route_value(value):
    # parse_qsl already decoded once. Keep routing values distinct, including
    # encoded slashes and numeric portlet/resource IDs; never double-decode.
    decoded = value
    if len(decoded) > 256 or EMAIL.search(decoded) or any(ord(c) < 32 for c in decoded):
        return "{redacted}"
    if SENSITIVE_NAME.search(decoded) and ("=" in decoded or ":" in decoded):
        return "{redacted}"
    return TEMPLATE.sub("{value}", decoded)


def classify_resource(path, parameter_names=()):
    suffix = Path(urlsplit(path).path).suffix.lower()
    if suffix in (".js", ".mjs", ".cjs"):
        return "javascript"
    if suffix == ".map":
        return "source_map"
    if suffix in (".pdf", ".zip", ".gz", ".tar", ".7z", ".rar", ".doc", ".docx", ".xls", ".xlsx", ".csv", ".txt", ".jsonl", ".ndjson", ".sql", ".bak", ".bin", ".exe", ".apk") or re.search(r"(?:^|/)(?:download|export|attachment|attachments)(?:/|$)", path, re.I):
        return "download"
    if any(name.lower() in ("download", "attachment", "filename") for name in parameter_names):
        return "download"
    if suffix in (".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico", ".css", ".woff", ".woff2", ".ttf", ".mp4", ".mp3"):
        return "static_resource"
    return "endpoint"


def query_parts(query):
    pairs = parse_qsl(query, keep_blank_values=True, max_num_fields=256)
    names = sorted(set(name for name, _ in pairs))
    routing = [{"name": name, "value": route_value(item)} for name, item in pairs if name.lower() in ROUTING_PARAMETERS]
    safe_pairs = sorted((name, route_value(item) if name.lower() in ROUTING_PARAMETERS else "{value}") for name, item in pairs)
    normalized = "&".join(quote(name, safe="[]_.-") + "=" + quote(item, safe="{}/:_.-") for name, item in safe_pairs)
    return names, routing, normalized


def normalize_candidate(value, method="UNKNOWN", source=None, base_url=None):
    if not isinstance(value, str) or not value or len(value) > MAX_URL_CHARS:
        raise InputError("invalid_url_type_or_length")
    if any(ord(c) < 32 or c.isspace() for c in value):
        raise InputError("url_contains_controls_or_whitespace")
    # Resolve only when the caller explicitly supplies a base; never request it.
    uncertainty = []
    if base_url:
        value = urljoin(base_url, value)
    parsed = urlsplit(value)
    if parsed.scheme and parsed.scheme.lower() not in ("http", "https", "ws", "wss"):
        raise InputError("unsupported_url_scheme")
    if parsed.username is not None or parsed.password is not None:
        raise InputError("embedded_credentials_rejected")
    try:
        port = parsed.port
    except ValueError as exc:
        raise InputError("invalid_url_port") from exc
    if port is not None and not 1 <= port <= 65535:
        raise InputError("invalid_url_port")
    scheme = parsed.scheme.lower()
    host = (parsed.hostname or "").lower().rstrip(".")
    if (scheme or parsed.netloc) and not host:
        raise InputError("missing_url_host")
    if not host:
        uncertainty.append("relative_base_unresolved")
    elif not scheme:
        uncertainty.append("protocol_relative_scheme_unresolved")
    if "${" in value or "{" in parsed.path:
        uncertainty.append("template_expression_not_evaluated")
    if not isinstance(method, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,31}", method):
        raise InputError("invalid_method")
    path = template_path(parsed.path) if parsed.path or host else ""
    names, routing, query = query_parts(parsed.query)
    fragment, fragment_route = "", None
    if parsed.fragment.startswith(("/", "!/")):
        fragment_url = urlsplit(parsed.fragment.removeprefix("!"))
        fragment_names, fragment_routing, fragment_query = query_parts(fragment_url.query)
        fragment_path = template_path(fragment_url.path)
        fragment = ("!" if parsed.fragment.startswith("!") else "") + fragment_path + ("?" + fragment_query if fragment_query else "")
        fragment_route = {"path_template": fragment_path, "parameter_names": fragment_names, "routing_parameters": fragment_routing}
        names = sorted(set(names) | set(fragment_names))
        uncertainty.append("fragment_route_not_server_endpoint")
    netloc = "[" + host + "]" if ":" in host else host
    if port is not None:
        netloc += ":" + str(port)
    normalized = urlunsplit((scheme, netloc, path, query, fragment))
    resource_type = "websocket" if scheme in ("ws", "wss") else classify_resource(path, names)
    if resource_type == "endpoint" and any(re.search(r"(?:^|[/_.-])(?:download|export|attachment)(?:$|[/_.-])", item["value"], re.I) for item in routing):
        resource_type = "download"
    return {
        "schema_version": SCHEMA_VERSION, "url": normalized, "scheme": scheme or None,
        "host": host or None, "port": port, "path_template": path,
        "parameter_names": names,
        "routing_parameters": routing, "fragment_route": fragment_route,
        "method": method.upper(), "resource_type": resource_type,
        "source": source, "candidate_only": True, "coverage": "unverified_candidate",
        "uncertainty": uncertainty,
    }


class BoundedCSVLines:
    def __init__(self, stream, check):
        self.stream, self.check = stream, check
        self.record_chars = 0

    def reset_record(self):
        self.record_chars = 0

    def __iter__(self):
        return self

    def __next__(self):
        self.check()
        line = self.stream.readline(MAX_CSV_LINE_CHARS + 1)
        if not line:
            raise StopIteration
        if len(line) > MAX_CSV_LINE_CHARS:
            raise InputError("csv_line_limit")
        self.record_chars += len(line)
        if self.record_chars > MAX_CSV_RECORD_CHARS:
            raise InputError("csv_record_limit")
        return line


def csv_rows(path, check=lambda: None, root=None):
    """Streaming CSV; strict decoding/field/line limits never imply completeness."""
    old_limit = csv.field_size_limit(MAX_CSV_FIELD_CHARS)
    try:
        with open_regular(path, "r", root=root, encoding="utf-8-sig", errors="strict", newline="") as stream:
            lines = BoundedCSVLines(stream, check)
            reader = csv.reader(lines, strict=True)
            header = next(reader, [])
            if len(header) > MAX_CSV_COLUMNS:
                raise InputError("csv_column_limit")
            names = [name.strip().lower() for name in header]
            if "url" not in names or "method" not in names or len(set(names)) != len(names):
                raise InputError("csv_missing_or_duplicate_columns")
            while True:
                lines.reset_record()
                try:
                    row = next(reader)
                except StopIteration:
                    break
                # Reject malformed shapes instead of silently dropping extra fields.
                if len(row) != len(names):
                    yield None, reader.line_num
                else:
                    yield dict(zip(names, row)), reader.line_num
    finally:
        csv.field_size_limit(old_limit)


class CandidateWriter:
    """Disk-backed deduplication; memory use is independent of candidate count."""

    def __init__(self, path, queues=False, provenance=False):
        self.path = Path(path)
        self.counts = {"raw": 0, "unique": 0, "exported": 0, "skipped": 0, "parse_errors": 0, "duplicates": 0}
        self.preview, self.queues = [], {}
        self.provenance = provenance
        self.stream, self.db, self.index_path = None, None, None
        try:
            self.stream = self._output(self.path)
            temporary = tempfile.NamedTemporaryFile(prefix="candidate-index-", suffix=".sqlite", dir=self.path.parent, delete=False)
            self.index_path = Path(temporary.name)
            temporary.close()
            self.db = sqlite3.connect(self.index_path)
            self.db.execute("PRAGMA journal_mode=OFF")
            self.db.execute("PRAGMA synchronous=OFF")
            self.db.execute("CREATE TABLE candidates (signature TEXT PRIMARY KEY)")
            if queues:
                for kind, name in (("javascript", "js_queue.ndjson"), ("source_map", "map_queue.ndjson"), ("download", "download_queue.ndjson")):
                    self.queues[kind] = self._output(self.path.parent / name)
        except BaseException:
            try:
                self.close()
            except Exception:
                pass
            raise

    @staticmethod
    def _output(path):
        # Exclusive creation rejects existing files and even dangling symlinks.
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
        return os.fdopen(fd, "w", encoding="utf-8", buffering=1)

    def write(self, candidate):
        key = [candidate["method"], candidate["url"]]
        if self.provenance:
            key.append(candidate.get("source"))
        signature = hashlib.sha256(json.dumps(key, sort_keys=True).encode()).hexdigest()
        try:
            self.db.execute("INSERT INTO candidates VALUES (?)", (signature,))
        except sqlite3.IntegrityError:
            self.counts["skipped"] += 1
            self.counts["duplicates"] += 1
            return False
        self.counts["unique"] += 1
        candidate["candidate_id"] = signature
        line = json.dumps(candidate, ensure_ascii=False) + "\n"
        self.stream.write(line)
        self.counts["exported"] += 1
        if len(self.preview) < 50:
            self.preview.append(candidate)
        if candidate["resource_type"] in self.queues:
            self.queues[candidate["resource_type"]].write(line)
        if self.counts["exported"] % 1000 == 0:
            self.db.commit()
        return True

    def close(self):
        error = None
        for stream in [self.stream] + list(self.queues.values()):
            if stream is not None and not stream.closed:
                try:
                    stream.flush()
                    os.fsync(stream.fileno())
                except Exception as exc:
                    error = error or exc
                finally:
                    try:
                        stream.close()
                    except Exception as exc:
                        error = error or exc
        try:
            if self.db is not None:
                self.db.close()
                self.db = None
        finally:
            if self.index_path is not None:
                self.index_path.unlink(missing_ok=True)
        if error:
            raise error

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        self.close()
