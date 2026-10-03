#!/usr/bin/env python3
"""Extract unverified JS/source-map references offline, without executing JS or HTTP."""

import json
from pathlib import Path
import re
import time

try:
    from .candidate_inventory import (BudgetExceeded, CandidateWriter, InputError, SCHEMA_VERSION,
                                     atomic_json, check_budget, file_paths, normalize_candidate,
                                     stream_sha256, template_path)
    from .url_inventory import OfflineParser, input_file, output_directory, positive_seconds
except ImportError:
    from candidate_inventory import (BudgetExceeded, CandidateWriter, InputError, SCHEMA_VERSION,
                                     atomic_json, check_budget, file_paths, normalize_candidate,
                                     stream_sha256, template_path)
    from url_inventory import OfflineParser, input_file, output_directory, positive_seconds

CHUNK_CHARS = 8192
WINDOW_CHARS = 16384
OVERLAP_CHARS = 4096
SOURCE_EXTENSIONS = {".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".map"}
LITERAL = r"(?P<quote>['\"`])(?P<value>(?:\\.|[^'\"`\\\r\n]){1,2048})(?P=quote)"
PATTERNS = (
    ("base_url", re.compile(r"\bbaseURL\s*[:=]\s*" + LITERAL)),
    ("client_call", re.compile(r"(?<![\w$])(?P<callee>[A-Za-z_$][\w.$]*)\.(?P<method>get|post|put|patch|delete|head|options)\s*\(\s*" + LITERAL, re.I)),
    ("concatenated_client_call", re.compile(r"(?<![\w$])(?P<callee>[A-Za-z_$][\w.$]*)\.(?P<method>get|post|put|patch|delete|head|options)\s*\(\s*(?P<base>[A-Za-z_$][\w.$]*)\s*\+\s*" + LITERAL, re.I)),
    ("browser_call", re.compile(r"\b(?P<callee>fetch|WebSocket|EventSource|importScripts|import|Worker|SharedWorker)\s*\(\s*" + LITERAL)),
    ("concatenated_browser_call", re.compile(r"\b(?P<callee>fetch|WebSocket|EventSource|importScripts|import|Worker|SharedWorker)\s*\(\s*(?P<base>[A-Za-z_$][\w.$]*)\s*\+\s*" + LITERAL)),
    ("xhr_call", re.compile(r"(?<![\w$])(?P<callee>[A-Za-z_$][\w.$]*\.open)\s*\(\s*['\"](?P<method>GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)['\"]\s*,\s*" + LITERAL, re.I)),
    ("concatenated_xhr_call", re.compile(r"(?<![\w$])(?P<callee>[A-Za-z_$][\w.$]*\.open)\s*\(\s*['\"](?P<method>GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)['\"]\s*,\s*(?P<base>[A-Za-z_$][\w.$]*)\s*\+\s*" + LITERAL, re.I)),
    ("request_config", re.compile(r"\burl\s*:\s*" + LITERAL)),
)
STRING = re.compile(LITERAL)
MAP_REFERENCE = re.compile(r"[#@]\s*sourceMappingURL\s*=\s*(?P<value>[^\s*]{1,2048})")
METHOD = re.compile(r"\bmethod\s*:\s*['\"](GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)['\"]", re.I)
PARAMETERS = re.compile(r"\b(?:params|data|body)\s*:\s*\{([^}]{0,512})\}")
PARAMETER_KEY = re.compile(r"(?:^|,)\s*['\"]?([A-Za-z_$][\w$.-]*)['\"]?\s*:")
PRIVATE_PROPERTY = re.compile(r"(?:['\"])?[\w$.-]*(?:token|secret|password|passwd|authorization|cookie|email|phone|mobile|api.?key|username|full.?name)[\w$.-]*(?:['\"])?\s*[:=]\s*$", re.I)
PRIVATE_CONTEXT = re.compile(r"(?:\bheaders['\"]?\s*:\s*[^}]{0,256}|\b(?:setRequestHeader|Headers)\s*\([^)]{0,256})$", re.I)


def literal_value(value):
    # Decode only safe string escapes. Never eval JS or infer variable values.
    return re.sub(r"\\(?:/|x([0-9a-fA-F]{2})|u([0-9a-fA-F]{4}))",
                  lambda match: "/" if match.group(0) == r"\/" else chr(int(match.group(1) or match.group(2), 16)), value)


class StaticScanner:
    """Bounded overlapping windows. Context is structural, never a raw secret-bearing snippet."""

    def __init__(self, writer, source, check, base_url=None):
        self.writer, self.source, self.check, self.base_url = writer, source, check, base_url
        self.buffer, self.line, self.column = "", 1, 1
        self.base_candidates = []
        self.gaps = []

    def feed(self, text, final=False):
        self.buffer += text
        if not final and len(self.buffer) < WINDOW_CHARS:
            return
        self.check()
        cutoff = len(self.buffer) if final else len(self.buffer) - OVERLAP_CHARS
        events, used = [], []
        for kind, pattern in PATTERNS:
            for match in pattern.finditer(self.buffer):
                if match.start() < cutoff:
                    events.append((match.start(), kind, match))
                    used.append(match.span("value"))
        for match in STRING.finditer(self.buffer):
            if match.start() >= cutoff or any(start <= match.start("value") < end for start, end in used):
                continue
            value = literal_value(match.group("value"))
            if value.startswith(("http://", "https://", "ws://", "wss://", "/", "./", "../", "?")) or ("/" in value and not any(char.isspace() for char in value)):
                prefix = self.buffer[max(0, match.start() - 256):match.start()]
                private = PRIVATE_PROPERTY.search(prefix) or PRIVATE_CONTEXT.search(prefix)
                events.append((match.start(), "private_literal_omitted" if private else "string_reference", match))
        for match in MAP_REFERENCE.finditer(self.buffer):
            if match.start() < cutoff:
                events.append((match.start(), "source_map_reference", match))
        for offset, kind, match in sorted(events, key=lambda event: event[0]):
            self.check()
            self.writer.counts["raw"] += 1
            if kind == "private_literal_omitted":
                self.writer.counts["skipped"] += 1
                continue
            value = literal_value(match.group("value"))
            if value.startswith("data:"):
                self.writer.counts["skipped"] += 1
                self.gaps.append("inline_source_map_not_decoded")
                continue
            groups = match.groupdict()
            method, uncertainty = "UNKNOWN", ["static_reference_not_executed"]
            callee = groups.get("callee")
            # Bound options to the immediately following call/config context.
            tail = self.buffer[match.end():match.end() + 512].split(")", 1)[0]
            if groups.get("method"):
                method = groups["method"].upper()
                if "client_call" in kind and callee != "axios":
                    uncertainty.append("client_object_binding_unverified")
            elif callee in ("fetch", "EventSource"):
                method_match = METHOD.search(tail) if tail.lstrip().startswith(",") else None
                method = method_match.group(1).upper() if method_match else "GET"
                uncertainty.append("method_static_options" if method_match else "default_method_unverified")
            elif callee == "WebSocket":
                method = "CONNECT"
            elif kind == "request_config":
                method_match = METHOD.search(tail)
                if method_match:
                    method = method_match.group(1).upper()
                uncertainty.append("request_config_binding_unverified")
            before = self.buffer[:offset]
            line = self.line + before.count("\n")
            column = len(before.rsplit("\n", 1)[-1]) + 1 if "\n" in before else self.column + offset
            source = {**self.source, "line": line, "column": column}
            try:
                candidate = normalize_candidate(value, method, source, self.base_url)
            except ValueError:
                self.writer.counts["skipped"] += 1
                self.writer.counts["parse_errors"] += 1
                continue
            if kind == "base_url":
                if candidate["url"] not in self.base_candidates and len(self.base_candidates) < 20:
                    self.base_candidates.append(candidate["url"])
            candidate["kind"] = kind
            candidate["context"] = {"callee": callee, "argument_kind": "template" if "${" in value else "literal",
                                    "dynamic_prefix": groups.get("base"),
                                    "options_inspected_chars": min(len(tail), 512), "raw_context_omitted": True}
            if groups.get("base"):
                uncertainty.append("concatenation_not_evaluated")
            candidate["base_url_candidates"] = list(self.base_candidates)
            if not candidate["host"]:
                uncertainty.append("base_url_binding_unresolved")
            for match_params in PARAMETERS.finditer(tail):
                candidate["parameter_names"] = sorted(set(candidate["parameter_names"]) | set(PARAMETER_KEY.findall(match_params.group(1))))
            candidate["uncertainty"].extend(uncertainty)
            self.writer.write(candidate)
        consumed = self.buffer[:cutoff]
        if "\n" in consumed:
            self.line += consumed.count("\n")
            self.column = len(consumed.rsplit("\n", 1)[-1]) + 1
        else:
            self.column += len(consumed)
        self.buffer = self.buffer[cutoff:]


class JSONStream:
    """Small streaming JSON reader for source maps, including very large string fields."""

    def __init__(self, stream, check):
        self.stream, self.check = stream, check
        self.buffer, self.position = "", 0

    def peek(self):
        if self.position >= len(self.buffer):
            self.check()
            self.buffer, self.position = self.stream.read(CHUNK_CHARS), 0
        return self.buffer[self.position:self.position + 1]

    def pop(self):
        char = self.peek()
        if not char:
            raise InputError("truncated_source_map")
        self.position += 1
        return char

    def space(self):
        while self.peek() and self.peek().isspace():
            self.pop()

    def expect(self, char):
        self.space()
        if self.pop() != char:
            raise InputError("invalid_source_map_json")

    def string_chunks(self):
        self.expect('"')
        chunk = []
        while True:
            char = self.pop()
            if char == '"':
                if chunk:
                    yield "".join(chunk)
                return
            if ord(char) < 32:
                raise InputError("invalid_source_map_string")
            if char == "\\":
                escape = self.pop()
                translations = {'"': '"', "\\": "\\", "/": "/", "b": "\b", "f": "\f", "n": "\n", "r": "\r", "t": "\t"}
                if escape == "u":
                    digits = "".join(self.pop() for _ in range(4))
                    if not re.fullmatch(r"[0-9a-fA-F]{4}", digits):
                        raise InputError("invalid_source_map_unicode_escape")
                    code = int(digits, 16)
                    if 0xD800 <= code <= 0xDBFF:
                        if self.pop() != "\\" or self.pop() != "u":
                            raise InputError("invalid_source_map_surrogate")
                        lower = "".join(self.pop() for _ in range(4))
                        if not re.fullmatch(r"[0-9a-fA-F]{4}", lower) or not 0xDC00 <= int(lower, 16) <= 0xDFFF:
                            raise InputError("invalid_source_map_surrogate")
                        code = 0x10000 + ((code - 0xD800) << 10) + int(lower, 16) - 0xDC00
                    elif 0xDC00 <= code <= 0xDFFF:
                        raise InputError("invalid_source_map_surrogate")
                    char = chr(code)
                elif escape in translations:
                    char = translations[escape]
                else:
                    raise InputError("invalid_source_map_escape")
            chunk.append(char)
            if len(chunk) >= CHUNK_CHARS:
                yield "".join(chunk)
                chunk = []

    def string(self, limit=8192):
        chunks, size = [], 0
        for chunk in self.string_chunks():
            size += len(chunk)
            if size > limit:
                raise InputError("source_map_metadata_limit")
            chunks.append(chunk)
        return "".join(chunks)

    def primitive(self):
        self.space()
        chars = []
        while self.peek() and self.peek() not in ",]} \t\r\n":
            chars.append(self.pop())
            if len(chars) > 64:
                raise InputError("source_map_scalar_limit")
        try:
            value = json.loads("".join(chars))
        except ValueError as exc:
            raise InputError("invalid_source_map_scalar") from exc
        if isinstance(value, (dict, list, str)):
            raise InputError("invalid_source_map_scalar")
        return value

    def skip(self, depth=0):
        if depth > 32:
            raise InputError("source_map_depth_limit")
        self.space()
        char = self.peek()
        if char == '"':
            for _chunk in self.string_chunks():
                pass
        elif char in ("{", "["):
            closing = "}" if self.pop() == "{" else "]"
            self.space()
            if self.peek() == closing:
                self.pop()
                return
            while True:
                if closing == "}":
                    self.string()
                    self.expect(":")
                self.skip(depth + 1)
                self.space()
                if self.peek() == closing:
                    self.pop()
                    return
                self.expect(",")
        else:
            self.primitive()


def scan_source_map(path, writer, source, check, base_url, status):
    names, source_root = [], ""
    embedded, content_count, version = False, 0, None
    with path.open(encoding="utf-8-sig", errors="strict") as stream:
        reader = JSONStream(stream, check)
        reader.expect("{")
        reader.space()
        if reader.peek() != "}":
            while True:
                key = reader.string()
                reader.expect(":")
                reader.space()
                if key == "sources":
                    reader.expect("[")
                    reader.space()
                    if reader.peek() != "]":
                        while True:
                            names.append(template_path(reader.string().split("?", 1)[0].split("#", 1)[0]))
                            if len(names) > 10000:
                                raise InputError("source_map_sources_limit")
                            reader.space()
                            if reader.peek() == "]":
                                break
                            reader.expect(",")
                    reader.expect("]")
                elif key == "sourceRoot":
                    source_root = template_path(reader.string().split("?", 1)[0])
                elif key == "version":
                    version = reader.primitive()
                    if version != 3:
                        raise InputError("unsupported_source_map_version")
                elif key == "sourcesContent" and reader.peek() == "[":
                    embedded = True
                    reader.expect("[")
                    reader.space()
                    if reader.peek() != "]":
                        while True:
                            index = content_count
                            content_count += 1
                            reader.space()
                            if reader.peek() == '"':
                                map_source = {**source, "map_source_index": index, "source_root": source_root,
                                              "map_source": names[index] if index < len(names) else None}
                                scanner = StaticScanner(writer, map_source, check, base_url)
                                for chunk in reader.string_chunks():
                                    scanner.feed(chunk)
                                scanner.feed("", final=True)
                                status["gaps"].extend(scanner.gaps)
                                if index >= len(names):
                                    status["gaps"].append("source_map_name_binding_unavailable")
                            elif reader.primitive() is None:
                                status["gaps"].append("source_map_source_not_embedded")
                            else:
                                raise InputError("invalid_sources_content_type")
                            reader.space()
                            if reader.peek() == "]":
                                break
                            reader.expect(",")
                    reader.expect("]")
                else:
                    if key == "sections":
                        status["gaps"].append("indexed_source_map_not_supported")
                    reader.skip()
                reader.space()
                if reader.peek() == "}":
                    break
                reader.expect(",")
        reader.expect("}")
        reader.space()
        if reader.peek():
            raise InputError("source_map_trailing_data")
    status["source_count"] = len(names)
    status["embedded_source_count"] = content_count
    if not embedded or content_count < len(names):
        status["gaps"].append("source_map_sources_not_embedded")
    if version is None:
        status["gaps"].append("source_map_version_missing")


def source_paths(inputs):
    for value in inputs:
        if not isinstance(value, (str, Path)):
            raise InputError("source_path_required")
        path = Path(value).expanduser()
        if path.is_symlink():
            raise InputError("symlink_input_rejected")
        if path.is_dir():
            yield from (file for file in file_paths(path) if file.suffix.lower() in SOURCE_EXTENSIONS)
        else:
            path = input_file(path)
            if path.suffix.lower() not in SOURCE_EXTENSIONS:
                raise InputError("unsupported_source_extension")
            yield path


def run(inputs, output_dir, base_url=None, timeout=120, max_source_bytes=32 * 1024 * 1024):
    if not isinstance(inputs, (list, tuple)) or not inputs:
        raise InputError("source_input_list_required")
    if type(timeout) is not int or not 1 <= timeout <= 1800 or type(max_source_bytes) is not int or not 1 <= max_source_bytes <= 256 * 1024 * 1024:
        raise InputError("invalid_offline_limits")
    if base_url and not normalize_candidate(base_url)["host"]:
        raise InputError("absolute_base_url_required")
    output = output_directory(output_dir)
    deadline = time.monotonic() + timeout
    check = lambda: check_budget(deadline)
    manifest = {"schema_version": SCHEMA_VERSION, "mode": "offline_js_candidates", "state": "partial",
                "complete": False, "export_complete": False, "raw_complete": True,
                "candidate_only": True, "coverage_complete": False, "network_requests": 0, "js_executed": False,
                "inputs": [], "blocked_reasons": [], "inventory_file": str(output / "inventory.ndjson"),
                "queues": {"javascript": str(output / "js_queue.ndjson"), "source_map": str(output / "map_queue.ndjson"), "download": str(output / "download_queue.ndjson")},
                "limits": {"timeout_seconds": timeout, "max_source_bytes": max_source_bytes, "window_chars": WINDOW_CHARS, "literal_chars": 2048},
                "notes": ["raw counts literal/call candidate occurrences, not HTTP requests; unique includes source location",
                          "regex/static extraction cannot prove full endpoint coverage or evaluate concatenations, variables or runtime routing",
                          "source-map sourcesContent is streamed; maps without embedded sources remain explicit gaps",
                          "base_url_candidates are contextual hints, not proof of binding; only --base-url resolves relative URLs",
                          "raw JS context, header values and non-routing query values are omitted"]}
    atomic_json(output / "manifest.json", manifest)
    try:
        writer = CandidateWriter(output / "inventory.ndjson", queues=True, provenance=True)
    except Exception:
        manifest.update(raw_complete=False, partial=True, counts={name: 0 for name in ("raw", "unique", "exported", "skipped", "parse_errors", "duplicates")})
        manifest["blocked_reasons"].append("inventory_initialization_failed")
        atomic_json(output / "manifest.json", manifest)
        return manifest
    try:
        for path in source_paths(inputs):
            check()
            status = {"path": str(path), "bytes": path.stat().st_size, "raw_complete": False, "gaps": []}
            manifest["inputs"].append(status)
            try:
                if status["bytes"] > max_source_bytes:
                    raise InputError("source_size_limit")
                original = path.stat()
                status["sha256"] = stream_sha256(path, check)
                source = {"path": str(path), "sha256": status["sha256"]}
                if path.suffix.lower() == ".map":
                    scan_source_map(path, writer, source, check, base_url, status)
                else:
                    scanner = StaticScanner(writer, source, check, base_url)
                    with path.open(encoding="utf-8-sig", errors="strict") as stream:
                        while True:
                            check()
                            chunk = stream.read(CHUNK_CHARS)
                            if not chunk:
                                break
                            scanner.feed(chunk)
                        scanner.feed("", final=True)
                    status["gaps"].extend(scanner.gaps)
                current = path.stat()
                if original.st_size != current.st_size or original.st_mtime_ns != current.st_mtime_ns:
                    raise InputError("input_changed_during_extraction")
                status["raw_complete"] = True
            except (ValueError, UnicodeError) as exc:
                writer.counts["parse_errors"] += 1
                status["gaps"].append(exc.code if isinstance(exc, InputError) else "source_parse_or_encoding_error")
            if status["gaps"] or not status["raw_complete"]:
                manifest["blocked_reasons"].extend(status["gaps"])
            if not status["raw_complete"]:
                manifest["raw_complete"] = False
        if not manifest["inputs"]:
            manifest["blocked_reasons"].append("no_supported_source_files")
        manifest["export_complete"] = manifest["raw_complete"] and writer.counts["parse_errors"] == 0
    except Exception as exc:
        manifest["raw_complete"] = False
        manifest["blocked_reasons"].append(str(exc) if isinstance(exc, BudgetExceeded) else "source_extraction_exception")
    finally:
        manifest["counts"] = writer.counts.copy()
        manifest["candidates_preview"] = writer.preview
        try:
            writer.close()
        except Exception:
            manifest["export_complete"] = False
            manifest["blocked_reasons"].append("inventory_flush_failed")
        manifest["complete"] = manifest["export_complete"] and not manifest["blocked_reasons"]
        manifest["partial"] = not manifest["complete"]
        manifest["state"] = "complete" if manifest["complete"] else "partial"
        manifest["blocked_reasons"] = list(dict.fromkeys(manifest["blocked_reasons"]))
        atomic_json(output / "manifest.json", manifest)
    return manifest


def make_parser():
    parser = OfflineParser(description=__doc__)
    parser.add_argument("--input", action="append", required=True, help="local JS/TS/source-map file or directory; repeatable; no downloads")
    parser.add_argument("--output-dir", required=True, help="new private output directory")
    parser.add_argument("--base-url", help="explicit offline base; relative bindings otherwise stay uncertain")
    parser.add_argument("--timeout", type=positive_seconds, default=120)
    parser.add_argument("--max-source-bytes", type=int, default=32 * 1024 * 1024, help="per-source limit, 1-268435456 bytes; oversized files are explicit gaps")
    return parser


def main(argv=None):
    args = make_parser().parse_args(argv)
    try:
        manifest = run(args.input, args.output_dir, args.base_url, args.timeout, args.max_source_bytes)
        print(json.dumps({"mode": manifest["mode"], "manifest_file": str(Path(args.output_dir).resolve() / "manifest.json"),
                          "inventory_file": manifest["inventory_file"], "complete": manifest["complete"],
                          "export_complete": manifest["export_complete"], "counts": manifest["counts"],
                          "candidate_only": True, "network_requests": 0, "js_executed": False}), flush=True)
        return 0 if manifest["complete"] else 1
    except (OSError, ValueError):
        print(json.dumps({"mode": "offline_js_candidates", "complete": False, "blocked_reasons": ["invalid_or_unwritable_input_output"], "network_requests": 0, "js_executed": False}), flush=True)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
