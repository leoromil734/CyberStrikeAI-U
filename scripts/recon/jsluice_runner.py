#!/usr/bin/env python3
"""Offline-only adapter for BishopFox/jsluice; never fetch URLs or execute JS.

Upstream CLI/source contract: cmd/jsluice/{main,urls,secrets}.go on main.
Only `urls --include-source -- FILE` and `secrets -- FILE` are used.
Upstream -j means raw INPUT, -p means secret PATTERNS, neither means JSON.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import time
import uuid
from urllib.parse import urlsplit

MAX_INPUT = 32 << 20
MAX_OUTPUT = 64 << 20
MAX_LINE = 1 << 20
MAX_RECORDS = 100000
SCHEMA = "csai.jsluice.v1"


class InputError(ValueError):
    pass


def regular_path(value, directory=False):
    path = Path(os.path.abspath(value))
    for part in (path, *path.parents):
        if part.is_symlink() or part.resolve() != part:
            raise InputError("symlink_path_rejected")
    info = path.stat()
    if directory:
        if not stat.S_ISDIR(info.st_mode):
            raise InputError("directory_required")
    elif not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise InputError("regular_single_link_file_required")
    return path


def validate(args):
    if args.mode not in ("urls", "secrets") or not 1 <= args.timeout <= 600:
        raise InputError("invalid_mode_or_timeout")
    if "://" in args.file or "\n" in args.file or "\r" in args.file:
        raise InputError("local_file_required")
    source = regular_path(args.file)
    if source.stat().st_size > MAX_INPUT:
        raise InputError("source_size_limit")
    parsed = urlsplit(args.source_url)
    if (parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username is not None
            or parsed.password is not None or len(args.source_url) > 8192
            or any(ord(c) <= 32 for c in args.source_url)):
        raise InputError("source_url_metadata_required")
    # source_url is attribution only, never an upstream input or a fetch target.
    return source


def allocate_job():
    value = os.environ.get("CSAI_EXECUTION_ID", "")
    if not re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", value):
        raise InputError("service_execution_id_required")
    if str(uuid.UUID(value)) != value:
        raise InputError("invalid_execution_id")
    root_value = os.environ.get("CSAI_ARTIFACT_DIR", "")
    if not root_value or not Path(root_value).is_absolute():
        raise InputError("service_artifact_directory_required")
    root = regular_path(root_value, directory=True)
    if root.name != value or root.parent.name != "executions":
        raise InputError("artifact_execution_binding_mismatch")
    parent = root / "jsluice"
    parent.mkdir(mode=0o700, exist_ok=True)
    regular_path(parent, directory=True)
    job = parent / ("execution-" + value)
    job.mkdir(mode=0o700)  # Atomic reservation. Never reuse a previous run.
    return job, value


def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(65536), b""):
            h.update(block)
    return h.hexdigest()


def private_open(path, mode="xb"):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
    return os.fdopen(fd, mode)


def copy_source(source, destination):
    # Pin the opened file and compare identities to avoid reading a replacement.
    before = source.stat()
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    with os.fdopen(os.open(source, flags), "rb") as incoming, private_open(destination) as outgoing:
        opened = os.fstat(incoming.fileno())
        if not os.path.samestat(before, opened) or opened.st_nlink != 1:
            raise InputError("source_changed")
        total = 0
        for block in iter(lambda: incoming.read(65536), b""):
            total += len(block)
            if total > MAX_INPUT:
                raise InputError("source_size_limit")
            outgoing.write(block)
        after = os.fstat(incoming.fileno())
        if before.st_size != total or before.st_mtime_ns != after.st_mtime_ns:
            raise InputError("source_changed")
    regular_path(source)
    if not os.path.samestat(before, source.stat()):
        raise InputError("source_changed")


def execute(binary, mode, job, timeout):
    argv = [binary, mode]
    if mode == "urls":
        argv.append("--include-source")
    argv.extend(["--", str(job / "source.js")])
    blockers = []
    with private_open(job / "raw.jsonl") as output, private_open(job / "stderr.log") as errors:
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=output, stderr=errors, shell=False)
        deadline = time.monotonic() + timeout
        try:
            while process.poll() is None:
                if time.monotonic() >= deadline:
                    blockers.append("analysis_timeout")
                    break
                if any((job / name).stat().st_size > MAX_OUTPUT for name in ("raw.jsonl", "stderr.log")):
                    blockers.append("output_size_limit")
                    break
                time.sleep(0.05)
        finally:
            if process.poll() is None:
                process.kill()
            code = process.wait()
    if code:
        blockers.append("upstream_failed")
    if (job / "stderr.log").stat().st_size:
        # Upstream may print errors and still exit 0. Never claim success then.
        blockers.append("upstream_stderr_requires_review")
    if any((job / name).stat().st_size > MAX_OUTPUT for name in ("raw.jsonl", "stderr.log")):
        if "output_size_limit" not in blockers:
            blockers.append("output_size_limit")
    return argv, code, blockers


def export_records(job, args, source_hash):
    counts = {"raw": 0, "exported": 0, "parse_errors": 0}
    blockers = []
    output_name = args.mode + ".jsonl"
    with (job / "raw.jsonl").open("rb") as raw, private_open(job / output_name) as output:
        read = 0
        written = 0
        while True:
            line = raw.readline(MAX_LINE + 1)
            if not line:
                break
            read += len(line)
            if len(line) > MAX_LINE or read > MAX_OUTPUT or counts["raw"] >= MAX_RECORDS:
                blockers.append("export_limit")
                break
            counts["raw"] += 1
            try:
                match = json.loads(line)
                if not isinstance(match, dict):
                    raise ValueError()
                if args.mode == "urls":
                    if not isinstance(match.get("url"), str) or not match["url"]:
                        raise ValueError()
                    # Keep relative strings and EXPR placeholders unchanged; no
                    # base URL inference, status code, or verified claim.
                    row = {key: match[key] for key in ("url", "method", "type", "queryParams", "bodyParams") if key in match}
                    row["relativeURL"] = match["url"] if not urlsplit(match["url"]).scheme else ""
                else:
                    if not isinstance(match.get("kind"), str) or not match["kind"]:
                        raise ValueError()
                    # Secret values/context stay only in private raw.jsonl.
                    row = {"kind": match["kind"], "severity": "tentative"}
                row.update(schema=SCHEMA, mode=args.mode, source_js=args.source_url,
                           source_sha256=source_hash, source_file="source.js", raw_line=counts["raw"],
                           candidate_only=True, verification="unverified")
                encoded = (json.dumps(row, ensure_ascii=True, separators=(",", ":")) + "\n").encode()
                if len(encoded) > MAX_LINE or written + len(encoded) > MAX_OUTPUT:
                    blockers.append("export_limit")
                    break
                output.write(encoded)
                written += len(encoded)
                counts["exported"] += 1
            except (ValueError, UnicodeError, TypeError):
                counts["parse_errors"] += 1
                if "invalid_upstream_jsonl" not in blockers:
                    blockers.append("invalid_upstream_jsonl")
    return counts, blockers


def run(args):
    source = validate(args)
    if args.validate_only:
        return {"tool": "jsluice", "validate_only": True, "network_requests": 0, "candidate_only": True}, 0
    job, execution_id = allocate_job()
    manifest = {"schema": SCHEMA, "tool": "jsluice", "execution_id": execution_id,
                "mode": args.mode, "source_js": args.source_url, "complete": False,
                "analysis_complete": False, "export_complete": False, "raw_complete": False,
                "coverage_complete": False, "candidate_only": True, "verification": "unverified",
                "partial": True, "timed_out": False, "blocked_reasons": []}
    code = 1
    try:
        copy_source(source, job / "source.js")
        manifest["source_sha256"] = digest(job / "source.js")
        binary = shutil.which("jsluice")
        if not binary:
            raise InputError("jsluice_not_installed")
        argv, code, blockers = execute(binary, args.mode, job, args.timeout)
        manifest.update(command=argv, returncode=code, analysis_complete=not blockers,
                        raw_complete="output_size_limit" not in blockers,
                        timed_out="analysis_timeout" in blockers)
        counts, export_blockers = export_records(job, args, manifest["source_sha256"])
        manifest.update(counts=counts, export_complete=not export_blockers)
        manifest["blocked_reasons"].extend(blockers + export_blockers)
        manifest["complete"] = not manifest["blocked_reasons"]
        code = 0 if manifest["complete"] else 1
    except (InputError, OSError, ValueError) as exc:
        code = 1
        # No URL/secret/body in stdout or error summaries.
        manifest["blocked_reasons"].append(str(exc) if isinstance(exc, InputError) else "local_adapter_failed")
    finally:
        manifest["partial"] = not manifest["complete"]
        manifest["files"] = {}
        for name in ("source.js", "raw.jsonl", "stderr.log", args.mode + ".jsonl"):
            path = job / name
            if path.is_file():
                manifest["files"][name] = {"sha256": digest(path), "bytes": path.stat().st_size}
        with private_open(job / "manifest.json") as output:
            output.write(json.dumps(manifest, ensure_ascii=True).encode())
    return {"tool": "jsluice", "execution_id": execution_id, "complete": manifest["complete"],
            "partial": manifest["partial"], "candidate_only": True, "coverage_complete": False,
            "counts": manifest.get("counts", {}), "blocked_reasons": manifest["blocked_reasons"]}, code


def main(argv=None):
    parser = argparse.ArgumentParser(description="Offline jsluice adapter; source URL is metadata only")
    parser.add_argument("mode", choices=("urls", "secrets"))
    parser.add_argument("--file", required=True, help="Existing local JavaScript file")
    parser.add_argument("--source-url", required=True, help="Source JS URL metadata; never fetched")
    parser.add_argument("--timeout", type=int, default=120)
    parser.add_argument("--validate-only", action="store_true")
    args = parser.parse_args(argv)
    try:
        summary, code = run(args)
    except (InputError, OSError, ValueError) as exc:
        summary, code = {"tool": "jsluice", "complete": False, "candidate_only": True,
                         "error": str(exc) if isinstance(exc, InputError) else "local_adapter_failed"}, 1
    print(json.dumps(summary, ensure_ascii=True))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
