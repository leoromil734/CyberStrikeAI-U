#!/usr/bin/env python3
"""Normalize local URL lists into a candidate-only inventory; never sends requests."""

import argparse
import csv
import json
import os
from pathlib import Path
import time

try:
    from .candidate_inventory import (BudgetExceeded, CandidateWriter, InputError, SCHEMA_VERSION,
                                     atomic_json, check_budget, csv_rows, normalize_candidate,
                                     stream_sha256)
except ImportError:
    from candidate_inventory import (BudgetExceeded, CandidateWriter, InputError, SCHEMA_VERSION,
                                     atomic_json, check_budget, csv_rows, normalize_candidate,
                                     stream_sha256)

MAX_RECORD_CHARS = 1024 * 1024


class OfflineParser(argparse.ArgumentParser):
    def error(self, _message):
        self.print_usage()
        self.exit(2, "invalid_cli_input; verify input paths, scalar types and limits (--help)\n")


def positive_seconds(value):
    try:
        number = int(value)
    except (ValueError, TypeError) as exc:
        raise argparse.ArgumentTypeError("integer required") from exc
    if not 1 <= number <= 1800:
        raise argparse.ArgumentTypeError("must be 1-1800 seconds")
    return number


def output_directory(value):
    if not isinstance(value, (str, Path)):
        raise InputError("output_path_required")
    path = Path(value).expanduser()
    if path.is_symlink():
        raise InputError("symlink_output_directory_rejected")
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = path.resolve()
    if any((path / name).exists() or (path / name).is_symlink() for name in ("manifest.json", "inventory.ndjson", "js_queue.ndjson", "map_queue.ndjson", "download_queue.ndjson")):
        raise InputError("output_already_exists_use_new_directory")
    path.chmod(0o700)
    return path


def input_file(value):
    if not isinstance(value, (str, Path)):
        raise InputError("input_path_required")
    path = Path(value).expanduser()
    if path.is_symlink():
        raise InputError("symlink_input_rejected")
    try:
        path = path.resolve(strict=True)
        if not path.is_file():
            raise InputError("regular_input_file_required")
        return path
    except OSError as exc:
        raise InputError("missing_or_unreadable_input_file") from exc


def input_records(path, input_format, check):
    if input_format == "auto":
        input_format = "csv" if path.suffix.lower() == ".csv" else ("ndjson" if path.suffix.lower() in (".ndjson", ".jsonl") else "text")
    if input_format == "csv":
        for row, line in csv_rows(path, check):
            yield ({"url": row.get("url"), "method": row.get("method")} if row else None), line
        return
    with path.open(encoding="utf-8-sig", errors="strict") as stream:
        line_number = 0
        while True:
            check()
            line = stream.readline(MAX_RECORD_CHARS + 1)
            if not line:
                break
            line_number += 1
            if len(line) > MAX_RECORD_CHARS:
                raise InputError("input_record_limit")
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if input_format == "text":
                yield {"url": line, "method": "UNKNOWN"}, line_number
            else:
                try:
                    record = json.loads(line)
                    yield record if isinstance(record, dict) else None, line_number
                except (ValueError, TypeError):
                    yield None, line_number


def run(inputs, output_dir, input_format="auto", base_url=None, timeout=120):
    if input_format not in ("auto", "text", "ndjson", "csv"):
        raise InputError("unsupported_input_format")
    if type(timeout) is not int or not 1 <= timeout <= 1800:
        raise InputError("invalid_timeout")
    if not inputs or not isinstance(inputs, (list, tuple)):
        raise InputError("input_file_list_required")
    paths = [input_file(value) for value in inputs]
    if base_url:
        normalized_base = normalize_candidate(base_url)
        if not normalized_base["host"]:
            raise InputError("absolute_base_url_required")
    output = output_directory(output_dir)
    deadline = time.monotonic() + timeout
    check = lambda: check_budget(deadline)
    manifest = {"schema_version": SCHEMA_VERSION, "mode": "offline_url_inventory", "state": "partial",
                "complete": False, "export_complete": False, "raw_complete": True,
                "candidate_only": True, "coverage_complete": False, "network_requests": 0,
                "inputs": [], "blocked_reasons": [], "inventory_file": str(output / "inventory.ndjson"),
                "queues": {"javascript": str(output / "js_queue.ndjson"), "source_map": str(output / "map_queue.ndjson"), "download": str(output / "download_queue.ndjson")},
                "notes": ["all references are unverified candidates, not evidence of requested/tested coverage",
                          "scheme, host, explicit port, static path template and parameter names are retained",
                          "routing parameter values are retained; ordinary query values and likely PII are omitted",
                          "JS and source maps have independent queues; downloads remain in the inventory and download queue"]}
    atomic_json(output / "manifest.json", manifest)
    try:
        writer = CandidateWriter(output / "inventory.ndjson", queues=True)
    except Exception:
        manifest.update(raw_complete=False, partial=True, counts={name: 0 for name in ("raw", "unique", "exported", "skipped", "parse_errors", "duplicates")})
        manifest["blocked_reasons"].append("inventory_initialization_failed")
        atomic_json(output / "manifest.json", manifest)
        return manifest
    try:
        for path in paths:
            status = {"path": str(path), "raw": 0, "raw_complete": False, "parse_errors": 0}
            manifest["inputs"].append(status)
            try:
                status["sha256"] = stream_sha256(path, check)
                original = path.stat()
                for record, line in input_records(path, input_format, check):
                    writer.counts["raw"] += 1
                    status["raw"] += 1
                    try:
                        if not isinstance(record, dict):
                            raise InputError("invalid_input_record")
                        candidate = normalize_candidate(record.get("url"), record.get("method", "UNKNOWN"),
                                                        {"path": str(path), "line": line, "sha256": status["sha256"]}, base_url)
                        writer.write(candidate)
                    except (ValueError, TypeError):
                        writer.counts["skipped"] += 1
                        writer.counts["parse_errors"] += 1
                        status["parse_errors"] += 1
                current = path.stat()
                if original.st_size != current.st_size or original.st_mtime_ns != current.st_mtime_ns:
                    raise InputError("input_changed_during_export")
                status["raw_complete"] = True
            except (csv.Error, UnicodeError, InputError) as exc:
                writer.counts["parse_errors"] += 1
                status["parse_errors"] += 1
                status["blocked_reason"] = exc.code if isinstance(exc, InputError) else "input_parse_or_encoding_error"
            if not status["raw_complete"]:
                manifest["raw_complete"] = False
            if status["parse_errors"]:
                manifest["blocked_reasons"].append("input_incomplete_or_invalid")
        manifest["export_complete"] = not manifest["blocked_reasons"]
    except Exception as exc:
        manifest["raw_complete"] = False
        manifest["blocked_reasons"].append(str(exc) if isinstance(exc, BudgetExceeded) else "inventory_export_exception")
    finally:
        manifest["counts"] = writer.counts.copy()
        manifest["candidates_preview"] = writer.preview
        try:
            writer.close()
        except Exception:
            manifest["export_complete"] = False
            manifest["blocked_reasons"].append("inventory_flush_failed")
        manifest["complete"] = manifest["export_complete"] and manifest["raw_complete"] and writer.counts["parse_errors"] == 0
        manifest["partial"] = not manifest["complete"]
        manifest["state"] = "complete" if manifest["complete"] else "partial"
        manifest["blocked_reasons"] = list(dict.fromkeys(manifest["blocked_reasons"]))
        atomic_json(output / "manifest.json", manifest)
    return manifest


def make_parser():
    parser = OfflineParser(description=__doc__)
    parser.add_argument("--input", action="append", required=True, help="existing UTF-8 text/NDJSON/CSV file; repeat for several files")
    parser.add_argument("--output-dir", required=True, help="new private output directory; existing inventories are never overwritten")
    parser.add_argument("--input-format", choices=("auto", "text", "ndjson", "csv"), default="auto")
    parser.add_argument("--base-url", help="explicit offline base for relative references; never fetched")
    parser.add_argument("--timeout", type=positive_seconds, default=120)
    return parser


def main(argv=None):
    args = make_parser().parse_args(argv)
    try:
        manifest = run(args.input, args.output_dir, args.input_format, args.base_url, args.timeout)
        print(json.dumps({"mode": manifest["mode"], "manifest_file": str(Path(args.output_dir).resolve() / "manifest.json"),
                          "inventory_file": manifest["inventory_file"], "complete": manifest["complete"],
                          "export_complete": manifest["export_complete"], "counts": manifest["counts"],
                          "candidate_only": True, "network_requests": 0}), flush=True)
        return 0 if manifest["complete"] else 1
    except (OSError, ValueError):
        print(json.dumps({"mode": "offline_url_inventory", "complete": False, "blocked_reasons": ["invalid_or_unwritable_input_output"], "network_requests": 0}), flush=True)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
