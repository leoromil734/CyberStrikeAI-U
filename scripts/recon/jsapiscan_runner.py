#!/usr/bin/env python3
"""Run the pinned JSAPIscan release in a bounded, low-privilege systemd sandbox."""

import argparse
import csv
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import tempfile
import time
from urllib.parse import urlsplit
import uuid

try:
    import pwd
except ImportError:
    pwd = None

RELEASE = "v1.1.2"
BINARY = Path("/opt/jsapiscan/releases/v1.1.2/JSAPIscan_linux_amd64")
BINARY_SHA256 = "bf829b3e754a98c2817b5aa73dd138cf63a761dec669b1227e24a7f316958b68"
RUN_ROOT = Path("/var/lib/jsapiscan/runs")
RUN_USER = "csai-jsapiscan"
MAX_INPUT_BYTES = 128 * 1024
VALUE_FLAGS = (
    ("threads", "-t"), ("fetch_threads", "-ft"), ("depth", "-d"),
    ("request_timeout", "-time"), ("max_js_requests", "-maxreq"),
    ("max_html_requests", "-maxhtml"), ("max_api_tests", "-maxapi"),
    ("output_format", "-o"), ("output_name", "-op"), ("headers", "-header"),
    ("proxy", "-p"), ("hide_status_codes", "-sc"),
    ("append_keywords", "-gjca"), ("only_keywords", "-gjc"),
    ("js_prefix", "-basejspath"), ("api_prefix", "-baseapipath"),
    ("external_suffixes", "-extlinksuffix"), ("external_depth", "-extlinkdepth"),
    ("blocked_domains", "-domainblock"), ("rod_options", "-rod"),
)
BOOL_FLAGS = (
    ("api_tests", "-api"), ("verify_tls", "-tlsverify"), ("save_js", "-savejs"),
    ("headless", "-gorog"), ("external_links", "-extlink"),
    ("proxy_api_only", "-pa"), ("key_files_only", "-K"),
    ("personal_data", "-person"), ("evil_keywords", "-ey"),
    ("scan_public_libraries", "-scan-libs"), ("collect_external_links", "-wl"),
)


def bounded_int(minimum, maximum):
    def parse(value):
        number = int(value)
        if not minimum <= number <= maximum:
            raise argparse.ArgumentTypeError(f"must be between {minimum} and {maximum}; zero/unlimited is not accepted")
        return number
    return parse


def make_parser():
    parser = argparse.ArgumentParser(description=__doc__)
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("-u", "--url", dest="url", help="HTTP(S) URL, or up to 20 comma-separated in-scope URLs")
    target.add_argument("-f", "--targets-file", dest="targets_file", help="existing UTF-8 file; at most 20 in-scope URLs")
    parser.add_argument("-t", "--threads", type=bounded_int(1, 5), default=1)
    parser.add_argument("-ft", "--fetch-threads", type=bounded_int(1, 10), default=2)
    parser.add_argument("-d", "--depth", type=bounded_int(1, 16), default=8)
    parser.add_argument("-time", "--request-timeout", type=bounded_int(1, 60), default=8)
    parser.add_argument("-maxreq", "--max-js-requests", type=bounded_int(1, 10000), default=1000)
    parser.add_argument("-maxhtml", "--max-html-requests", type=bounded_int(1, 200), default=40)
    parser.add_argument("-maxapi", "--max-api-tests", type=bounded_int(1, 3000), default=200)
    parser.add_argument("--total-timeout", type=bounded_int(1, 1800), default=300)
    parser.add_argument("-o", "--output-format", choices=("txt", "html"), default="txt")
    parser.add_argument("-op", "--output-name", default="scan.txt", help="report filename inside this run, not an arbitrary output path")
    auth = parser.add_mutually_exclusive_group()
    auth.add_argument("-header", "--headers", help="prefer --headers-file so secrets do not enter command arguments")
    auth.add_argument("-header-file", "--headers-file", dest="headers_file")
    parser.add_argument("-p", "--proxy")
    parser.add_argument("-sc", "--hide-status-codes", dest="hide_status_codes")
    parser.add_argument("-gjca", "--append-keywords", dest="append_keywords")
    parser.add_argument("-gjc", "--only-keywords", dest="only_keywords")
    parser.add_argument("-basejspath", "--js-prefix", dest="js_prefix")
    parser.add_argument("-baseapipath", "--api-prefix", dest="api_prefix")
    parser.add_argument("-extlinksuffix", "--external-suffixes", dest="external_suffixes", default=".js,.mjs,.html,.htm")
    parser.add_argument("-extlinkdepth", "--external-depth", dest="external_depth", type=bounded_int(1, 3), default=1)
    parser.add_argument("-domainblock", "--blocked-domains", dest="blocked_domains")
    parser.add_argument("-rod", "--rod-options", dest="rod_options")
    for name, flag in BOOL_FLAGS:
        parser.add_argument(flag, "--" + name.replace("_", "-"), dest=name, action="store_true")
    parser.add_argument("-aget", "--get-only", dest="get_only", action="store_true")
    parser.add_argument("--allow-post-retry", action="store_true", help="explicitly permit the upstream GET-405 POST fallback; requires -api and no -aget")
    parser.add_argument("--version", action="version", version=f"CyberStrikeAI wrapper; official release {RELEASE}; SHA-256 {BINARY_SHA256}")
    return parser


def validate_url(value):
    parsed = urlsplit(value)
    if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("targets must be HTTP(S) URLs without embedded credentials")
    if any(ord(char) < 32 for char in value) or any(char.isspace() for char in value):
        raise ValueError("target URL contains whitespace/control characters")
    return value


def read_input(path):
    path = Path(path).expanduser().resolve(strict=True)
    if not path.is_file() or path.stat().st_size > MAX_INPUT_BYTES:
        raise ValueError("input must be a regular file no larger than 128 KiB")
    data = path.read_bytes()
    if len(data) > MAX_INPUT_BYTES or b"\0" in data:
        raise ValueError("oversized/binary input rejected")
    data.decode("utf-8-sig")
    return data


def prepare_targets(args):
    if args.url:
        targets = [validate_url(value.strip()) for value in args.url.split(",") if value.strip()]
    else:
        targets = [validate_url(value.strip()) for value in read_input(args.targets_file).decode("utf-8-sig").splitlines() if value.strip() and not value.strip().startswith("#")]
    targets = list(dict.fromkeys(targets))
    if not 1 <= len(targets) <= 20:
        raise ValueError("each run requires 1-20 unique, in-scope targets")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,79}", args.output_name):
        raise ValueError("output-name must be a simple filename inside the isolated run")
    if args.allow_post_retry and (not args.api_tests or args.get_only):
        raise ValueError("POST fallback requires api_tests=true, get_only=false and explicit allow_post_retry=true")
    if args.proxy_api_only and (not args.proxy or not args.api_tests):
        raise ValueError("API-only proxy requires both a proxy and api_tests=true")
    return targets


def build_upstream_args(args, targets, targets_path=None, headers_path=None):
    result = ["-f", str(targets_path)] if targets_path else ["-u", ",".join(targets)]
    for name, flag in VALUE_FLAGS:
        value = getattr(args, name)
        if value is not None and value != "":
            result.extend([flag, str(value)])
    for name, flag in BOOL_FLAGS:
        if getattr(args, name):
            result.append(flag)
    if not args.allow_post_retry or args.get_only:
        result.append("-aget")
    if headers_path:
        result.extend(["-header-file", str(headers_path)])
    return result


def sandbox_command(binary, argv, work, unit, seconds, headless=False):
    properties = (
        f"User={RUN_USER}", f"Group={RUN_USER}", f"WorkingDirectory={work}",
        f"ReadWritePaths={work}", "ProtectSystem=strict", "ProtectHome=yes",
        "PrivateTmp=yes", "PrivateDevices=yes", "NoNewPrivileges=yes", "CapabilityBoundingSet=",
        "RestrictSUIDSGID=yes", "ProtectProc=invisible", "ProtectKernelTunables=yes",
        "ProtectKernelModules=yes", "ProtectControlGroups=yes", "RestrictRealtime=yes",
        "LockPersonality=yes", "InaccessiblePaths=-/opt/CyberStrikeAI-U -/opt/cyberstrike -/var/lib/docker -/run/docker.sock",
        f"RuntimeMaxSec={seconds}", f"MemoryMax={'1G' if headless else '512M'}", "TasksMax=128",
        "CPUQuota=100%", "Environment=HOME=/tmp PATH=/usr/bin:/bin GOMAXPROCS=2", "UMask=0077",
    )
    command = ["/usr/bin/systemd-run", "--quiet", "--wait", "--pipe", f"--unit={unit}"]
    for prop in properties:
        command.extend(["--property", prop])
    return command + [str(binary)] + argv


def collect_artifacts(work):
    artifacts, endpoints, seen = [], [], set()
    for path in sorted(work.rglob("*")):
        if path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(work.resolve()):
            continue
        relative = str(path.relative_to(work))
        item = {"path": relative, "bytes": path.stat().st_size}
        if item["bytes"] <= 32 * 1024 * 1024:
            item["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
        artifacts.append(item)
        if path.suffix.lower() == ".csv" and item["bytes"] <= 8 * 1024 * 1024:
            with path.open(encoding="utf-8-sig", errors="replace", newline="") as stream:
                for index, row in enumerate(csv.DictReader(stream)):
                    if index >= 10000:
                        break
                    url, method = row.get("URL", ""), row.get("Method", "")
                    if not url or not method or (url, method) in seen:
                        continue
                    seen.add((url, method))
                    endpoints.append({"url": url, "method": method, "status": row.get("Status", ""), "length": row.get("Length", ""), "source": relative, "candidate_only": True})
    return artifacts, endpoints


def run(args):
    targets = prepare_targets(args)
    if sys.platform != "linux" or pwd is None or os.geteuid() != 0:
        raise RuntimeError("this launcher requires the Linux/root orchestrator; the upstream process itself runs as csai-jsapiscan, never root")
    if hashlib.sha256(BINARY.read_bytes()).hexdigest() != BINARY_SHA256:
        raise RuntimeError("installed binary SHA-256 differs from the verified official release; refusing execution")
    user = pwd.getpwnam(RUN_USER)
    RUN_ROOT.mkdir(parents=True, mode=0o755, exist_ok=True)
    job = Path(tempfile.mkdtemp(prefix="run-", dir=RUN_ROOT))
    job.chmod(0o711)
    work = job / "work"
    work.mkdir(mode=0o700)
    os.chown(work, user.pw_uid, user.pw_gid)
    def copy_input(name, data):
        destination = work / name
        destination.write_bytes(data)
        destination.chmod(0o600)
        os.chown(destination, user.pw_uid, user.pw_gid)
        return destination
    targets_path = copy_input("targets.txt", ("\n".join(targets) + "\n").encode()) if args.targets_file else None
    headers_path = copy_input("headers.txt", read_input(args.headers_file)) if args.headers_file else None
    upstream = build_upstream_args(args, targets, targets_path, headers_path)
    unit = "csai-jsapiscan-" + uuid.uuid4().hex[:16]
    command = sandbox_command(BINARY, upstream, work, unit, args.total_timeout, args.headless)
    start = time.monotonic()
    print(f"JSAPIscan {RELEASE}: sandbox user={RUN_USER}; targets={len(targets)}; timeout={args.total_timeout}s; artifacts={job}", flush=True)
    log = job / "stdout.log"
    timed_out, systemd_result = False, "unknown"
    with log.open("wb") as stream:
        log.chmod(0o600)
        try:
            result = subprocess.run(command, stdout=stream, stderr=subprocess.STDOUT, timeout=args.total_timeout + 20)
            returncode = result.returncode
        except subprocess.TimeoutExpired:
            timed_out, returncode = True, 124
        finally:
            # Also stop the transient unit when the launcher is cancelled or the external timeout wins.
            try:
                status = subprocess.run(["/usr/bin/systemctl", "show", "--property=Result", "--value", unit + ".service"], capture_output=True, text=True, timeout=5, check=False)
                systemd_result = status.stdout.strip() or "unknown"
                timed_out = timed_out or systemd_result in ("timeout", "watchdog")
            except subprocess.SubprocessError:
                pass
            try:
                subprocess.run(["/usr/bin/systemctl", "stop", unit + ".service"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15, check=False)
                subprocess.run(["/usr/bin/systemctl", "reset-failed", unit + ".service"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5, check=False)
            except subprocess.SubprocessError:
                pass  # RuntimeMaxSec still bounds the transient unit if the control plane is unavailable.
            if headers_path:
                headers_path.unlink(missing_ok=True)
    artifacts, endpoints = collect_artifacts(work)
    manifest = {"release": RELEASE, "sha256": BINARY_SHA256, "unit": unit, "user": RUN_USER,
                "targets": targets, "returncode": returncode, "timed_out": timed_out, "systemd_result": systemd_result,
                "elapsed_seconds": round(time.monotonic() - start, 3), "work_dir": str(work),
                "stdout_file": str(log), "artifacts": artifacts, "candidate_count": len(endpoints),
                "candidates_preview": endpoints[:50], "candidate_only": True,
                "limits": {"max_js_requests": args.max_js_requests, "max_html_requests": args.max_html_requests, "max_api_tests": args.max_api_tests, "total_timeout": args.total_timeout},
                "notes": ["CSV/strings are candidates, not confirmed vulnerabilities", "also run grep/rg over every saved JS and source-map source", "request caps are upstream category caps, not a strict total HTTP request limit", "headless/external-link/POST behavior needs task-specific scope and was not audited by the offline smoke test"]}
    destination = job / "manifest.json"
    destination.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n")
    destination.chmod(0o600)
    print(json.dumps(manifest, ensure_ascii=False, indent=2), flush=True)
    return returncode


def main():
    parser = make_parser()
    args = parser.parse_args()
    if sys.platform == "linux":
        def cancelled(signum, _frame):
            raise RuntimeError(f"cancelled by signal {signum}")
        signal.signal(signal.SIGTERM, cancelled)
        signal.signal(signal.SIGINT, cancelled)
    try:
        return run(args)
    except (OSError, ValueError, RuntimeError, KeyError) as exc:
        print(f"jsapiscan blocked: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
