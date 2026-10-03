#!/usr/bin/env python3
"""Run pinned JSAPIscan in systemd or an already verified workspace sandbox."""

import argparse
import csv
import json
import math
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
    from .candidate_inventory import (BudgetExceeded, CandidateWriter, InputError, SCHEMA_VERSION,
                                     atomic_json, check_budget, csv_rows, emit_json, file_paths,
                                     normalize_candidate, stream_sha256)
except ImportError:  # Executed as a standalone installed launcher.
    from candidate_inventory import (BudgetExceeded, CandidateWriter, InputError, SCHEMA_VERSION,
                                     atomic_json, check_budget, csv_rows, emit_json, file_paths,
                                     normalize_candidate, stream_sha256)

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
MAX_TARGETS = 200
MAX_BATCH_SIZE = 20
CLEANUP_GRACE_SECONDS = 20
POLL_SECONDS = 0.5
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
INT_LIMITS = {
    "threads": (1, 5), "fetch_threads": (1, 10), "depth": (1, 16),
    "request_timeout": (1, 60), "max_js_requests": (1, 10000),
    "max_html_requests": (1, 200), "max_api_tests": (1, 3000),
    "total_timeout": (1, 1800), "batch_timeout": (1, 1800), "batch_size": (1, 20),
    "heartbeat_interval": (15, 30), "export_timeout": (1, 300), "external_depth": (1, 3),
}


class SafeParser(argparse.ArgumentParser):
    def error(self, _message):
        # argparse's original error can repeat a secret passed as an argument.
        self.print_usage(sys.stderr)
        self.exit(2, "jsapiscan: invalid_cli_input; verify scalar types, limits and mutually exclusive inputs (--help)\n")


def bounded_int(minimum, maximum):
    def parse(value):
        try:
            number = int(value)
        except (ValueError, TypeError) as exc:
            raise argparse.ArgumentTypeError("integer required") from exc
        if not minimum <= number <= maximum:
            raise argparse.ArgumentTypeError(f"must be between {minimum} and {maximum}; zero/unlimited is not accepted")
        return number
    return parse


def make_parser():
    parser = SafeParser(description=__doc__)
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("-u", "--url", help="HTTP(S) URLs, comma-separated; at most 200 unique authorized targets")
    target.add_argument("-f", "--targets-file", help="existing UTF-8 URL list, <=128 KiB; at most 200 authorized targets")
    parser.add_argument("-t", "--threads", type=bounded_int(1, 5), default=1)
    parser.add_argument("-ft", "--fetch-threads", type=bounded_int(1, 10), default=2)
    parser.add_argument("-d", "--depth", type=bounded_int(1, 16), default=8)
    parser.add_argument("-time", "--request-timeout", type=bounded_int(1, 60), default=8)
    parser.add_argument("-maxreq", "--max-js-requests", type=bounded_int(1, 10000), default=1000)
    parser.add_argument("-maxhtml", "--max-html-requests", type=bounded_int(1, 200), default=40)
    parser.add_argument("-maxapi", "--max-api-tests", type=bounded_int(1, 3000), default=200)
    parser.add_argument("--total-timeout", type=bounded_int(1, 1800), default=300, help="global scan deadline, shared by all batches (not reset)")
    parser.add_argument("--batch-timeout", type=bounded_int(1, 1800), default=300, help="each batch is also capped by the remaining global scan time")
    parser.add_argument("--batch-size", type=bounded_int(1, 20), default=20)
    parser.add_argument("--heartbeat-interval", type=bounded_int(15, 30), default=20)
    parser.add_argument("--export-timeout", type=bounded_int(1, 300), default=120, help="separate bounded offline export budget after scan/cleanup")
    parser.add_argument("--validate-only", action="store_true", help="offline input preflight; no binary, systemd or HTTP execution")
    parser.add_argument("-o", "--output-format", choices=("txt", "html"), default="txt")
    parser.add_argument("-op", "--output-name", default="scan.txt", help="simple filename inside each isolated batch")
    auth = parser.add_mutually_exclusive_group()
    auth.add_argument("-header", "--headers", help="prefer --headers-file; inline values are copied to a private file, never echoed")
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
    parser.add_argument("--allow-post-retry", action="store_true", help="explicit GET-405 POST fallback; requires -api and no -aget; never automatically reruns a batch")
    parser.add_argument("--version", action="version", version=f"CyberStrikeAI wrapper; official release {RELEASE}; SHA-256 {BINARY_SHA256}")
    return parser


def validate_url(value):
    if not isinstance(value, str) or not value:
        raise InputError("invalid_type", "url")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise InputError("invalid_url", "url") from exc
    if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username is not None or parsed.password is not None:
        raise InputError("http_url_without_credentials_required", "url")
    if port is not None and not 1 <= port <= 65535:
        raise InputError("invalid_port", "url")
    if any(ord(char) < 32 or char.isspace() for char in value):
        raise InputError("url_contains_controls_or_whitespace", "url")
    return value


def read_input(path, field="input_file"):
    if not isinstance(path, (str, Path)):
        raise InputError("invalid_type", field)
    try:
        path = Path(path).expanduser()
        if path.is_symlink():
            raise InputError("symlink_input_rejected", field)
        path = path.resolve(strict=True)
        if not path.is_file() or path.stat().st_size > MAX_INPUT_BYTES:
            raise InputError("regular_file_at_most_128kib_required", field)
        with path.open("rb") as stream:
            data = stream.read(MAX_INPUT_BYTES + 1)
        if len(data) > MAX_INPUT_BYTES or b"\0" in data:
            raise InputError("oversized_or_binary_input", field)
        data.decode("utf-8-sig")
        return data
    except (OSError, UnicodeError) as exc:
        raise InputError("missing_unreadable_or_non_utf8_file", field) from exc


def validate_types(args):
    for name, (low, high) in INT_LIMITS.items():
        value = getattr(args, name, None)
        if type(value) is not int or not low <= value <= high:
            raise InputError("invalid_integer_or_limit", name)
    for name in [name for name, _flag in VALUE_FLAGS if name not in INT_LIMITS] + ["url", "targets_file", "headers_file"]:
        value = getattr(args, name, None)
        if value is not None and not isinstance(value, str):
            raise InputError("string_required", name)
    for name in [name for name, _flag in BOOL_FLAGS] + ["get_only", "allow_post_retry", "validate_only"]:
        if type(getattr(args, name, None)) is not bool:
            raise InputError("boolean_required", name)


def prepare_targets(args):
    validate_types(args)
    if bool(args.url) == bool(args.targets_file):
        raise InputError("exactly_one_target_input_required")
    if args.url:
        if len(args.url.encode("utf-8")) > MAX_INPUT_BYTES:
            raise InputError("oversized_target_input", "url")
        targets = [validate_url(value.strip()) for value in args.url.split(",") if value.strip()]
    else:
        targets = [validate_url(value.strip()) for value in read_input(args.targets_file, "targets_file").decode("utf-8-sig").splitlines() if value.strip() and not value.strip().startswith("#")]
    targets = list(dict.fromkeys(targets))
    if not 1 <= len(targets) <= MAX_TARGETS:
        raise InputError("requires_1_to_200_unique_authorized_targets")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,79}", args.output_name):
        raise InputError("simple_output_filename_required", "output_name")
    if args.output_format not in ("txt", "html"):
        raise InputError("unsupported_output_format", "output_format")
    if args.headers and args.headers_file:
        raise InputError("headers_inputs_are_mutually_exclusive")
    if args.allow_post_retry and (not args.api_tests or args.get_only):
        raise InputError("post_fallback_requires_explicit_api_and_no_get_only")
    if args.proxy_api_only and (not args.proxy or not args.api_tests):
        raise InputError("api_only_proxy_requires_proxy_and_api_tests")
    return targets


def preflight(args):
    targets = prepare_targets(args)
    headers = read_input(args.headers_file, "headers_file") if args.headers_file else None
    if args.headers:
        headers = args.headers.encode("utf-8")
        if len(headers) > MAX_INPUT_BYTES or b"\0" in headers:
            raise InputError("oversized_or_binary_headers", "headers")
    return targets, headers


def build_upstream_args(args, targets, targets_path=None, headers_path=None):
    result = ["-f", str(targets_path)] if targets_path else ["-u", ",".join(targets)]
    for name, flag in VALUE_FLAGS:
        if name == "headers" and headers_path:
            continue
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
        "KillMode=control-group", "TimeoutStopSec=5s", "SendSIGKILL=yes",
    )
    command = ["/usr/bin/systemd-run", "--quiet", "--wait", "--pipe", f"--unit={unit}"]
    for prop in properties:
        command.extend(["--property", prop])
    return command + [str(binary)] + argv


def _workspace_mounts():
    mounts = {}
    for line in Path("/proc/self/mountinfo").read_text(encoding="utf-8").splitlines():
        before, after = line.split(" - ", 1)
        fields, filesystem = before.split(), after.split()
        mountpoint = re.sub(r"\\([0-7]{3})", lambda match: chr(int(match[1], 8)), fields[4])
        mounts[Path(mountpoint)] = (filesystem[0], set(fields[5].split(",")))
    return mounts


def _covering_mount(path, mounts):
    path = Path(path)
    return max((mount for mount in mounts if path.is_relative_to(mount)), key=lambda mount: len(mount.parts))


def _workspace_nproc_enforced():
    # uid_map describes the *parent* user namespace, not necessarily the host.
    # In particular unprivileged bwrap can report <uid> -> 0 through its setup
    # namespace. Probe in a separate, bounded interpreter, so no rlimit of the
    # orchestrator is changed and a host-root mapping cannot bypass NPROC.
    probe = ("import errno, os, resource, sys\n"
             "resource.setrlimit(resource.RLIMIT_NPROC, (0, 0))\n"
             "try:\n pid = os.fork()\n"
             "except OSError as exc:\n sys.exit(0 if exc.errno == errno.EAGAIN else 2)\n"
             "if pid == 0:\n os._exit(1)\n"
             "os.waitpid(pid, 0)\nsys.exit(1)\n")
    try:
        result = subprocess.run([sys.executable, "-I", "-S", "-c", probe], env={"PATH": "/usr/bin:/bin"},
                                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                start_new_session=True, timeout=3, check=False)
        return result.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def _workspace_sandbox():
    """The service marker is necessary, never sufficient to skip systemd isolation.

    Accept a single-ID user namespace or the full identity UID/GID maps after
    real host-side privilege dropping. Both require a read-only tmpfs root and
    runtime, private bubblewrap PID/proc context, no privilege regain or host
    control plane, and an actually enforced NPROC limit. Guest UID alone never
    proves that the underlying host identity is unprivileged.
    """
    marker = os.environ.get("CSAI_WORKSPACE_SANDBOX")
    if marker is None:
        return False
    try:
        if marker != "1" or sys.platform != "linux":
            raise ValueError("marker")
        status = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text(encoding="ascii").splitlines() if ":" in line)
        for field in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"):
            if int(status[field].strip(), 16) != 0:
                raise ValueError("capabilities")
        if status["NoNewPrivs"].strip() != "1":
            raise ValueError("privilege_regain")
        identity_maps = []
        for kind, actual in (("uid", os.getuid()), ("gid", os.getgid())):
            rows = [tuple(map(int, line.split())) for line in Path(f"/proc/self/{kind}_map").read_text(encoding="ascii").splitlines()]
            identity_map = rows == [(0, 0, 4294967295)]
            single_id = len(rows) == 1 and len(rows[0]) == 3 and rows[0][0] == actual and rows[0][2] == 1
            if not (identity_map or single_id):
                raise ValueError("namespace_mapping")
            identity_maps.append(identity_map)
            if actual == 0 or list(map(int, status[kind.title()].split())) != [actual] * 4:
                raise ValueError("mixed_or_root_credentials")
        if identity_maps[0] != identity_maps[1]:
            raise ValueError("mixed_namespace_mappings")
        mounts = _workspace_mounts()
        root_fs, root_options = mounts[Path("/")]
        if root_fs != "tmpfs" or not {"ro", "nosuid", "nodev"} <= root_options:
            raise ValueError("root_mount")
        if mounts[Path("/proc")][0] != "proc":
            raise ValueError("proc_mount")
        # A freshly mounted procfs must describe our PID namespace, whose PID 1
        # is bubblewrap's init, not host systemd (nor a host procfs bind mount).
        init = dict(line.split(":", 1) for line in Path("/proc/1/status").read_text(encoding="ascii").splitlines() if ":" in line)
        if (int(status["Pid"]) != os.getpid() or list(map(int, status["NSpid"].split())) != [os.getpid()]
                or init["Name"].strip() != "bwrap" or int(init["Pid"]) != 1 or int(init["PPid"]) != 0
                or list(map(int, init["NSpid"].split())) != [1]):
            raise ValueError("private_bubblewrap_pid_namespace_required")
        for path in (Path("/usr"), BINARY.resolve(), Path(__file__).resolve(), Path(sys.executable).resolve()):
            if "ro" not in mounts[_covering_mount(path, mounts)][1]:
                raise ValueError("writable_runtime")
        if Path("/run/systemd").exists() or Path("/run/dbus").exists():
            raise ValueError("host_control_plane")
        if os.getuid() == 0 or not _workspace_nproc_enforced():
            raise InputError("workspace_resource_limits_require_nonroot_uid_mapping")
        return True
    except InputError:
        raise
    except (OSError, ValueError, KeyError, IndexError, AttributeError) as exc:
        raise InputError("untrusted_workspace_sandbox_context", "CSAI_WORKSPACE_SANDBOX") from exc


def _workspace_run_root():
    value = os.environ.get("CSAI_ARTIFACT_DIR")
    base = Path(value) if value else Path.cwd()
    # An explicit, invalid artifact location must not silently switch to cwd.
    if value == "" or not base.is_absolute() or not base.is_dir() or base.resolve() != base:
        raise InputError("invalid_workspace_artifact_directory", "CSAI_ARTIFACT_DIR")
    mounts = _workspace_mounts()
    mount = _covering_mount(base, mounts)
    filesystem, options = mounts[mount]
    if (mount in {Path(p) for p in ("/", "/usr", "/etc", "/dev", "/proc", "/sys", "/run", "/var", "/tmp")}
            or "rw" not in options or filesystem in ("proc", "sysfs", "devtmpfs", "devpts")):
        raise InputError("workspace_artifact_writable_mount_required", "CSAI_ARTIFACT_DIR")
    return base / ("jsapiscan" if value else ".jsapiscan-runs")


def workspace_command(binary, argv, work, seconds, headless=False):
    """Hard, inherited per-process memory/CPU and per-real-UID task limits.

    GNU timeout is an independent wall-clock watchdog, including when this
    Python orchestrator is killed. No missing-helper or resource-limit failure
    ever retries the binary without the limits. These are rlimits, not a claim
    of aggregate cgroup MemoryMax accounting.
    """
    memory = (1024 if headless else 512) * 1024 * 1024
    limits = {"as": 4 * 1024 ** 3, "data": memory, "nproc": 128,
              "cpu": seconds + 2, "core": 0, "nofile": 256}
    command = ["/usr/bin/prlimit", *(f"--{name}={value}:{value}" for name, value in limits.items()),
               "--", "/usr/bin/timeout", "--signal=TERM", "--kill-after=2s", f"{seconds}s", str(binary), *argv]
    home, temporary = work / ".home", work / ".tmp"
    home.mkdir(mode=0o700)
    temporary.mkdir(mode=0o700)
    env = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "HOME": str(home), "TMPDIR": str(temporary),
           "TMP": str(temporary), "TEMP": str(temporary), "GOMAXPROCS": "2", "GOMEMLIMIT": str(memory * 3 // 4),
           "XDG_CACHE_HOME": str(home / ".cache"), "XDG_CONFIG_HOME": str(home / ".config")}
    return command, {"cwd": str(work), "env": env, "umask": 0o077}


class Cancellation:
    """Signal handlers only set state; they never interrupt cleanup/manifest writes."""

    def __init__(self):
        self.requested = False
        self.signum = None

    def request(self, signum=None, _frame=None):
        # No locks, I/O or exceptions in a signal handler (Event.set can deadlock
        # if the signal interrupts Event.wait while its internal lock is held).
        self.signum = signum
        self.requested = True

    def is_set(self):
        return self.requested

    def wait(self, seconds):
        time.sleep(seconds)  # Always <= POLL_SECONDS, so cancellation stays bounded.
        return self.requested


class Heartbeat:
    def __init__(self, interval=20):
        self.interval = interval
        self.started = time.monotonic()
        self.last = self.started - interval
        self.phase = "preflight"
        self.counts = {}

    def tick(self, force=False, phase=None, **counts):
        if phase:
            self.phase = phase
        self.counts.update(counts)
        now = time.monotonic()
        if force or now - self.last >= self.interval:
            emit_json({"event": "jsapiscan_progress", "phase": self.phase,
                       "elapsed_seconds": round(now - self.started, 3), **self.counts})
            self.last = now


def _systemctl(unit, action, deadline, timeout=5):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise BudgetExceeded("cleanup_budget_exhausted")
    command = ["/usr/bin/systemctl", *action, unit + ".service"]
    return subprocess.run(command, capture_output=True, text=True,
                          timeout=min(timeout, remaining), check=False)


def cleanup_process(process, unit, deadline):
    result, blockers = "unknown", []
    try:
        response = _systemctl(unit, ["show", "--property=Result", "--value"], deadline, 3)
        if response.returncode:
            raise RuntimeError("status_failed")
        value = response.stdout.strip()
        if value in ("success", "timeout", "watchdog", "exit-code", "signal", "resources", "start-limit-hit", "oom-kill"):
            result = value
    except Exception:
        blockers.append("systemd_status_unavailable")
    try:
        stopped = _systemctl(unit, ["stop"], deadline, 5)
        if stopped.returncode:
            raise RuntimeError("stop_failed")
    except Exception:
        blockers.append("systemd_stop_failed")
        try:
            killed = _systemctl(unit, ["kill", "--signal=KILL", "--kill-whom=all"], deadline, 3)
            if killed.returncode:
                blockers.append("systemd_kill_failed")
        except Exception:
            blockers.append("systemd_kill_failed")
    try:
        reset = _systemctl(unit, ["reset-failed"], deadline, 2)
        if reset.returncode:
            raise RuntimeError("reset_failed")
    except Exception:
        blockers.append("systemd_reset_failed")
    if process is not None:
        try:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=max(0.01, min(2, deadline - time.monotonic())))
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=max(0.01, min(2, deadline - time.monotonic())))
        except Exception:
            blockers.append("launcher_cleanup_failed")
    return result, blockers


def cleanup_workspace_process(process, deadline):
    """Reap the launcher and kill its entire session's initial process group.

    Always signal the group, even after its leader has exited: a child may
    still be writing artifacts. The enclosing private PID namespace must be
    destroyed with its owning command (bwrap --die-with-parent).
    """
    blockers = []
    if process is None:
        return "not_started", blockers
    for signum in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(process.pid, signum)
        except ProcessLookupError:
            pass
        except OSError:
            blockers.append("process_group_signal_failed")
        try:
            process.wait(timeout=max(0, min(2, deadline - time.monotonic())))
        except subprocess.TimeoutExpired:
            if signum == signal.SIGKILL:
                blockers.append("process_group_reap_timeout")
        except OSError:
            blockers.append("process_group_reap_failed")
    return ("failed" if blockers else "stopped"), blockers


def collect_artifacts(work, export_path=None, deadline=None, heartbeat=None, cancellation=None):
    work = Path(work).resolve()
    export_path = Path(export_path) if export_path else work.parent / "candidates.ndjson"
    result = {"artifacts": [], "csv_files": [], "candidates_file": str(export_path),
              "export_complete": False, "raw_complete": True, "blockers": []}
    tick = heartbeat.tick if heartbeat else None
    check = lambda: check_budget(deadline, tick, cancellation.is_set if cancellation else None)
    writer = None
    try:
        writer = CandidateWriter(export_path)
        check()
        for path in file_paths(work):
            check()
            relative = path.relative_to(work).as_posix()
            item = {"path": relative, "bytes": path.stat().st_size}
            result["artifacts"].append(item)
            item["sha256"] = stream_sha256(path, check, root=work)
            if path.suffix.lower() != ".csv":
                continue
            status = {"path": relative, "bytes": item["bytes"], "raw": 0,
                      "raw_complete": False, "export_complete": False, "parse_errors": 0}
            result["csv_files"].append(status)
            try:
                for row, line in csv_rows(path, check, root=work):
                    writer.counts["raw"] += 1
                    status["raw"] += 1
                    if row is None or not row.get("url") or not row.get("method"):
                        writer.counts["parse_errors"] += 1
                        writer.counts["skipped"] += 1
                        status["parse_errors"] += 1
                        continue
                    try:
                        candidate = normalize_candidate(row["url"], row["method"],
                                                        {"path": relative, "line": line, "sha256": item["sha256"]})
                    except ValueError:
                        writer.counts["parse_errors"] += 1
                        writer.counts["skipped"] += 1
                        status["parse_errors"] += 1
                        continue
                    for field in ("status", "length"):
                        # Never copy Body, Headers or arbitrary scanner columns.
                        value = row.get(field, "")
                        candidate[field] = value if re.fullmatch(r"[0-9]{1,20}", value) else None
                    writer.write(candidate)
                    if heartbeat:
                        heartbeat.tick(raw=writer.counts["raw"], exported=writer.counts["exported"])
                status["raw_complete"] = True
                status["export_complete"] = status["parse_errors"] == 0
            except (csv.Error, UnicodeError, InputError) as exc:
                writer.counts["parse_errors"] += 1
                status["parse_errors"] += 1
                status["blocked_reason"] = exc.code if isinstance(exc, InputError) else "csv_parse_or_encoding_error"
            if not status["export_complete"]:
                result["blockers"].append("csv_incomplete_or_invalid:" + relative)
            if not status["raw_complete"]:
                result["raw_complete"] = False
        check()
        result["export_complete"] = not result["blockers"] and writer.counts["parse_errors"] == 0
    except Exception as exc:
        result["raw_complete"] = False
        result["export_complete"] = False
        result["blockers"].append(str(exc) if isinstance(exc, BudgetExceeded) else "artifact_export_failed")
    finally:
        if writer:
            result["counts"] = writer.counts.copy()
            result["candidates_preview"] = writer.preview
            try:
                writer.close()
            except Exception:
                result["export_complete"] = False
                result["blockers"].append("candidate_export_flush_failed")
        else:
            result["counts"] = {name: 0 for name in ("raw", "unique", "exported", "skipped", "parse_errors", "duplicates")}
            result["candidates_preview"] = []
    return result


def _execution_id():
    value = os.environ.get("CSAI_EXECUTION_ID")
    if value is None:
        return None
    # Accept only the hyphenated UUID spelling; no trimming, URN, braces or paths.
    if not re.fullmatch(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", value):
        raise InputError("invalid_execution_id", "CSAI_EXECUTION_ID")
    return str(uuid.UUID(value))


def _new_job(workspace_sandbox=False):
    execution_id = _execution_id()
    root = _workspace_run_root() if workspace_sandbox else RUN_ROOT
    mode = 0o700 if workspace_sandbox else 0o711
    root.mkdir(parents=True, mode=0o700 if workspace_sandbox else 0o755, exist_ok=True)
    if root.is_symlink():
        raise InputError("symlink_run_root_rejected")
    if execution_id is None:
        job = Path(tempfile.mkdtemp(prefix="run-", dir=root))
    else:
        job = root / ("execution-" + execution_id)
        try:
            job.mkdir(mode=mode)  # Atomic reservation; never reuse an existing path.
        except FileExistsError as exc:
            raise InputError("execution_directory_already_exists", "CSAI_EXECUTION_ID") from exc
    job.chmod(mode)
    return job


def _copy_input(work, name, data, user):
    destination = work / name
    try:
        destination.write_bytes(data)
        destination.chmod(0o600)
        if user is not None:
            os.chown(destination, user.pw_uid, user.pw_gid)
        return destination
    except BaseException:
        try:
            destination.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def run_batch(args, targets, headers, work, log, user, number, deadline, cleanup_deadline, heartbeat, cancellation, workspace_sandbox=False):
    unit = None if workspace_sandbox else "csai-jsapiscan-" + uuid.uuid4().hex[:16]
    record = {"number": number, "unit": unit, "target_count": len(targets), "state": "partial",
              "returncode": 1, "timed_out": False, "cancelled": False, "blockers": []}
    process, inputs = None, []
    started = time.monotonic()
    try:
        work.mkdir(mode=0o700)
        if user is not None:
            os.chown(work, user.pw_uid, user.pw_gid)
        targets_path = _copy_input(work, "_input_targets.txt", ("\n".join(targets) + "\n").encode(), user)
        inputs.append(targets_path)
        headers_path = None
        if headers is not None:
            headers_path = _copy_input(work, "_input_headers.txt", headers, user)
            inputs.append(headers_path)
        seconds = min(args.batch_timeout, math.floor(deadline - time.monotonic()))
        if cancellation.is_set():
            record.update(cancelled=True, returncode=130)
            record["blockers"].append("cancelled_before_launch")
        elif seconds < 1:
            record.update(timed_out=True, returncode=124)
            record["blockers"].append("global_scan_timeout")
        else:
            record["runtime_max_seconds"] = seconds
            argv = build_upstream_args(args, targets, targets_path, headers_path)
            launch_options = {}
            if workspace_sandbox:
                command, launch_options = workspace_command(BINARY, argv, work, seconds, args.headless)
            else:
                command = sandbox_command(BINARY, argv, work, unit, seconds, args.headless)
            batch_deadline = min(deadline, time.monotonic() + seconds)
            heartbeat.tick(force=True, phase="scan", batch=number, batch_targets=len(targets))
            with log.open("ab") as stream:
                log.chmod(0o600)
                process = subprocess.Popen(command, stdout=stream, stderr=subprocess.STDOUT,
                                           start_new_session=True, **launch_options)
                record["launched"] = True
                while True:
                    if cancellation.is_set():
                        record.update(cancelled=True, returncode=130)
                        record["blockers"].append("cancelled")
                        break
                    code = process.poll()
                    if code is not None:
                        record["returncode"] = code
                        break
                    now = time.monotonic()
                    if now >= batch_deadline:
                        record.update(timed_out=True, returncode=124)
                        record["blockers"].append("global_scan_timeout" if now >= deadline else "batch_scan_timeout")
                        break
                    heartbeat.tick(log_bytes=log.stat().st_size)
                    cancellation.wait(min(POLL_SECONDS, max(0, batch_deadline - now)))
    except KeyboardInterrupt:
        cancellation.request(signal.SIGINT)
        record.update(cancelled=True, returncode=130)
        record["blockers"].append("cancelled")
    except Exception:
        # Upstream errors may contain URLs/headers: retain raw logs, not exception text.
        record["blockers"].append("batch_launcher_exception")
    finally:
        heartbeat.tick(force=True, phase="cleanup", batch=number)
        if workspace_sandbox:
            try:
                record["process_group_result"], blockers = cleanup_workspace_process(process, cleanup_deadline)
                record["blockers"].extend(blockers)
            except Exception:
                record["process_group_result"] = "unknown"
                record["blockers"].append("cleanup_exception_watchdog_still_applies")
            if record["returncode"] == 124:
                record["timed_out"] = True
                record["blockers"].append("workspace_wall_timeout")
        else:
            try:
                record["systemd_result"], blockers = cleanup_process(process, unit, cleanup_deadline)
                record["blockers"].extend(blockers)
            except Exception:
                record["systemd_result"] = "unknown"
                record["blockers"].append("cleanup_exception_runtime_max_still_applies")
            if record["systemd_result"] in ("timeout", "watchdog"):
                record.update(timed_out=True, returncode=124)
                record["blockers"].append("systemd_runtime_timeout")
            elif record["systemd_result"] not in ("success", "unknown"):
                record["blockers"].append("systemd_" + record["systemd_result"])
                record["returncode"] = record["returncode"] or 1
        if record["returncode"] and not record["timed_out"] and not record["cancelled"]:
            record["blockers"].append("upstream_nonzero_exit")
        for path in inputs:
            try:
                path.unlink(missing_ok=True)
            except OSError:
                record["blockers"].append("private_input_cleanup_failed")
        if not record["returncode"] and not record["blockers"]:
            record["state"] = "complete"
        if record["cancelled"]:
            record["state"] = "cancelled"
        record["elapsed_seconds"] = round(time.monotonic() - started, 3)
    return record


def _manifest_base():
    return {"schema_version": SCHEMA_VERSION, "release": RELEASE, "sha256": BINARY_SHA256,
            "user": RUN_USER, "state": "partial", "partial": True, "complete": False,
            "cancelled": False, "timed_out": False, "scan_complete": False,
            "export_complete": False, "raw_complete": False, "candidate_only": True,
            "coverage_complete": False, "batches": [], "target_count": 0, "started_target_count": 0,
            "blocked_reasons": [], "returncode": 1, "candidate_count": 0,
            "counts": {name: 0 for name in ("raw", "unique", "exported", "skipped", "parse_errors", "duplicates")},
            "notes": ["complete describes bounded process/export completion, never target coverage",
                      "URLs are templates: ordinary query values and likely personal identifiers are omitted",
                      "CSV/source references are candidates only, not verified endpoints or vulnerabilities",
                      "raw_complete/export_complete describe available regular on-disk inputs, not all upstream discovery work",
                      "symlinks and non-regular artifacts are never read as candidate inputs",
                      "calling-task authorization is required; URL syntax validation never grants scope",
                      "request/category/depth caps may leave undiscovered work; HTTP request count is not observable",
                      "authorized input URLs do not authorize discovered cross-domain links; no automatic retries"]}


def _runtime_supported():
    return sys.platform == "linux" and pwd is not None and os.geteuid() == 0


def run(args, cancellation=None):
    cancellation = cancellation or Cancellation()
    started = time.monotonic()
    heartbeat = Heartbeat(getattr(args, "heartbeat_interval", 20) if type(getattr(args, "heartbeat_interval", None)) is int else 20)
    manifest, job, work = _manifest_base(), None, None
    workspace_sandbox, runtime_checked = False, False
    code = 1
    heartbeat.tick(force=True)
    try:
        manifest["execution_id"] = _execution_id()
        if not getattr(args, "validate_only", False):
            workspace_sandbox = _workspace_sandbox()
            runtime_checked = True
            manifest["execution_mode"] = "workspace" if workspace_sandbox else "systemd"
            if workspace_sandbox:
                manifest.update(user=str(os.getuid()), uid=os.getuid(), gid=os.getgid())
                manifest["resource_limit_scope"] = "per-process address-space/data/CPU; per-real-UID tasks (128), not aggregate cgroup memory"
        targets, headers = preflight(args)
        manifest["target_count"] = len(targets)
        manifest["batch_size"] = args.batch_size
        manifest["batch_count"] = math.ceil(len(targets) / args.batch_size)
        manifest["limits"] = {name: getattr(args, name) for name in INT_LIMITS}
        manifest["effective_get_only"] = not args.allow_post_retry or args.get_only
        manifest["validation_only"] = args.validate_only
        if args.validate_only:
            code = 0
            manifest.update(state="validated", partial=False, returncode=0)
            emit_json({"event": "jsapiscan_validation", "valid": True, "target_count": len(targets),
                       "batch_count": manifest["batch_count"], "batch_size": args.batch_size,
                       "global_scan_timeout_seconds": args.total_timeout,
                       "network_requests": 0, "candidate_only": True})
            return 0
        if not workspace_sandbox and not _runtime_supported():
            raise InputError("linux_root_orchestrator_required_upstream_never_root")
        job = _new_job(workspace_sandbox)
        manifest.update(work_dir=str(job / "work"), stdout_file=str(job / "stdout.log"), manifest_file=str(job / "manifest.json"))
        atomic_json(job / "manifest.json", manifest)  # Checkpoint survives even an uncatchable external kill.
        binary_check = lambda: check_budget(started + args.total_timeout, heartbeat.tick, cancellation.is_set)
        if stream_sha256(BINARY, binary_check) != BINARY_SHA256:
            raise InputError("pinned_binary_sha256_mismatch")
        user = None
        if not workspace_sandbox:
            user = pwd.getpwnam(RUN_USER)
            if user.pw_uid == 0 or user.pw_gid == 0:
                raise InputError("dedicated_upstream_account_must_not_be_root")
        work = job / "work"
        work.mkdir(mode=0o700)
        if user is not None:
            os.chown(work, user.pw_uid, user.pw_gid)
        deadline = started + args.total_timeout
        cleanup_deadline = deadline + CLEANUP_GRACE_SECONDS  # One global grace, never reset per batch.
        for offset in range(0, len(targets), args.batch_size):
            if cancellation.is_set() or time.monotonic() >= deadline:
                manifest["blocked_reasons"].append("cancelled" if cancellation.is_set() else "global_scan_timeout")
                code = 130 if cancellation.is_set() else 124
                manifest["timed_out"] = not cancellation.is_set()
                break
            batch = targets[offset:offset + args.batch_size]
            number = len(manifest["batches"]) + 1
            record = run_batch(args, batch, headers, work / f"batch-{number:04d}", job / "stdout.log",
                               user, number, deadline, cleanup_deadline, heartbeat, cancellation, workspace_sandbox)
            manifest["batches"].append(record)
            manifest["unit"] = record["unit"]
            manifest["started_target_count"] += len(batch) if record.get("launched") else 0
            manifest["timed_out"] |= record["timed_out"]
            manifest["blocked_reasons"].extend(record["blockers"])
            manifest["cancelled"] = cancellation.is_set() or record["cancelled"]
            atomic_json(job / "manifest.json", manifest)
            heartbeat.tick(force=True, phase="batch_finished", finished_batches=number)
            code = record["returncode"]
            if code < 0:
                code = 128 - code
            if code or record["blockers"] or manifest["cancelled"]:
                # Fail closed. A failed batch is never retried; later targets remain explicitly unstarted.
                code = code or 1
                break
        manifest["scan_complete"] = len(manifest["batches"]) == manifest["batch_count"] and all(item["state"] == "complete" for item in manifest["batches"])
    except KeyboardInterrupt:
        cancellation.request(signal.SIGINT)
        manifest["blocked_reasons"].append("cancelled")
        code = 130
    except BudgetExceeded:
        manifest["timed_out"] = not cancellation.is_set()
        manifest["blocked_reasons"].append("cancelled" if cancellation.is_set() else "global_scan_timeout")
        code = 130 if cancellation.is_set() else 124
    except InputError as exc:
        manifest["blocked_reasons"].append(exc.code)
        manifest["invalid_field"] = exc.field
        code = 2
    except Exception:
        manifest["blocked_reasons"].append("launcher_preflight_or_io_exception")
        code = 1
    finally:
        if not getattr(args, "validate_only", False) or code:
            manifest["cancelled"] |= cancellation.is_set()
            if manifest["cancelled"]:
                code = 130
            if manifest["target_count"] > manifest["started_target_count"]:
                manifest["unstarted_target_count"] = manifest["target_count"] - manifest["started_target_count"]
            if work and work.exists():
                # Cancellation is checked during every hash/row; do not delay termination with a large export.
                heartbeat.tick(force=True, phase="export", raw=0, exported=0)
                try:
                    exported = collect_artifacts(work, job / "candidates.ndjson",
                                                 time.monotonic() + args.export_timeout, heartbeat, cancellation)
                    manifest.update({name: value for name, value in exported.items() if name != "blockers"})
                    manifest["blocked_reasons"].extend(exported["blockers"])
                    manifest["candidate_count"] = manifest["counts"]["exported"]
                except Exception:
                    manifest["export_complete"] = False
                    manifest["raw_complete"] = False
                    manifest["blocked_reasons"].append("artifact_export_exception")
            manifest["cancelled"] |= cancellation.is_set()
            if manifest["cancelled"]:
                code = 130
            manifest["complete"] = manifest["scan_complete"] and manifest["export_complete"] and not manifest["blocked_reasons"] and not manifest["cancelled"]
            manifest["partial"] = not manifest["complete"]
            manifest["state"] = "cancelled" if manifest["cancelled"] else ("complete" if manifest["complete"] else "partial")
            manifest["blocked_reasons"] = list(dict.fromkeys(manifest["blocked_reasons"]))
            manifest["elapsed_seconds"] = round(time.monotonic() - started, 3)
            code = code or (0 if manifest["complete"] else 1)
            manifest["returncode"] = code
            try:
                if job is None and not runtime_checked and getattr(args, "validate_only", False):
                    # Invalid offline inputs still get a durable manifest when
                    # the execution context permits it; successful validation
                    # never probes or launches any process.
                    workspace_sandbox = _workspace_sandbox()
                    runtime_checked = True
                    if workspace_sandbox:
                        manifest.update(execution_mode="workspace", user=str(os.getuid()), uid=os.getuid(), gid=os.getgid())
                if job is None and runtime_checked and (workspace_sandbox or _runtime_supported()):
                    job = _new_job(workspace_sandbox)  # Never persist an invalid sandbox claim on the host.
                if job:
                    manifest["manifest_file"] = str(job / "manifest.json")
                    atomic_json(job / "manifest.json", manifest)
            except InputError as exc:
                manifest["blocked_reasons"] = list(dict.fromkeys(manifest["blocked_reasons"] + [exc.code]))
                manifest["invalid_field"] = exc.field
                code = code or 2
                manifest["returncode"] = code
            except OSError:
                manifest["blocked_reasons"].append("manifest_write_failed")
                code = code or 1
                manifest.update(complete=False, partial=True, state="cancelled" if manifest["cancelled"] else "partial", returncode=code)
            # Only paths, controlled diagnostics and numeric counts leave stdout. Read the private manifest for previews.
            emit_json({"event": "jsapiscan_result", "state": manifest["state"], "returncode": code,
                       "execution_id": manifest.get("execution_id"),
                       "manifest_file": manifest.get("manifest_file"), "work_dir": manifest.get("work_dir"),
                       "stdout_file": manifest.get("stdout_file"), "candidates_file": manifest.get("candidates_file"),
                       "complete": manifest["complete"], "cancelled": manifest["cancelled"],
                       "export_complete": manifest["export_complete"], "raw_complete": manifest["raw_complete"],
                       "counts": manifest["counts"], "target_count": manifest["target_count"],
                       "started_target_count": manifest["started_target_count"],
                       "blocked_reasons": [reason.split(":", 1)[0] for reason in manifest["blocked_reasons"]],
                       "candidate_only": True})
    return code


def main(argv=None):
    parser = make_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        if exc.code:
            manifest = _manifest_base()
            manifest["blocked_reasons"] = ["invalid_cli_input"]
            manifest["returncode"] = 2
            path = None
            try:
                manifest["execution_id"] = _execution_id()
                workspace_sandbox = _workspace_sandbox()
                if workspace_sandbox or _runtime_supported():
                    if workspace_sandbox:
                        manifest.update(execution_mode="workspace", user=str(os.getuid()), uid=os.getuid(), gid=os.getgid())
                    path = _new_job(workspace_sandbox) / "manifest.json"
                    manifest["manifest_file"] = str(path)
                    atomic_json(path, manifest)
            except InputError as error:
                manifest["blocked_reasons"].append(error.code)
            except OSError:
                pass
            emit_json({"event": "jsapiscan_result", "state": "partial", "returncode": 2,
                       "execution_id": manifest.get("execution_id"),
                       "manifest_file": str(path) if path else None, "blocked_reasons": manifest["blocked_reasons"]})
        return exc.code
    cancellation, previous = Cancellation(), {}
    if sys.platform == "linux":
        for signum in (signal.SIGTERM, signal.SIGINT):
            previous[signum] = signal.getsignal(signum)
            signal.signal(signum, cancellation.request)
    try:
        return run(args, cancellation)
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)


if __name__ == "__main__":
    sys.exit(main())
