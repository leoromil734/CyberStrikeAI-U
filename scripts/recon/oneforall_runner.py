#!/usr/bin/env python3
"""Run installation-prepared OneForAll without mutating its read-only tree.

Only data files are copied, never source/configuration/API credentials. The
existing OS sandbox remains authoritative; this adapter does not create one.
"""
import hashlib
import json
import os
from pathlib import Path
import platform
import runpy
import shutil
import stat
import sys
import tempfile
import uuid

ADAPTER_VERSION = 1
MANIFEST = ".csai-oneforall.json"
MAX_DATA_BYTES = 256 * 1024 * 1024
MAX_DATA_FILES = 10000
MANAGED_FILES = ("common/utils.py", "config/default.py", "config/setting.py",
                 "config/log.py", "oneforall_runner.py")


class AdapterError(RuntimeError):
    pass


def no_symlink_path(path):
    path = Path(path)
    if not path.is_absolute() or ".." in path.parts:
        raise AdapterError("absolute_path_without_parent_traversal_required")
    for component in (path, *path.parents):
        if component.is_symlink():
            raise AdapterError("symlink_path_rejected")
    return path


def require_massdns_executable(path):
    """No chmod, including on EROFS. Permissions are an installation concern."""
    path = Path(path)
    if not path.is_file() or not os.access(path, os.R_OK | os.X_OK):
        raise AdapterError("massdns_missing_or_not_executable: rerun oneforall_prepare.py during maintenance; do not disable the sandbox")
    return path


def massdns_path(installation):
    system, machine = platform.system().lower(), platform.machine().lower()
    if system != "linux":
        raise AdapterError("oneforall_managed_runtime_requires_linux")
    return Path(installation) / "thirdparty" / "massdns" / f"massdns_{system}_{machine}"


def artifact_root(environ):
    if environ.get("CSAI_WORKSPACE_SANDBOX") != "1":
        raise AdapterError("managed_workspace_sandbox_required; no host fallback")
    execution = environ.get("CSAI_EXECUTION_ID", "")
    try:
        if str(uuid.UUID(execution)) != execution:
            raise ValueError()
    except ValueError as error:
        raise AdapterError("service_execution_uuid_required") from error
    root = no_symlink_path(environ.get("CSAI_ARTIFACT_DIR", ""))
    if not root.is_dir() or root.name != execution or root.parent.name != "executions":
        raise AdapterError("service_execution_artifact_directory_required")
    if os.name == "posix" and root.stat().st_mode & 0o022:
        raise AdapterError("artifact_directory_must_not_be_group_or_world_writable")
    return root


def runtime_path(name):
    """Used by prepared upstream settings, including spawned Python workers."""
    if name not in ("data", "results"):
        raise AdapterError("unknown_runtime_path")
    root = artifact_root(os.environ)
    run = no_symlink_path(os.environ.get("CSAI_ONEFORALL_RUN_DIR", ""))
    if run.parent != root or not run.name.startswith("oneforall-") or not run.is_dir():
        raise AdapterError("private_run_directory_required; use the managed oneforall launcher")
    path = no_symlink_path(run / name)
    if not path.is_dir():
        raise AdapterError("prepared_runtime_directory_missing")
    return path


def validate_installation(installation):
    installation = no_symlink_path(installation)
    try:
        manifest_path = no_symlink_path(installation / MANIFEST)
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        if manifest.get("adapter_version") != ADAPTER_VERSION:
            raise AdapterError("adapter_version_mismatch; rerun oneforall_prepare.py")
        hashes = manifest.get("sha256", {})
        for relative in MANAGED_FILES:
            path = no_symlink_path(installation / relative)
            if hashlib.sha256(path.read_bytes()).hexdigest() != hashes.get(relative):
                raise AdapterError("prepared_source_changed; review changes and rerun oneforall_prepare.py")
        if not no_symlink_path(installation / "oneforall.py").is_file():
            raise AdapterError("oneforall_entrypoint_missing")
        require_massdns_executable(no_symlink_path(massdns_path(installation)))
    except (OSError, ValueError, TypeError, AttributeError) as error:
        raise AdapterError("installation_not_prepared; run oneforall_prepare.py with the existing venv interpreter") from error


def _walk_failure(error):
    raise error


def copy_runtime_data(source, destination):
    source = no_symlink_path(source)
    if not source.is_dir():
        raise AdapterError("installation_data_directory_missing")
    count, remaining = 0, MAX_DATA_BYTES
    # Installation data is trusted, read-only vendor material, not user input.
    for directory, dirs, files in os.walk(source, followlinks=False, onerror=_walk_failure):
        parent = Path(directory)
        for name in dirs + files:
            candidate = parent / name
            if candidate.is_symlink():
                raise AdapterError("installation_data_symlink_rejected")
            count += 1
            if count > MAX_DATA_FILES:
                raise AdapterError("installation_data_file_limit_exceeded")
        relative = parent.relative_to(source)
        target = destination / relative
        target.mkdir(mode=0o700, parents=True, exist_ok=True)
        for name in files:
            candidate = parent / name
            info = candidate.stat()
            if not stat.S_ISREG(info.st_mode) or info.st_size > remaining:
                raise AdapterError("installation_data_size_or_file_type_rejected")
            with candidate.open("rb") as incoming, (target / name).open("xb") as outgoing:
                while True:
                    chunk = incoming.read(min(1024 * 1024, remaining + 1))
                    if not chunk:
                        break
                    remaining -= len(chunk)
                    if remaining < 0:
                        raise AdapterError("installation_data_size_limit_exceeded")
                    outgoing.write(chunk)


def prepare_run(installation, environ):
    validate_installation(installation)
    root = artifact_root(environ)
    run = Path(tempfile.mkdtemp(prefix="oneforall-", dir=root))
    try:
        (run / "results" / "temp").mkdir(mode=0o700, parents=True)
        copy_runtime_data(Path(installation) / "data", run / "data")
    except Exception:
        shutil.rmtree(run)
        raise
    return run


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    installation = Path(__file__).resolve().parent
    try:
        # An offline deployment probe: never import upstream or contact targets.
        if argv == ["--check-runtime"]:
            validate_installation(installation)
            print("oneforall adapter: installation and massdns permissions verified (offline)")
            return 0
        if argv in (["--help"], ["-h"], ["--runner-help"]):
            print("Managed OneForAll (offline adapter help)\n"
                  "CLI forwarded unchanged: --target DOMAIN [--fmt csv|json] [--path PATH] [--brute True|False] [--dns True|False] [--req True|False] run\n"
                  "Target execution requires the service workspace sandbox and execution artifact environment.\n"
                  "--check-runtime verifies the installed adapter and massdns without importing upstream or scanning.")
            return 0
        os.umask(0o077)
        run = prepare_run(installation, os.environ)
        os.environ["CSAI_ONEFORALL_RUN_DIR"] = str(run)
        os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
        sys.dont_write_bytecode = True
        # Do not chdir: explicit relative --path/--targets retain caller semantics.
        sys.path.insert(0, str(installation))
        sys.argv = [str(installation / "oneforall.py"), *argv]
        print("oneforall adapter: private runtime " + str(run), file=sys.stderr)
    except AdapterError as error:
        print("oneforall adapter: " + str(error), file=sys.stderr)
        return 78
    except OSError as error:
        # Only local preparation errors are classified here. An upstream
        # OSError can be a network failure and must retain its original meaning.
        print(f"oneforall adapter: local preparation failed (errno={error.errno}); inspect runtime permissions and disk space", file=sys.stderr)
        return 78
    try:
        runpy.run_path(str(installation / "oneforall.py"), run_name="__main__")
    except AdapterError as error:
        print("oneforall adapter: " + str(error), file=sys.stderr)
        return 78
    return 0
    # SystemExit (including upstream exit 2) intentionally propagates unchanged.


if __name__ == "__main__":
    # Prepared upstream modules import helpers by this name; share exception
    # identity with the launcher instead of loading a second module instance.
    sys.modules.setdefault("oneforall_runner", sys.modules[__name__])
    raise SystemExit(main())
