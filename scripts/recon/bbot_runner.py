#!/usr/bin/env python3
"""Run BBOT inside the CyberStrikeAI workspace sandbox without mutating the
read-only runtime tree.

Deployment (maintenance window, root, outside the sandbox):

    pipx install bbot                       # /opt/pipx/venvs/bbot
    bbot -c home=/opt/bbot-home --install-all-deps   # prepared tools + cache

The prepared home is mounted read-only into the sandbox; scan evidence is
written to the execution artifact directory:

  * private BBOT home: ``$HOME/.bbot`` (tools/cache/lib/temp/scans; persists per
    workspace, so tools and the module cache are seeded at most once)

    - ``tools``: real writable directory (BBOT requires it) seeded from
      ``/opt/bbot-home/tools``; small binaries are copied, large ones symlinked
    - ``cache``: seeded once from ``/opt/bbot-home/cache``
    - ``logs``, ``scans``: writable workspace state
  * optional ``$HOME/.config/bbot/{bbot.yml,secrets.yml}`` linked from
    ``/opt/bbot-home/config/`` when the workspace has none yet
  * scan output defaults to ``$CSAI_ARTIFACT_DIR/bbot-out``

The dependency installer is always disabled (``--no-deps``): installing module
dependencies needs root, and the prepared runtime mount is read-only.

The existing OS sandbox remains the security boundary; this adapter does not
create one and never falls back to host execution.
"""
import os
import shutil
import sys
import uuid
from pathlib import Path

ADAPTER_VERSION = 1
BBOT_ENTRY = Path("/opt/pipx/venvs/bbot/bin/bbot")
PREPARED_HOME = Path("/opt/bbot-home")
PREPARED_TOOLS = PREPARED_HOME / "tools"
PREPARED_CACHE = PREPARED_HOME / "cache"
PREPARED_CONFIG = PREPARED_HOME / "config"
CACHE_SEED_MARKER = ".csai-cache-seed-v1"
TOOLS_SEED_MARKER = ".csai-tools-seed-v1"
# BBOT checks that its tools directory is writable, so prepared binaries are
# seeded into the workspace home: small files are copied, large vendor binaries
# are symlinked to the read-only runtime instead of being duplicated.
TOOLS_COPY_LIMIT = 8 * 1024 * 1024
OUTPUT_DIR_NAME = "bbot-out"
SANDBOX_ENV = "CSAI_WORKSPACE_SANDBOX"
HELP_FLAG = "--csai-help"
CHECK_FLAG = "--check-runtime"
DEPS_FLAGS = ("--no-deps", "--force-deps", "--retry-deps", "--ignore-failed-deps")

# Printed by --check-runtime; tool-doctor matches declared parameter flags here.
RUNTIME_SYNOPSIS = """\
managed BBOT launcher (sandbox only)
bbot 3.x: recursive OSINT / attack-surface scanner
supported flags:
  -t                 target (domain, IP, CIDR, URL, ORG:name, USER:name)
  -p                 preset(s), space or comma separated
  -m                 scan module(s)
  -rf                require flags (e.g. passive)
  -ef                exclude flags (e.g. loud invasive)
  -n                 scan name (subdirectory of the output dir)
  -c                 config option, dotted key=value (e.g. dns.threads=10)
  -o                 output directory (default: $CSAI_ARTIFACT_DIR/bbot-out)
  --json -j          machine output: JSONL events on stdout
  --brief -br        with --json: only type, data, scope_description
  --event-types      only show the listed event types
  --dry-run          load modules, install nothing, run no scan
  --no-deps          dependency installer disabled (forced by this launcher)
  -y                 non-interactive
  --no-color         plain text
  -l -lp -lf -mh     list modules / presets / flags, module help
run flags:
  --csai-help        this text
  --check-runtime    verify the pipx install and prepared runtime, then exit
"""


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


def artifact_root(environ):
    """Only this execution's managed artifact directory is writable evidence."""
    if environ.get(SANDBOX_ENV) != "1":
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


def ensure_dir(path):
    path = Path(path)
    if path.is_symlink():
        raise AdapterError("symlink_path_rejected: " + str(path))
    path.mkdir(parents=True, exist_ok=True)
    return path


def prepare_home(home):
    """Private writable BBOT home seeded from the read-only prepared runtime."""
    ensure_dir(home)
    seed_tools(home)
    seed_cache(home)
    link_prepared_config()
    return home


def seed_tools(home):
    """Seed the writable BBOT tools directory from the prepared runtime.

    BBOT requires ``tools`` to exist and be writable, so it must not be a
    symlink to the read-only mount. Small binaries are copied; anything larger
    than ``TOOLS_COPY_LIMIT`` is symlinked so vendor tools are never duplicated
    into the workspace.
    """
    tools = home / "tools"
    if tools.is_symlink():
        raise AdapterError("bbot tools directory must not be a symlink: " + str(tools))
    marker = home / TOOLS_SEED_MARKER
    if marker.exists():
        return tools
    ensure_dir(tools)
    if not PREPARED_TOOLS.is_dir():
        # Nothing prepared; BBOT runs with whatever tools it can find in PATH.
        marker.touch()
        return tools
    for source, relative in prepared_tool_entries():
        target = tools / relative
        try:
            if source.is_dir():
                ensure_dir(target)
                continue
            if target.exists() or target.is_symlink():
                continue
            ensure_dir(target.parent)
            if source.stat().st_size <= TOOLS_COPY_LIMIT:
                shutil.copy2(str(source), str(target))
            else:
                target.symlink_to(source)
        except OSError as error:
            raise AdapterError("unable to prepare bbot tools: {}: {}".format(relative, error)) from error
    marker.touch()
    return tools


def prepared_tool_entries():
    """Depth-first entries of the prepared tools dir, skipping symlinks."""
    root = PREPARED_TOOLS
    for dirpath, dirnames, filenames in os.walk(str(root), onerror=lambda _error: None):
        relative = Path(dirpath).relative_to(root)
        for name in sorted(dirnames):
            candidate = Path(dirpath) / name
            if candidate.is_symlink():
                continue
            yield candidate, relative / name
        for name in sorted(filenames):
            candidate = Path(dirpath) / name
            if candidate.is_symlink():
                continue
            yield candidate, relative / name


def cache_seed_files():
    """Leaf cache entries to copy; ansible-runner scratch dirs are skipped.

    Only files BBOT reads back are needed (hash markers, setup_status.json,
    downloaded models). ``depsinstaller/playbook_*`` holds root-owned ansible
    working directories that the sandbox identity cannot read.
    """
    root = PREPARED_CACHE
    for dirpath, dirnames, filenames in os.walk(str(root), onerror=lambda _error: None):
        relative = Path(dirpath).relative_to(root)
        keep = []
        for name in sorted(dirnames):
            child = relative / name
            if child.parts[0] == "depsinstaller" and name.startswith("playbook_"):
                continue
            keep.append(name)
        dirnames[:] = keep
        for name in sorted(filenames):
            yield Path(dirpath) / name, relative / name


def copy_prepared_cache(staging):
    failures = []
    for source, relative in cache_seed_files():
        target = staging / relative
        try:
            ensure_dir(target.parent)
            shutil.copy2(str(source), str(target))
        except OSError as error:
            failures.append("{}: {}".format(relative, error))
    return failures


def seed_cache(home):
    """Copy the prepared module/http cache once per workspace.

    Without it BBOT re-downloads word-prediction models and re-runs the core
    dependency check on every new workspace.
    """
    cache = home / "cache"
    marker = cache / CACHE_SEED_MARKER
    if marker.exists():
        return
    ensure_dir(cache)
    if not PREPARED_CACHE.is_dir():
        # Nothing prepared; BBOT will populate its own cache.
        marker.touch()
        return
    staging = home / (cache.name + ".seed-tmp")
    if staging.exists():
        shutil.rmtree(staging)
    staging.mkdir()
    failures = copy_prepared_cache(staging)
    if failures:
        shutil.rmtree(staging, ignore_errors=True)
        print(
            "[csai] warning: {:,} prepared cache entr(ies) were not readable; "
            "run `chmod -R a+rX {}` during maintenance. BBOT will rebuild its own cache.".format(
                len(failures), PREPARED_CACHE
            ),
            file=sys.stderr,
            flush=True,
        )
        return
    for entry in staging.iterdir():
        target = cache / entry.name
        if target.exists():
            if target.is_dir() and not target.is_symlink():
                shutil.rmtree(target)
            else:
                target.unlink()
        entry.rename(target)
    shutil.rmtree(staging)
    marker.touch()


def link_prepared_config():
    """Central secrets/config for every workspace, unless one already exists."""
    if not PREPARED_CONFIG.is_dir():
        return
    config_dir = Path(os.environ.get("HOME", "")) / ".config" / "bbot"
    ensure_dir(config_dir)
    for name in ("bbot.yml", "secrets.yml"):
        source = PREPARED_CONFIG / name
        target = config_dir / name
        if not source.is_file() or target.exists() or target.is_symlink():
            continue
        target.symlink_to(source)


def _flag_index(argv):
    """Map option name -> indices; used to respect explicit caller options."""
    seen = {}
    for index, token in enumerate(argv):
        if token.startswith("-") and token != "-":
            seen.setdefault(token, []).append(index)
    return seen


# BBOT options that take multiple values. Single-token recipe parameters are
# expanded here so `presets: "subdomain-enum web"` (or comma separated) reaches
# BBOT as two values. Values are never shell-interpreted.
MULTI_VALUE_FLAGS = (
    "-t", "--targets", "-s", "--seeds", "-b", "--blacklist",
    "-p", "--preset", "-m", "--modules", "-em", "--exclude-modules",
    "-rf", "--require-flags", "-ef", "--exclude-flags",
    "-om", "--output-modules", "-eom", "--exclude-output-modules",
    "--event-types",
)
SPLIT_CHARS = " \t,"


def expand_multi_value_args(argv):
    expanded = []
    index = 0
    while index < len(argv):
        token = argv[index]
        expanded.append(token)
        index += 1
        if token not in MULTI_VALUE_FLAGS:
            continue
        while index < len(argv) and not argv[index].startswith("-"):
            for value in argv[index].replace(",", " ").split():
                expanded.append(value)
            index += 1
    return expanded


def inject_managed_args(argv, home, output_dir):
    argv = expand_multi_value_args(argv)
    seen = _flag_index(argv)
    config_values = set()
    for index in list(seen.get("-c", [])) + list(seen.get("--config", [])):
        for value in argv[index + 1:]:
            if value.startswith("-"):
                break
            config_values.add(value)
    if not any(value.startswith("home=") or value == "home" for value in config_values):
        argv += ["-c", "home=" + str(home)]
    if not any(flag in seen for flag in DEPS_FLAGS) and not any(
        value.startswith("deps.behavior") for value in config_values
    ):
        argv.append("--no-deps")
    if "-o" not in seen and "--output-dir" not in seen:
        argv += ["-o", str(output_dir)]
    if "-y" not in seen and "--yes" not in seen:
        argv.append("-y")
    if "--no-color" not in seen:
        argv.append("--no-color")
    return argv


def run_scan(argv):
    if not (BBOT_ENTRY.is_file() and os.access(BBOT_ENTRY, os.X_OK)):
        raise AdapterError("bbot entrypoint not installed: " + str(BBOT_ENTRY))
    root = artifact_root(os.environ)
    home_root = os.environ.get("HOME", "")
    if not home_root:
        raise AdapterError("workspace HOME is required")
    home = prepare_home(no_symlink_path(Path(home_root)) / ".bbot")
    output_dir = ensure_dir(root / OUTPUT_DIR_NAME)
    final_args = inject_managed_args(list(argv), home, output_dir)
    print(
        "[csai] bbot sandbox run\n"
        "[csai] bbot home:  {}\n"
        "[csai] bbot tools: {} (seeded into the workspace home)\n"
        "[csai] output dir: {}\n"
        "[csai] scan dir:   {}/<scan name>/\n"
        "[csai] dependency installer: disabled (prepared runtime)".format(
            home, home / "tools", output_dir, output_dir
        ),
        file=sys.stderr,
        flush=True,
    )
    os.execv(str(BBOT_ENTRY), [str(BBOT_ENTRY)] + final_args)


def check_runtime():
    problems = []
    if not (BBOT_ENTRY.is_file() and os.access(BBOT_ENTRY, os.X_OK)):
        problems.append("missing bbot entrypoint: " + str(BBOT_ENTRY))
    if not PREPARED_TOOLS.is_dir():
        problems.append("missing prepared tools dir: " + str(PREPARED_TOOLS))
    elif not os.access(PREPARED_TOOLS, os.R_OK | os.X_OK):
        problems.append("prepared tools dir is not readable: " + str(PREPARED_TOOLS))
    if not PREPARED_CACHE.is_dir():
        problems.append("missing prepared cache dir (run --install-all-deps): " + str(PREPARED_CACHE))
    print(RUNTIME_SYNOPSIS, flush=True)
    if problems:
        for problem in problems:
            print("[csai] " + problem, file=sys.stderr, flush=True)
        return 1
    print("[csai] runtime ok (adapter v{})".format(ADAPTER_VERSION), flush=True)
    return 0


def main(argv):
    if HELP_FLAG in argv:
        print(RUNTIME_SYNOPSIS, end="")
        return 0
    if CHECK_FLAG in argv:
        return check_runtime()
    if not argv:
        print(RUNTIME_SYNOPSIS, end="", file=sys.stderr)
        return 2
    run_scan(argv)
    return 0  # unreachable: os.execv replaces the process


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except AdapterError as error:
        print("[csai] bbot launcher error: " + str(error), file=sys.stderr, flush=True)
        sys.exit(3)
