#!/usr/bin/env python3
"""Idempotently prepare an installed OneForAll for a read-only runtime.

This installation-only command never imports OneForAll, installs dependencies,
starts services, or makes network requests. Unknown upstream layouts fail closed.
"""
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import shlex
import stat
import sys
import tempfile

try:
    from . import oneforall_runner as runtime
except ImportError:
    import oneforall_runner as runtime

IMPORT = "import oneforall_runner as _csai  # CSAI read-only runtime adapter v1\n"


def replace_node(source, node, replacement):
    if node.lineno != node.end_lineno:
        raise runtime.AdapterError("unsupported_multiline_upstream_statement; manual review required")
    # All transformed statements are ASCII before any trailing comments.
    lines = source.splitlines(keepends=True)
    line = lines[node.lineno - 1]
    raw = line.encode("utf-8")
    lines[node.lineno - 1] = (raw[:node.col_offset] + replacement.encode("utf-8") + raw[node.end_col_offset:]).decode("utf-8")
    return "".join(lines)


def expression_shape(text):
    return ast.dump(ast.parse(text, mode="eval").body)


def replace_path_assignment(source, name, directory):
    tree = ast.parse(source)
    nodes = [node for node in tree.body if isinstance(node, ast.Assign)
             and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)
             and node.targets[0].id == name]
    if len(nodes) != 1:
        raise runtime.AdapterError(f"unsupported_upstream_assignment: {name}; manual review required")
    node = nodes[0]
    expected = f"relative_directory.joinpath('{directory}')"
    replacement = f"_csai.runtime_path('{directory}')"
    shape = ast.dump(node.value)
    if shape == expression_shape(replacement):
        return source
    if shape != expression_shape(expected):
        raise runtime.AdapterError(f"custom_or_changed_path_assignment: {name}; refusing to overwrite operator configuration")
    return replace_node(source, node, f"{name} = {replacement}")


def replace_massdns_chmod(source):
    functions = [node for node in ast.parse(source).body if isinstance(node, ast.FunctionDef)
                 and node.name == "get_massdns_path"]
    if len(functions) != 1:
        raise runtime.AdapterError("unsupported_get_massdns_path; manual review required")
    old, new = "path.chmod(S_IXUSR)", "_csai.require_massdns_executable(path)"
    nodes = [node for node in ast.walk(functions[0]) if isinstance(node, ast.Expr)
             and ast.dump(node.value) in (expression_shape(old), expression_shape(new))]
    if len(nodes) != 1:
        raise runtime.AdapterError("unsupported_massdns_chmod; manual review required")
    return replace_node(source, nodes[0], new)


def add_import(source):
    if IMPORT in source:
        return source
    tree = ast.parse(source)
    # Preserve encoding declaration, module docstring and future imports.
    offset = 0
    for node in tree.body:
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            offset = node.end_lineno
        elif isinstance(node, ast.ImportFrom) and node.module == "__future__":
            offset = node.end_lineno
        else:
            offset = max(offset, node.lineno - 1)
            break
    lines = source.splitlines(keepends=True)
    lines.insert(offset, IMPORT)
    return "".join(lines)


def build_plan(installation):
    installation = runtime.no_symlink_path(installation)
    if not runtime.no_symlink_path(installation / "oneforall.py").is_file():
        raise runtime.AdapterError("oneforall.py_missing; expected an existing upstream installation")
    patches = {
        "common/utils.py": (),
        "config/default.py": (("data_storage_dir", "data"), ("result_save_dir", "results")),
        "config/setting.py": (("data_storage_dir", "data"),),
        "config/log.py": (("result_save_dir", "results"),),
    }
    plan = {}
    for relative, assignments in patches.items():
        path = runtime.no_symlink_path(installation / relative)
        source = path.read_text(encoding="utf-8")
        if relative == "common/utils.py":
            source = replace_massdns_chmod(source)
        for name, directory in assignments:
            source = replace_path_assignment(source, name, directory)
        source = add_import(source)
        compile(source, relative, "exec")  # Syntax only: never executes upstream.
        plan[relative] = source.encode("utf-8")
    plan["oneforall_runner.py"] = Path(runtime.__file__).read_bytes()
    binary = runtime.no_symlink_path(runtime.massdns_path(installation))
    if not binary.is_file():
        raise runtime.AdapterError("massdns_for_host_architecture_missing; install a trusted compatible binary before preparation")
    return plan, binary


def atomic_write(path, content, mode):
    runtime.no_symlink_path(path)
    fd, temporary = tempfile.mkstemp(prefix=".csai-prepare-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(content)
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def prepare(installation, python, launcher=None, check=False):
    installation = runtime.no_symlink_path(Path(installation).absolute())
    # Preserve the venv path itself; resolve() would turn its python symlink
    # into the system interpreter and silently lose installed dependencies.
    python = Path(python).absolute()
    if not python.is_file() or not os.access(python, os.X_OK):
        raise runtime.AdapterError("existing_venv_python_required")
    plan, binary = build_plan(installation)
    launcher_bytes = ("#!/bin/sh\n# CyberStrikeAI managed OneForAll; preserve sandbox and venv\n"
                      "export PYTHONDONTWRITEBYTECODE=1\nexec " + shlex.quote(str(python)) + " -B " +
                      shlex.quote(str(installation / "oneforall_runner.py")) + ' "$@"\n').encode("utf-8")
    if launcher is not None:
        launcher = runtime.no_symlink_path(Path(launcher).absolute())
        if not launcher.parent.is_dir():
            raise runtime.AdapterError("launcher_parent_directory_missing")
        if launcher.exists() and not launcher.is_file():
            raise runtime.AdapterError("launcher_must_be_a_regular_file")
    if check:
        runtime.validate_installation(installation)
        if any((installation / name).read_bytes() != content for name, content in plan.items()):
            raise runtime.AdapterError("installed_adapter_is_outdated")
        if launcher is not None and (not launcher.is_file() or launcher.read_bytes() != launcher_bytes or not os.access(launcher, os.X_OK)):
            raise runtime.AdapterError("managed_launcher_missing_or_outdated")
        return
    # Validate every source before changing any installation file. Preserve a
    # first-use backup; never touch config/api.py, requirements, venv or git.
    for relative, content in plan.items():
        path = runtime.no_symlink_path(installation / relative)
        mode = 0o644
        if path.exists():
            mode = stat.S_IMODE(path.stat().st_mode)
            if path.read_bytes() == content:
                continue
            backup = runtime.no_symlink_path(path.with_name(path.name + ".csai-original"))
            if not backup.exists():
                atomic_write(backup, path.read_bytes(), 0o600)
        atomic_write(path, content, mode)
    # Only the installation phase changes this file's permissions. Restoring
    # 0755 also repairs upstream's chmod(0100), which can remove read/other-x.
    binary.chmod(0o755)
    manifest = {"adapter_version": runtime.ADAPTER_VERSION,
                "sha256": {name: hashlib.sha256(content).hexdigest() for name, content in plan.items()}}
    atomic_write(installation / runtime.MANIFEST, (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode(), 0o644)
    if launcher is not None:
        if launcher.is_file() and launcher.read_bytes() != launcher_bytes:
            backup = runtime.no_symlink_path(launcher.with_name(launcher.name + ".csai-original"))
            if not backup.exists():
                atomic_write(backup, launcher.read_bytes(), 0o600)
        atomic_write(launcher, launcher_bytes, 0o755)
    runtime.validate_installation(installation)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--install-dir", type=Path, default=Path("/opt/OneForAll"))
    parser.add_argument("--python", type=Path, required=True, help="existing venv python path (preserved, not resolved)")
    parser.add_argument("--launcher", type=Path, help="installation-time destination, normally /usr/local/bin/oneforall")
    parser.add_argument("--check", action="store_true", help="read-only verification; no upstream imports or network")
    args = parser.parse_args(argv)
    try:
        prepare(args.install_dir, args.python, args.launcher, args.check)
    except (runtime.AdapterError, OSError, SyntaxError) as error:
        detail = str(error) if isinstance(error, runtime.AdapterError) else type(error).__name__
        print("OneForAll preparation failed: " + detail, file=sys.stderr)
        return 1
    print("OneForAll read-only runtime adapter " + ("verified" if args.check else "prepared") + "; no scan or service activation performed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
