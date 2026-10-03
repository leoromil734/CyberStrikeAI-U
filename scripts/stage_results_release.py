#!/usr/bin/env python3
"""Prepare a credential-preserving release; activation is explicit and idle-gated."""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request

import yaml


def command(argv, capture=False):
    return subprocess.run(argv, check=True, text=True, stdout=subprocess.PIPE if capture else None).stdout


def db_count(sql):
    value = command(["docker", "exec", "csai-postgres", "psql", "-U", "cyberstrike", "-d", "cyberstrike", "-Atc", sql], True)
    return int(value.strip())


def assert_idle(args):
    # SQL reads are cluster-local and cover every owner, not just a UI user.
    if db_count("SELECT count(*) FROM tool_executions WHERE status IN ('running','queued')"):
        raise RuntimeError("production tools are active; activation refused")
    if db_count("SELECT count(*) FROM batch_task_queues WHERE status='running'"):
        raise RuntimeError("a batch executor is active; activation refused")
    if db_count("SELECT count(*) FROM tool_executions WHERE start_time > CURRENT_TIMESTAMP - INTERVAL '15 minutes'"):
        raise RuntimeError("recent executions exist; wait for the maintenance window")
    token = os.environ.get("CSAI_ADMIN_BEARER", "")
    if not token:
        raise RuntimeError("CSAI_ADMIN_BEARER is required to inspect in-memory tasks; no login/account is created")
    url = args.api.rstrip("/") + "/api/agent-loop/tasks"
    request = urllib.request.Request(url, headers={"Authorization": "Bearer " + token})
    with urllib.request.urlopen(request, timeout=10) as response:
        payload = json.load(response)
    if not isinstance(payload, dict) or not isinstance(payload.get("tasks"), list):
        raise RuntimeError("cannot verify active task response; activation refused")
    if payload["tasks"]:
        raise RuntimeError("in-memory conversation tasks are active; activation refused")


def merge_recipe(current, proposed, name):
    original = yaml.safe_load(current.read_text(encoding="utf-8"))
    update = yaml.safe_load(proposed.read_text(encoding="utf-8"))
    if not isinstance(original, dict) or original.get("name") != name:
        raise RuntimeError("unexpected deployed recipe; manual review required")
    merged = dict(original)
    if name == "jsapiscan":
        # Preserve command/args/enabled/exit codes and operator defaults.
        existing = {p["name"]: p for p in original.get("parameters", [])}
        parameters = []
        for new in update.get("parameters", []):
            combined = dict(new)
            combined.update(existing.get(new["name"], {}))
            for key in ("minimum", "maximum", "max_items", "conflicts_with"):
                if key in new:
                    combined[key] = new[key]
            parameters.append(combined)
        known = {p["name"] for p in parameters}
        parameters += [p for p in original.get("parameters", []) if p["name"] not in known]
        merged["parameters"] = parameters
        merged["description"] = update.get("description", original.get("description"))
        merged["short_description"] = update.get("short_description", original.get("short_description"))
    elif name == "fofa_search":
        patched = False
        new_args = []
        for value in original.get("args", []):
            if isinstance(value, str) and '"results_count":' in value:
                if re.search(r'"fields"\s*:', value[value.index('"results_count":'):value.index('"results":')]):
                    patched = True
                else:
                    pattern = r'(?m)^(\s*)"results": result_data\.get\(\x27results\x27, \[\]\),$'
                    value, count = re.subn(pattern, lambda m: m.group(1) + '"fields": as_text(params.get(\x27fields\x27, \x27ip,port,domain\x27)).split(\x27,\x27),\n' + m.group(0), value)
                    patched = count == 1
            new_args.append(value)
        if not patched:
            raise RuntimeError("FOFA custom wrapper differs; refusing to replace credentials or dispatch")
        merged["args"] = new_args
    return merged


def atomic_copy(source, target):
    target.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary = tempfile.mkstemp(prefix=".csai-release-", dir=target.parent)
    os.close(handle)
    try:
        shutil.copy2(source, temporary)
        os.replace(temporary, target)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def prepare(args):
    release = args.stage / "release"
    release.mkdir(mode=0o700, parents=True, exist_ok=True)
    for directory in ("internal", "cmd", "web", "skills"):
        target = release / directory
        if target.exists():
            shutil.rmtree(target)
        shutil.copytree(args.source / directory, target)
    target = release / "scripts" / "recon"
    if target.exists():
        shutil.rmtree(target)
    shutil.copytree(args.source / "scripts" / "recon", target, ignore=shutil.ignore_patterns("__pycache__"))
    atomic_copy(args.stage / "bin" / "cyberstrike-ai", release / "cyberstrike-ai")
    tools = release / "tools"
    tools.mkdir(exist_ok=True)
    for name in ("jsapiscan", "fofa_search"):
        merged = merge_recipe(args.production / "tools" / (name + ".yaml"), args.source / "tools" / (name + ".yaml"), name)
        path = tools / (name + ".yaml")
        path.write_text(yaml.safe_dump(merged, allow_unicode=True, sort_keys=False), encoding="utf-8")
        path.chmod(0o600)  # Existing inline recipes can contain credentials.
    print("Release prepared; command paths, operator defaults and credentials preserved. Production unchanged.")


def activate(args):
    if not args.maintenance_confirmed:
        raise RuntimeError("--maintenance-confirmed requires the operator to block new submissions/schedules and confirm a global maintenance window")
    assert_idle(args)
    # Re-merge from the current deployed overrides, not an older stage snapshot.
    prepare(args)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    backup = args.stage / "backups" / ("activation-" + stamp)
    backup.mkdir(mode=0o700, parents=True)
    command(["tar", "-czf", str(backup / "runtime.tar.gz"), "-C", str(args.production), "cyberstrike-ai", "config.yaml", "tools", "scripts/recon", "skills", "web"])
    with (backup / "database.dump").open("wb") as output:
        subprocess.run(["docker", "exec", "csai-postgres", "pg_dump", "-U", "cyberstrike", "-d", "cyberstrike", "-Fc"], stdout=output, check=True)
    assert_idle(args)
    command(["systemctl", "stop", "cyberstrikeai.service"])
    release = args.stage / "release"
    try:
        for directory in ("internal", "cmd", "web", "skills", "scripts/recon"):
            for file in (release / directory).rglob("*"):
                if file.is_file():
                    atomic_copy(file, args.production / file.relative_to(release))
        for name in ("jsapiscan", "fofa_search"):
            atomic_copy(release / "tools" / (name + ".yaml"), args.production / "tools" / (name + ".yaml"))
        atomic_copy(release / "cyberstrike-ai", args.production / "cyberstrike-ai")
        command(["systemctl", "start", "cyberstrikeai.service"])
        command(["systemctl", "is-active", "--quiet", "cyberstrikeai.service"])
    except Exception:
        # Restore runtime only: additive tables can remain; restoring an old DB
        # snapshot would discard newer task history and must never be automatic.
        command(["systemctl", "stop", "cyberstrikeai.service"])
        command(["tar", "-xzf", str(backup / "runtime.tar.gz"), "-C", str(args.production), "cyberstrike-ai", "tools", "scripts/recon", "skills", "web"])
        command(["systemctl", "start", "cyberstrikeai.service"])
        raise
    print("Activation complete. Runtime rollback archive: " + str(backup / "runtime.tar.gz"))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stage", type=Path, required=True)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--production", type=Path, default=Path("/opt/CyberStrikeAI-U"))
    parser.add_argument("--api", default="http://127.0.0.1:8080")
    parser.add_argument("--activate", action="store_true")
    parser.add_argument("--maintenance-confirmed", action="store_true")
    args = parser.parse_args()
    os.umask(0o077)
    try:
        activate(args) if args.activate else prepare(args)
    except Exception as error:
        # Never echo recipes, environment values, Authorization or HTTP bodies.
        print("Release operation refused/failed: " + type(error).__name__, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
