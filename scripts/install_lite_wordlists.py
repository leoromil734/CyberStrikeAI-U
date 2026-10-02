#!/usr/bin/env python3
"""Install bounded lite or standard SecLists subsets; never run downloaded content."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
from datetime import datetime, timezone
import urllib.request

REPOSITORY = "https://github.com/danielmiessler/SecLists"
COMMIT = "bd8f9b5501f9257e9d39c733540e793602c3da6f"
MAX_SOURCE_BYTES = 2 * 1024 * 1024
SOURCES = (
    ("passwords-top100.txt", "Passwords/Common-Credentials/10k-most-common.txt", 100, "password"),
    ("usernames-short.txt", "Usernames/top-usernames-shortlist.txt", 20, "username"),
    ("subdomains-top1000.txt", "Discovery/DNS/subdomains-top1million-5000.txt", 1000, "dns"),
    ("web-paths-top1000.txt", "Discovery/Web-Content/raft-small-directories.txt", 1000, "path"),
    ("api-paths-top150.txt", "Discovery/Web-Content/api/api-endpoints.txt", 150, "path"),
)
STANDARD_SOURCES = (
    ("passwords-top3000.txt", "Passwords/Common-Credentials/10k-most-common.txt", 3000, "password"),
    ("usernames-top500.txt", "Usernames/cirt-default-usernames.txt", 500, "username"),
    ("subdomains-top5000.txt", "Discovery/DNS/subdomains-top1million-20000.txt", 5000, "dns"),
    ("web-paths-top25000.txt", "Discovery/Web-Content/raft-medium-directories.txt", 25000, "path"),
    ("api-paths-top1000.txt", "Discovery/Web-Content/api/api-seen-in-wild.txt", 1000, "path"),
)
PROFILES = {"lite": SOURCES, "standard": STANDARD_SOURCES}
USAGE_LIMITS = {
    "credential": {
        "attempts_per_identity": 8,
        "identities_per_service": 5,
        "candidate_pairs_per_service": 40,
        "seconds_per_service": 300,
        "concurrency": 1,
        "minimum_interval_seconds": 3,
        "stop_on": ["success", "captcha", "mfa", "lockout", "rate_limit", "service_error"],
        "full_username_password_product": False,
    },
    "discovery": {"dns_qps": 10, "http_rps": 5, "seconds_per_asset": 300},
}


def source_url(path):
    return f"https://raw.githubusercontent.com/danielmiessler/SecLists/{COMMIT}/{path}"


def download_source(path):
    request = urllib.request.Request(
        source_url(path), headers={"User-Agent": "CyberStrikeAI-lite-wordlists/1.0"}
    )
    with urllib.request.urlopen(request, timeout=25) as response:
        data = response.read(MAX_SOURCE_BYTES + 1)
        content_type = response.headers.get("Content-Type", "").lower()
    if len(data) > MAX_SOURCE_BYTES:
        raise ValueError(f"source exceeds {MAX_SOURCE_BYTES} bytes: {path}")
    if "text/html" in content_type or data.lstrip().lower().startswith((b"<!doctype html", b"<html")):
        raise ValueError(f"HTML received instead of a dictionary: {path}")
    if b"\0" in data:
        raise ValueError(f"binary source rejected: {path}")
    data.decode("utf-8-sig")  # Fail rather than silently replace invalid bytes.
    return data


def select_entries(data, limit, kind):
    """Preserve upstream ordering while removing empty, duplicate and unsafe lines."""
    result, seen = [], set()
    for raw in data.decode("utf-8-sig").splitlines():
        word = raw.strip()
        if not word or word.startswith("#") or word in seen:
            continue
        if len(word.encode("utf-8")) > 256 or any(ord(char) < 32 or ord(char) == 127 for char in word):
            continue
        if kind == "dns" and not re.fullmatch(r"[a-z0-9][a-z0-9.-]{0,252}", word):
            continue
        if kind in ("path", "username") and any(char.isspace() for char in word):
            continue
        if kind == "path" and ("://" in word or word in (".", "..")):
            continue
        seen.add(word)
        result.append(word)
        if len(result) == limit:
            break
    if not result:
        raise ValueError(f"no usable entries for {kind}")
    return result


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def write_artifact(path, data):
    path.write_bytes(data)
    path.chmod(0o644)


def install(output, downloader=download_source, profile="lite"):
    if profile not in PROFILES:
        raise ValueError(f"unknown dictionary profile: {profile}")
    sources = PROFILES[profile]
    output = Path(output).expanduser().absolute()
    if output.exists() or output.is_symlink():
        raise FileExistsError(f"refusing to overwrite an existing directory: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    manifest = {
        "format_version": 1,
        "profile": profile,
        "repository": REPOSITORY,
        "commit": COMMIT,
        "installed_at": datetime.now(timezone.utc).isoformat(),
        "selection": "upstream-order, unique nonempty lines, hard per-file limits",
        "usage_limits": USAGE_LIMITS,
        "dictionaries": [],
    }
    # Fetch and validate everything before atomically publishing the destination.
    with tempfile.TemporaryDirectory(prefix=".cyberstrike-wordlists-", dir=output.parent) as temp:
        staging = Path(temp) / "release"
        staging.mkdir(mode=0o755)
        for filename, upstream_path, limit, kind in sources:
            original = downloader(upstream_path)
            words = select_entries(original, limit, kind)
            selected = ("\n".join(words) + "\n").encode("utf-8")
            write_artifact(staging / filename, selected)
            manifest["dictionaries"].append({
                "file": filename,
                "purpose": kind,
                "limit": limit,
                "entries": len(words),
                "bytes": len(selected),
                "sha256": sha256(selected),
                "source_url": source_url(upstream_path),
                "source_bytes": len(original),
                "source_sha256": sha256(original),
            })
        license_data = downloader("LICENSE")
        if not license_data.strip():
            raise ValueError("upstream license is empty")
        write_artifact(staging / "LICENSE.SecLists", license_data)
        manifest["license"] = {
            "file": "LICENSE.SecLists", "url": source_url("LICENSE"), "sha256": sha256(license_data)
        }
        manifest["total_entries"] = sum(item["entries"] for item in manifest["dictionaries"])
        manifest["total_dictionary_bytes"] = sum(item["bytes"] for item in manifest["dictionaries"])
        write_artifact(staging / "manifest.json", (json.dumps(manifest, ensure_ascii=False, indent=2) + "\n").encode("utf-8"))
        write_artifact(staging / "README.txt", (
            f"Pinned SecLists subset ({profile}) for authorized, bounded testing.\n"
            "Read manifest.json for source URLs, hashes, counts and usage limits.\n"
            "Credential lists are candidate pools, NOT permission to try every entry.\n"
            "Use known/default identities only; never run the full -L x -P product.\n"
            "8 attempts/identity, 5 identities/40 pairs/300 seconds/service maximum.\n"
            "Concurrency 1, interval >=3 seconds; stricter task/lockout limits win.\n"
            "Stop on success, challenge, MFA, lockout, rate limit or service errors.\n"
            "A dictionary can contain legitimate weak words; do not execute its content.\n"
        ).encode("utf-8"))
        if output.exists() or output.is_symlink():
            raise FileExistsError(f"destination appeared during installation: {output}")
        os.rename(staging, output)
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=tuple(PROFILES), default="standard", help="standard is the normal candidate pool; lite is a quick subset")
    parser.add_argument("--output", help="new destination; default /opt/wordlists/cyberstrike-<profile>; never overwrites existing paths")
    args = parser.parse_args()
    output = args.output or f"/opt/wordlists/cyberstrike-{args.profile}"
    try:
        manifest = install(output, profile=args.profile)
    except (OSError, ValueError) as exc:
        parser.exit(1, f"installation failed: {exc}\n")
    print(f"Installed {len(manifest['dictionaries'])} {args.profile} dictionaries in {Path(output).absolute()}")
    for item in manifest["dictionaries"]:
        print(f"{item['file']}: {item['entries']} entries, {item['bytes']} bytes, sha256={item['sha256']}")
    print(f"TOTAL: {manifest['total_entries']} entries, {manifest['total_dictionary_bytes']} dictionary bytes")


if __name__ == "__main__":
    main()
