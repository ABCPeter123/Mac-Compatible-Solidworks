"""Read-only bounded census of retained MSI candidates in original .NET Wine TEMP.

A filename or MSI signature candidate is NOT proof of Microsoft authenticity.
Do not publish names, paths, MSI contents, registry identifiers, vendor data.
"""
from __future__ import annotations

import os
from pathlib import Path
import re

from scripts.netfx481_trial import validate_prefix

MAX_DIRS = 144
MAX_DEPTH = 7
MAX_FILES = 600
MAX_MATCHES = 24
MAX_ROOT_HASH_DIRS = 12
MAX_FILE_SIZE = 200 * 1024 * 1024
STATE = {"NOT_REQUESTED", "ABSENT", "CANDIDATE_PRESENT",
         "PARTIAL_SCAN", "INVALID_ROOT"}
FAMILY = {"NETFX_NAMED", "OTHER_MSI"}
SAFE_FILENAME = re.compile(r"(?i)^[a-z0-9_. -]{1,110}\.msi\Z")
ROOT_HASH_FOLDER = re.compile(r"(?i)^[a-f0-9]{10,40}\Z")


def empty() -> dict:
    return {"status": "NOT_REQUESTED", "msi_candidates": 0,
            "netfx_named_candidates": 0, "directories_checked": 0,
            "file_entries_checked": 0}


def validate(result: dict) -> bool:
    if type(result) is not dict or set(result) != {
        "status", "msi_candidates", "netfx_named_candidates",
        "directories_checked", "file_entries_checked",
    }:
        return False
    if (result["status"] not in STATE
            or any(type(result[field]) is not int for field in (
                "msi_candidates", "netfx_named_candidates",
                "directories_checked", "file_entries_checked"))):
        return False
    n, v = result["msi_candidates"], result["netfx_named_candidates"]
    if (not 0 <= v <= n <= MAX_MATCHES
            or not 0 <= result["directories_checked"] <= MAX_DIRS
            or not 0 <= result["file_entries_checked"] <= MAX_FILES):
        return False
    if result["status"] == "NOT_REQUESTED":
        return result == empty()
    if result["status"] == "ABSENT":
        return n == 0
    if result["status"] == "CANDIDATE_PRESENT":
        return n > 0
    return True


def scan(prefix: Path) -> dict:
    validate_prefix(prefix)
    drive_c = prefix / "drive_c"
    roots = [
        drive_c / "windows" / "temp",
        drive_c / "windows" / "Temp",
        drive_c / "Temp",
        drive_c / "temp",
        drive_c / "users",
    ]
    result = {**empty(), "status": "ABSENT"}
    visited: set[Path] = set()
    partial = False
    invalid = False
    # Actual Microsoft .NET 4.0 offline installers may extract MSIs into
    # C:\\<random-hex> rather than %TEMP%. Include only strict immediate
    # hash-named directories inside this marked prefix, never drive roots
    # mounted elsewhere or arbitrary user-selected media directories.
    if drive_c.is_symlink():
        return {**result, "status": "INVALID_ROOT"}
    if not drive_c.exists():
        return result
    if not drive_c.is_dir():
        return {**result, "status": "INVALID_ROOT"}
    try:
        hash_dirs = [
            item for item in drive_c.iterdir()
            if ROOT_HASH_FOLDER.fullmatch(item.name)
            and not item.is_symlink() and item.is_dir()
        ]
        if len(hash_dirs) > MAX_ROOT_HASH_DIRS:
            partial = True
        roots = sorted(hash_dirs, key=lambda x: x.name)[:MAX_ROOT_HASH_DIRS] + roots
    except OSError:
        partial = True
    for root in roots:
        if not root.exists():
            continue
        if root.is_symlink() or not root.is_dir():
            invalid = True
            continue
        for base, subdirs, names in os.walk(root, topdown=True, followlinks=False):
            current = Path(base)
            try:
                actual = current.resolve(strict=True)
            except OSError:
                partial = True
                subdirs.clear()
                continue
            if actual in visited:
                subdirs.clear()
                continue
            visited.add(actual)
            if result["directories_checked"] >= MAX_DIRS:
                partial = True
                subdirs.clear()
                break
            result["directories_checked"] += 1
            if len(current.relative_to(root).parts) >= MAX_DEPTH:
                subdirs.clear()
            else:
                subdirs[:] = sorted(
                    n for n in subdirs if not (current / n).is_symlink()
                )[:20]
            for name in sorted(names):
                if result["file_entries_checked"] >= MAX_FILES:
                    partial = True
                    break
                result["file_entries_checked"] += 1
                if not SAFE_FILENAME.fullmatch(name):
                    continue
                file = current / name
                if file.is_symlink() or not file.is_file():
                    continue
                try:
                    size = file.stat().st_size
                except OSError:
                    partial = True
                    continue
                if not 4096 <= size <= MAX_FILE_SIZE:
                    continue
                if result["msi_candidates"] >= MAX_MATCHES:
                    partial = True
                    break
                result["msi_candidates"] += 1
                if name.lower().startswith(("netfx", "netframework", "dotnet")):
                    result["netfx_named_candidates"] += 1
            if (result["file_entries_checked"] >= MAX_FILES
                    or result["msi_candidates"] >= MAX_MATCHES):
                partial = True
                break

    result["status"] = (
        "PARTIAL_SCAN" if partial else
        "INVALID_ROOT" if invalid else
        "CANDIDATE_PRESENT" if result["msi_candidates"] else "ABSENT"
    )
    return result
