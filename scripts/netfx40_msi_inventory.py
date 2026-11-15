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
MAX_FILE_SIZE = 200 * 1024 * 1024
STATE = {"NOT_REQUESTED", "ABSENT", "CANDIDATE_PRESENT",
         "PARTIAL_SCAN", "INVALID_ROOT"}
FAMILY = {"NETFX_NAMED", "OTHER_MSI"}
SAFE_FILENAME = re.compile(r"(?i)^[a-z0-9_. -]{1,110}\.msi\Z")


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
    roots = [
        prefix / "drive_c" / "users",
        prefix / "drive_c" / "windows" / "temp",
        prefix / "drive_c" / "windows" / "Temp",
        prefix / "drive_c" / "Temp",
        prefix / "drive_c" / "temp",
    ]
    result = {**empty(), "status": "ABSENT"}
    visited: set[Path] = set()
    partial = False
    invalid = False
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
