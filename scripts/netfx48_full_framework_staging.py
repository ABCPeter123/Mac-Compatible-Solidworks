"""Reversibly stage genuine x64 4.8 components matching existing native 4.0.

Only previously SHA256/Authenticode-validated Microsoft MZZ payloads qualify.
The installed 4.0 Framework64 DLL names form a strict local allowlist. A PE
architecture check is enforced by the existing original MZZ stager. No GAC,
registry, installer, license files or unrelated directories are modified.
"""
from __future__ import annotations

from pathlib import Path
import re
import subprocess
import tempfile

from scripts.netfx48_signed_mzz_dependency_staging import (
    MAX_CLR, MAX_IMPORTS, MAX_LIST, MAX_MZZ, candidates, mzz_members,
    stage, valid as valid_batch,
)
from scripts.netfx48_x64_compatible_pe import compatible_x64

MAX_FRAMEWORK_DLLS = 160
MAX_ROOT_ENTRIES = 1500
DLL = re.compile(r"[a-z0-9_.-]{1,90}\.dll\Z")
STATES = {"NOT_RUN", "NO_MATCH", "STAGED", "INCOMPLETE", "BOUNDED", "ERROR"}


def blank() -> dict:
    return {"status": "NOT_RUN", "candidates": 0, "additional": 0,
            "staged": 0, "framework48_installed": False}


def valid(report: object) -> bool:
    if type(report) is not dict or set(report) != set(blank()):
        return False
    if (report["status"] not in STATES
            or any(type(report[k]) is not int or not 0 <= report[k] <= MAX_FRAMEWORK_DLLS
                   for k in ("candidates", "additional", "staged"))
            or not report["staged"] <= report["additional"] <= report["candidates"]
            or report["framework48_installed"] is not False):
        return False
    if report["status"] == "NOT_RUN":
        return report == blank()
    if report["status"] == "NO_MATCH":
        return report["candidates"] == report["additional"] == report["staged"] == 0
    if report["status"] == "STAGED":
        return report["candidates"] > 0 and report["staged"] == report["additional"]
    if report["status"] == "INCOMPLETE":
        return report["staged"] < report["additional"]
    return True


def matching(root: Path, private: Path, sevenzip: Path) -> dict[str, str] | None:
    """Identify only pre-existing Framework64 DLLs with signed-MZZ x64 names.

    Return None if the inventory is ambiguous or incomplete, never silently
    pretend a bounded prefix contains a complete coherent framework.
    """
    archives = private / "archives"
    if (root.is_symlink() or not root.is_dir()
            or private.is_symlink() or not private.is_dir()
            or archives.is_symlink() or not archives.is_dir()
            or sevenzip.is_symlink() or not sevenzip.is_file()
            or not sevenzip.exists()):
        raise ValueError("Unsafe original x64 framework archive boundary")
    members: set[str] = set()
    files = sorted(archives.iterdir())
    if len(files) > MAX_MZZ or any(p.is_symlink() or not p.is_file() for p in files):
        return None
    mzz_files = [p for p in files if p.suffix.casefold() == ".mzz"]
    if not mzz_files:
        return {}
    for archive in mzz_files:
        with tempfile.TemporaryFile() as stdout:
            try:
                proc = subprocess.run(
                    [str(sevenzip), "l", "-slt", str(archive)],
                    cwd=private, stdin=subprocess.DEVNULL,
                    stdout=stdout, stderr=subprocess.DEVNULL,
                    timeout=60, check=False)
                stdout.seek(0)
                listing = stdout.read(MAX_LIST + 1)
            except (OSError, subprocess.TimeoutExpired):
                return None
        if proc.returncode != 0 or len(listing) > MAX_LIST:
            return None
        names = mzz_members(listing)
        if not names:
            return None
        members.update(names)
    installed = sorted(root.iterdir())
    if len(installed) > MAX_ROOT_ENTRIES:
        return None
    eligible: dict[str, str] = {}
    for entry in installed:
        canonical = entry.name.casefold()
        if not DLL.fullmatch(canonical):
            continue
        if entry.is_symlink() or not entry.is_file():
            return None
        if any(alias in members for alias in candidates(canonical)):
            if canonical in eligible:
                return None
            eligible[canonical] = entry.name
            if len(eligible) > MAX_FRAMEWORK_DLLS:
                return None
    return eligible


def trusted_staged_source(path: Path) -> bool:
    """Check staged PE bytes, not just presence, before reusing prior MZZ files.

    Stage only from previously authenticated Microsoft installer archives;
    never accept an arbitrary file just because it has a Framework DLL name.
    """
    if path.is_symlink():
        return False
    try:
        if not path.is_file() or not 512 <= path.stat().st_size <= MAX_CLR:
            return False
        with path.open("rb") as stream:
            return compatible_x64(stream.read(65536), allow_anycpu=True)
    except OSError:
        return False


def stage_matching(root: Path, private: Path, sevenzip: Path) -> tuple[dict, dict[str, str]]:
    """Stage x64 matches, but do not replace runtime files or touch registry."""
    names = matching(root, private, sevenzip)
    result = blank()
    if names is None:
        result["status"] = "BOUNDED"
        return result, {}
    result["candidates"] = len(names)
    if not names:
        result["status"] = "NO_MATCH"
        return result, {}
    # A previous narrow CLR arm may have written a file in this ephemeral
    # directory. Presence alone never proves it is a complete x64/ILONLY
    # original Microsoft payload. If a regular cached member is invalid,
    # discard it and extract it afresh from the same authenticated MZZ.
    # Refuse linked/nonregular source paths rather than following them.
    missing: list[str] = []
    for name in names.keys():
        prior = private / name
        if prior.is_symlink() or (prior.exists() and not prior.is_file()):
            result["status"] = "ERROR"
            return result, {}
        if not trusted_staged_source(prior):
            if prior.exists():
                try:
                    prior.unlink()
                except OSError:
                    result["status"] = "ERROR"
                    return result, {}
            missing.append(name)
    result["additional"] = len(missing)
    for start in range(0, len(missing), MAX_IMPORTS):
        batch = stage(private, sevenzip, missing[start:start + MAX_IMPORTS],
                      allow_managed_anycpu=True)
        if not valid_batch(batch):
            result["status"] = "ERROR"
            return result, {}
        result["staged"] += batch["staged"]
    # The staging helper's fixed-count report is necessary but insufficient:
    # do not claim a coherent set unless every source actually exists and
    # passes the same PE architecture bound as the replacement transaction.
    if result["staged"] == result["additional"] and any(
            not trusted_staged_source(private / name) for name in names):
        result["status"] = "ERROR"
        return result, {}
    result["status"] = ("STAGED" if result["additional"] == result["staged"]
                        else "INCOMPLETE")
    assert valid(result)
    return result, names
