"""Strict metadata-only MSI CustomAction Type lookup through Windows MSI APIs.

Never send action names in argv or published reports. The test uses the original
self-authored MSI; the same tool can later inspect available original Microsoft
MSI media in a disposable Wine prefix, if and only if those files exist.
"""
from __future__ import annotations

import os
from pathlib import Path
import re
import subprocess

from scripts.netfx481_trial import validate_prefix
from scripts.netfx40_msi_custom_type import FAMILIES
from swcompat.wine_paths import windows_media_path

STATUSES = {
    "ACTION_FOUND", "ACTION_ABSENT", "DATABASE_UNAVAILABLE", "TABLE_UNAVAILABLE",
    "QUERY_FAILED", "INVALID_ARGUMENT", "PROCESS_FAILED", "TIMED_OUT",
    "MALFORMED", "BAD_EXIT", "MSI_DLL_UNAVAILABLE", "MSI_EXPORT_UNAVAILABLE",
    "SELFTEST_OK",
}
LINE = re.compile(rb"SWCOMPAT_CA_TABLE_(STATUS|TYPE|STAGE)=([A-Z_]+|[0-9]{1,10})\Z")
STAGES = {
    "NOT_OBSERVED", "ENTRY", "INPUT_OK", "MSI_DLL_LOADED", "MSI_EXPORTS_READY",
    "DATABASE_OPEN", "VIEW_OPEN",
    "PARAMETER_SET", "VIEW_EXECUTED", "ROW_FETCHED", "SELFTEST",
}
ACTIONS = {"ServiceTypeControlSentinel"}


def parse(raw: bytes, code: int) -> dict:
    r = {"status": "MALFORMED", "base_type": None,
         "family": "NOT_VERIFIED", "stage": "NOT_OBSERVED"}
    if not isinstance(raw, bytes) or len(raw) > 2048:
        return r
    fields: dict[str, str] = {}
    stage = "NOT_OBSERVED"
    stages = []
    for line in raw.splitlines():
        found = LINE.fullmatch(line.strip())
        if not found:
            return r
        key = found.group(1).decode("ascii")
        value = found.group(2).decode("ascii")
        if key == "STAGE":
            if value not in STAGES or value == "NOT_OBSERVED" or len(stages) >= 8:
                return r
            stages.append(value)
            stage = value
        else:
            if key in fields:
                return r
            fields[key] = value
    if code != 0:
        return {**r, "status": "BAD_EXIT", "stage": stage}
    if set(fields) != {"STATUS", "TYPE"} or fields["STATUS"] not in STATUSES:
        return {**r, "stage": stage}
    value = int(fields["TYPE"]) if fields["TYPE"].isdigit() else -1
    if fields["STATUS"] == "ACTION_FOUND":
        if not 0 <= value <= 65535:
            return {**r, "stage": stage}
        base = value & 0x3F
        return {"status": "ACTION_FOUND", "base_type": base,
                "family": FAMILIES.get(base, "OTHER_TYPE"), "stage": stage}
    if value == 0:
        return {"status": fields["STATUS"], "base_type": None,
                "family": "NOT_VERIFIED", "stage": stage}
    return {**r, "stage": stage}


def validate(report: dict) -> bool:
    if type(report) is not dict or set(report) != {"status", "base_type", "family", "stage"}:
        return False
    if report["status"] not in STATUSES or report["stage"] not in STAGES:
        return False
    if report["status"] != "ACTION_FOUND":
        return report["base_type"] is None and report["family"] == "NOT_VERIFIED"
    return (type(report["base_type"]) is int
            and 0 <= report["base_type"] <= 63
            and report["family"] == FAMILIES.get(report["base_type"], "OTHER_TYPE"))


def inspect(wine: Path, prefix: Path, probe: Path, msi: Path,
            action: str = "ServiceTypeControlSentinel") -> dict:
    if os.name == "nt":
        raise ValueError("Use native Windows probe directly")
    if any(p.is_symlink() for p in (wine, prefix, probe, msi)):
        raise ValueError("Do not follow linked MSI/probe/prefix")
    # subprocess uses cwd=prefix. Always resolve the Win32 helper before
    # changing the cwd, or Wine looks for build/probe.exe under the prefix.
    wine, prefix, probe, msi = (
        p.resolve(strict=True) for p in (wine, prefix, probe, msi)
    )
    validate_prefix(prefix)
    if action not in ACTIONS:
        raise ValueError("Control only accepts known self-authored action")
    if probe.name != "msi_custom_action_table_probe.exe" or not probe.is_file():
        raise ValueError("Expected original Win32 metadata probe")
    if not msi.is_file():
        raise ValueError("Expected original self-authored MSI")
    path = windows_media_path(wine, prefix, msi)
    # A fixed marker-only file is a fallback when Wine's Win32 console
    # does not forward stdout. Never store action names or raw MSI data.
    status_file = prefix / "drive_c" / "windows" / "temp" / "swcompat_ca_table_probe.status"
    if status_file.is_symlink() or status_file.parent.is_symlink():
        raise ValueError("Reject linked Win32 status output")
    status_file.parent.mkdir(parents=True, exist_ok=True)
    if status_file.exists():
        status_file.unlink()
    windows_status = r"C:\windows\temp\swcompat_ca_table_probe.status"
    env = os.environ.copy()
    env.update({"WINEPREFIX": str(prefix), "WINEARCH": "win64", "WINEDEBUG": "-all"})
    try:
        result = subprocess.run(
            [str(wine), str(probe), path, windows_status], input=action.encode("utf-8"),
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            env=env, cwd=prefix, timeout=25, check=False,
        )
    except subprocess.TimeoutExpired:
        return {"status": "TIMED_OUT", "base_type": None, "family": "NOT_VERIFIED", "stage": "NOT_OBSERVED"}
    except OSError:
        return {"status": "PROCESS_FAILED", "base_type": None, "family": "NOT_VERIFIED", "stage": "NOT_OBSERVED"}
    raw = result.stdout
    if status_file.is_file() and not status_file.is_symlink():
        try:
            with status_file.open("rb") as f:
                raw = f.read(2049)
        finally:
            status_file.unlink(missing_ok=True)
    return parse(raw, result.returncode)


def inspect_selftest(wine: Path, prefix: Path, probe: Path) -> dict:
    """Read-only executable-start smoke before any original MSI API is used."""
    if os.name == "nt" or any(p.is_symlink() for p in (wine, prefix, probe)):
        raise ValueError("Selftest requires non-linked Wine paths")
    wine, prefix, probe = (p.resolve(strict=True) for p in (wine, prefix, probe))
    validate_prefix(prefix)
    if probe.name != "msi_custom_action_table_probe.exe" or not probe.is_file():
        raise ValueError("Expected original Win32 MSI metadata helper")
    status_file = prefix / "drive_c" / "windows" / "temp" / "swcompat_ca_table_probe.status"
    if status_file.is_symlink() or status_file.parent.is_symlink():
        raise ValueError("Linked status path not allowed")
    status_file.parent.mkdir(parents=True, exist_ok=True)
    status_file.unlink(missing_ok=True)
    env = os.environ.copy()
    env.update({"WINEPREFIX": str(prefix), "WINEARCH": "win64", "WINEDEBUG": "-all"})
    try:
        child = subprocess.run(
            [str(wine), str(probe), "--selftest",
             r"C:\windows\temp\swcompat_ca_table_probe.status"],
            cwd=prefix, env=env, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            timeout=20, check=False,
        )
    except subprocess.TimeoutExpired:
        return {"status": "TIMED_OUT", "family": "NOT_VERIFIED",
                "base_type": None, "stage": "NOT_OBSERVED"}
    except OSError:
        return {"status": "PROCESS_FAILED", "family": "NOT_VERIFIED",
                "base_type": None, "stage": "NOT_OBSERVED"}
    raw = child.stdout
    if status_file.is_file() and not status_file.is_symlink():
        try:
            with status_file.open("rb") as f:
                raw = f.read(2049)
        finally:
            status_file.unlink(missing_ok=True)
    return parse(raw, child.returncode)
