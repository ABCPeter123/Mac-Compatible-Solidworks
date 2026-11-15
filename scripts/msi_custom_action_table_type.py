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
from scripts.netfx40_private_action import ACTION_RE
from scripts.netfx40_msi_custom_type import FAMILIES
from swcompat.wine_paths import windows_media_path

STATUSES = {
    "ACTION_FOUND", "ACTION_ABSENT", "DATABASE_UNAVAILABLE", "TABLE_UNAVAILABLE",
    "QUERY_FAILED", "INVALID_ARGUMENT", "PROCESS_FAILED", "TIMED_OUT",
    "MALFORMED", "BAD_EXIT", "MSI_DLL_UNAVAILABLE", "MSI_EXPORT_UNAVAILABLE",
    "SELFTEST_OK", "INPUT_UNAVAILABLE",
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
            if (value not in STAGES or value == "NOT_OBSERVED"
                    or value in stages or len(stages) >= len(STAGES) - 1):
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
            action: str = "ServiceTypeControlSentinel", *,
            allow_original_action: bool = False) -> dict:
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
    if action not in ACTIONS and not (
            allow_original_action and isinstance(action, str) and action.isascii()
            and ACTION_RE.fullmatch(action.encode("ascii"))):
        raise ValueError("Private original action must be a strict MSI identifier")
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
    # Passing a pipe as stdin to Wine worked differently from the native
    # Windows reference. An exclusively created mode-0600 file avoids that
    # ambiguity. This contains only the test action name (later original
    # identifiers stay private on the disposable runner), and is removed on
    # success, failure, timeout or process-start error.
    action_file = status_file.parent / "swcompat_ca_action_private.input"
    if action_file.exists() or action_file.is_symlink():
        raise ValueError("Existing or linked private action input")
    fd = os.open(action_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(action.encode("utf-8"))
        try:
            result = subprocess.run(
                [str(wine), str(probe), path, windows_status, "--private-file"],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                env=env, cwd=prefix, timeout=25, check=False,
            )
        except subprocess.TimeoutExpired:
            return {"status": "TIMED_OUT", "base_type": None,
                    "family": "NOT_VERIFIED", "stage": "NOT_OBSERVED"}
        except OSError:
            return {"status": "PROCESS_FAILED", "base_type": None,
                    "family": "NOT_VERIFIED", "stage": "NOT_OBSERVED"}
    finally:
        action_file.unlink(missing_ok=True)
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


_BOOTSTRAP_LINES = re.compile(
    rb"SWCOMPAT_CA_BOOT_(ENTRY|ARGC|REPORT)=([A-Z_]+)\Z"
)


def read_bootstrap(prefix: Path) -> dict:
    """Consume *only* fixed Win32 entry breadcrumbs, never vendor metadata."""
    validate_prefix(prefix)
    file = prefix / "drive_c" / "swcompat_ca_bootstrap.status"
    default = {"entry": "NOT_OBSERVED", "argc": "NOT_VERIFIED",
               "report": "NOT_VERIFIED"}
    if file.is_symlink() or file.parent.is_symlink():
        raise ValueError("Linked Win32 bootstrap marker")
    if not file.is_file():
        return default
    try:
        with file.open("rb") as stream:
            raw = stream.read(385)
    finally:
        file.unlink(missing_ok=True)
    if len(raw) > 384:
        return default
    fields = {}
    for line in raw.splitlines():
        m = _BOOTSTRAP_LINES.fullmatch(line.strip())
        if not m:
            return default
        key, value = m.group(1).decode("ascii"), m.group(2).decode("ascii")
        if key in fields:
            return default
        fields[key] = value
    if (fields.get("ENTRY") != "YES"
            or fields.get("ARGC") not in {"THREE", "FOUR", "OTHER"}
            or fields.get("REPORT") not in {"OPEN", "UNAVAILABLE"}
            or len(fields) != 3):
        return default
    return {"entry": "YES", "argc": fields["ARGC"],
            "report": fields["REPORT"]}
