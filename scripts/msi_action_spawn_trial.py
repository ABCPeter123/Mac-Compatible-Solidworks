"""Strict self-authored CreateProcessW smoke for Wine MSI metadata helper startup.

The launcher reports only enums, never command lines or filenames. The
original Windows MSI database is not touched by this process-start probe.
"""
from __future__ import annotations

import os
from pathlib import Path
import re
import subprocess

from scripts.netfx481_trial import validate_prefix
from swcompat.wine_paths import windows_media_path

STATUS = {"STARTED", "START_FAILED", "WAIT_FAILED", "TIMED_OUT",
          "INVALID_ARGUMENT", "BAD_EXIT", "MALFORMED", "PROCESS_FAILED"}
EXITS = {"ZERO", "NONZERO", "NOT_VERIFIED"}
ERRORS = {"NONE", "FILE_NOT_FOUND", "INVALID_IMAGE",
          "DEPENDENCY_MISSING", "OTHER_WIN32"}
LINE = re.compile(rb"SWCOMPAT_SPAWN_(STATUS|CHILD_EXIT|ERROR)=([A-Z_]+)\Z")


def parse(raw: bytes, exit_code: int) -> dict:
    malformed = {"status": "MALFORMED", "child_exit": "NOT_VERIFIED", "error": "NONE"}
    if type(raw) is not bytes or len(raw) > 1024:
        return malformed
    entries = {}
    for line in raw.splitlines():
        m = LINE.fullmatch(line.strip())
        if not m:
            return malformed
        key, value = m.group(1).decode(), m.group(2).decode()
        if key in entries:
            return malformed
        entries[key] = value
    if exit_code != 0:
        return {**malformed, "status": "BAD_EXIT"}
    if set(entries) != {"STATUS", "CHILD_EXIT", "ERROR"}:
        return malformed
    result = {"status": entries["STATUS"], "child_exit": entries["CHILD_EXIT"],
              "error": entries["ERROR"]}
    return result if validate(result) else malformed


def validate(result: dict) -> bool:
    if type(result) is not dict or set(result) != {"status", "child_exit", "error"}:
        return False
    if (result["status"] not in STATUS or result["child_exit"] not in EXITS
            or result["error"] not in ERRORS):
        return False
    if result["status"] == "STARTED":
        return result["child_exit"] in {"ZERO", "NONZERO"} and result["error"] == "NONE"
    if result["status"] == "START_FAILED":
        return result["child_exit"] == "NOT_VERIFIED" and result["error"] != "NONE"
    return result["child_exit"] == "NOT_VERIFIED" and result["error"] == "NONE"


def inspect(wine: Path, prefix: Path, launcher: Path, probe: Path) -> dict:
    if os.name == "nt" or any(p.is_symlink() for p in (wine, prefix, launcher, probe)):
        raise ValueError("Only unlinked disposable Wine experiment allowed")
    wine, prefix, launcher, probe = (
        p.resolve(strict=True) for p in (wine, prefix, launcher, probe)
    )
    validate_prefix(prefix)
    if launcher.name != "msi_action_spawn_probe.exe" or not launcher.is_file():
        raise ValueError("Unexpected native Win32 launcher")
    if probe.name != "msi_custom_action_table_probe.exe" or not probe.is_file():
        raise ValueError("Unexpected native Win32 target")
    target = windows_media_path(wine, prefix, probe)
    status_file = prefix / "drive_c" / "windows" / "temp" / "swcompat_ca_spawn.status"
    if status_file.is_symlink() or status_file.parent.is_symlink():
        raise ValueError("Linked status file")
    status_file.parent.mkdir(parents=True, exist_ok=True)
    status_file.unlink(missing_ok=True)
    env = os.environ.copy()
    env.update({"WINEPREFIX": str(prefix), "WINEARCH": "win64", "WINEDEBUG": "-all"})
    try:
        done = subprocess.run(
            [str(wine), str(launcher), target,
             r"C:\windows\temp\swcompat_ca_spawn.status"],
            cwd=prefix, env=env, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            timeout=22, check=False,
        )
    except subprocess.TimeoutExpired:
        return {"status": "TIMED_OUT", "child_exit": "NOT_VERIFIED", "error": "NONE"}
    except OSError:
        return {"status": "PROCESS_FAILED", "child_exit": "NOT_VERIFIED", "error": "NONE"}
    raw = done.stdout
    if status_file.is_file() and not status_file.is_symlink():
        try:
            with status_file.open("rb") as f:
                raw = f.read(1025)
        finally:
            status_file.unlink(missing_ok=True)
    return parse(raw, done.returncode)


def inspect_query(wine: Path, prefix: Path, launcher: Path,
                  probe: Path, msi: Path) -> dict:
    """Invoke the exact original source-authored MSI query through CreateProcessW.

    Avoid the direct Wine argv/stdio routing used by the inconclusive query.
    Both Win32 outputs and the original action identifier stay in the prefix.
    """
    from scripts.msi_custom_action_table_type import parse as parse_table, validate as validate_table
    if os.name == "nt" or any(
            p.is_symlink() for p in (wine, prefix, launcher, probe, msi)):
        raise ValueError("Only unlinked disposable Wine metadata control")
    wine, prefix, launcher, probe, msi = (
        p.resolve(strict=True) for p in (wine, prefix, launcher, probe, msi)
    )
    validate_prefix(prefix)
    if (launcher.name != "msi_action_spawn_probe.exe"
            or probe.name != "msi_custom_action_table_probe.exe"
            or msi.name != "swcompat_custom_action_type_control.msi"
            or not launcher.is_file() or not probe.is_file() or not msi.is_file()):
        raise ValueError("Unexpected source-authored Win32 fixtures")
    win_probe = windows_media_path(wine, prefix, probe)
    win_msi = windows_media_path(wine, prefix, msi)
    temp = prefix / "drive_c" / "windows" / "temp"
    if temp.is_symlink():
        raise ValueError("Linked temporary directory")
    temp.mkdir(parents=True, exist_ok=True)
    action_file = temp / "swcompat_ca_action_private.input"
    spawn_file = temp / "swcompat_ca_spawn.status"
    table_file = temp / "swcompat_ca_table_probe.status"
    if any(p.is_symlink() for p in (action_file, spawn_file, table_file)):
        raise ValueError("Linked Win32 private report")
    if action_file.exists():
        raise ValueError("Refuse stale Win32 private input")
    spawn_file.unlink(missing_ok=True)
    table_file.unlink(missing_ok=True)
    env = os.environ.copy()
    env.update({"WINEPREFIX": str(prefix), "WINEARCH": "win64", "WINEDEBUG": "-all"})
    fd = os.open(action_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(b"ServiceTypeControlSentinel")
        try:
            child = subprocess.run(
                [str(wine), str(launcher), win_probe,
                 r"C:\windows\temp\swcompat_ca_spawn.status", win_msi],
                cwd=prefix, env=env, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                timeout=30, check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            child = None
        spawn_raw = child.stdout if child else b""
        if spawn_file.is_file() and not spawn_file.is_symlink():
            with spawn_file.open("rb") as stream:
                spawn_raw = stream.read(1025)
        table_raw = b""
        if table_file.is_file() and not table_file.is_symlink():
            with table_file.open("rb") as stream:
                table_raw = stream.read(2049)
        spawn_report = parse(spawn_raw, child.returncode if child else 1)
        table_report = parse_table(table_raw, 0 if child else 1)
        if not validate(spawn_report) or not validate_table(table_report):
            raise ValueError("Invalid original Win32 metadata query protocol")
        return {"spawn": spawn_report, "table": table_report}
    finally:
        action_file.unlink(missing_ok=True)
        spawn_file.unlink(missing_ok=True)
        table_file.unlink(missing_ok=True)
