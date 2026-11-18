"""Bounded NGen assembly-cache control in an authenticated disposable Wine prefix.

A real Wine issue reports that NGen may fail when C:\\windows\\assembly is
missing. This module changes no Microsoft binary, NGen executable, service,
registry value, or MSI table. It can create only that one directory when
explicitly requested after verified native Microsoft CLR4 execution.
"""
from __future__ import annotations

from pathlib import Path

STATES = {"NOT_RUN", "PRESENT", "MISSING", "CREATED", "UNSAFE", "FAILED"}


def inspect_assembly_cache(prefix: Path, *, prepare: bool = False) -> str:
    """Observe or prepare a *single* cache directory; never follow links.

    Caller must already validate an isolated Wine prefix and native CLR4.
    No repair of C:\\windows itself or creation of arbitrary parents is allowed.
    """
    if type(prepare) is not bool:
        raise ValueError("Explicit boolean preparation required")
    if prefix.is_symlink() or not prefix.is_dir():
        return "UNSAFE"
    drive = prefix / "drive_c"
    windows = drive / "windows"
    target = windows / "assembly"
    if any(part.is_symlink() or not part.is_dir() for part in (drive, windows)):
        return "UNSAFE"
    if target.is_symlink():
        return "UNSAFE"
    if target.is_dir():
        return "PRESENT"
    if target.exists():
        return "UNSAFE"
    if not prepare:
        return "MISSING"
    try:
        # Parent must already exist. Do not use parents=True.
        target.mkdir(mode=0o755, exist_ok=False)
    except FileExistsError:
        return "PRESENT" if target.is_dir() and not target.is_symlink() else "UNSAFE"
    except OSError:
        return "FAILED"
    return "CREATED" if target.is_dir() and not target.is_symlink() else "FAILED"
