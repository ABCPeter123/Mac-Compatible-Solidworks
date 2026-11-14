"""Bounded original .NET Framework file presence audit in disposable Wine.

A PE-shaped clr.dll is not authenticated Microsoft code, and neither disk
presence nor LoadLibrary establishes managed-runtime functionality. Never
publish hashes, file paths, file sizes, versions or original binaries.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
import struct

ITEMS = {
    "CLR64": ("windows", "Microsoft.NET", "Framework64", "v4.0.30319", "clr.dll"),
    "MSCORLIB64": ("windows", "Microsoft.NET", "Framework64", "v4.0.30319", "mscorlib.dll"),
    "CLR32": ("windows", "Microsoft.NET", "Framework", "v4.0.30319", "clr.dll"),
    "MSCORLIB32": ("windows", "Microsoft.NET", "Framework", "v4.0.30319", "mscorlib.dll"),
}
STATES = {"ABSENT", "PE_AMD64", "PE_I386", "PE_OTHER", "NOT_PE", "LINKED", "IO_ERROR", "INVALID_SIZE"}
CHANGES = {"CREATED", "REMOVED", "CHANGED", "UNCHANGED", "UNVERIFIED"}
MAX_BYTES = 80 * 1024 * 1024
MIN_BYTES = 512


def pe_type(header: bytes) -> str:
    """Check MZ, PE offset, COFF machine, and optional-header architecture."""
    if len(header) < 512 or header[:2] != b"MZ":
        return "NOT_PE"
    pe_offset = struct.unpack_from("<I", header, 0x3C)[0]
    if pe_offset > 4096 or pe_offset + 26 > len(header):
        return "NOT_PE"
    if header[pe_offset:pe_offset + 4] != b"PE\0\0":
        return "NOT_PE"
    machine = struct.unpack_from("<H", header, pe_offset + 4)[0]
    opt_size = struct.unpack_from("<H", header, pe_offset + 20)[0]
    magic = struct.unpack_from("<H", header, pe_offset + 24)[0]
    if opt_size < 96:
        return "NOT_PE"
    if machine == 0x8664 and magic == 0x20B:
        return "PE_AMD64"
    if machine == 0x014C and magic == 0x10B:
        return "PE_I386"
    return "PE_OTHER"


def _measure(prefix: Path, parts: tuple[str, ...]) -> tuple[str, str | None]:
    drive = prefix / "drive_c"
    path = drive
    for part in parts:
        path = path / part
        if path.is_symlink():
            return "LINKED", None
    try:
        if not path.is_file():
            return "ABSENT", None
        size = path.stat().st_size
        if not MIN_BYTES <= size <= MAX_BYTES:
            return "INVALID_SIZE", None
        digest = hashlib.sha256()
        with path.open("rb") as source:
            header = source.read(8192)
            kind = pe_type(header)
            digest.update(header)
            for block in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(block)
        return kind, digest.hexdigest()
    except OSError:
        return "IO_ERROR", None


def snapshot(prefix: Path) -> dict[str, tuple[str, str | None]]:
    from scripts.netfx481_trial import validate_prefix
    validate_prefix(prefix)
    return {key: _measure(prefix, parts) for key, parts in ITEMS.items()}


def compare(before: dict, after: dict) -> dict:
    if set(before) != set(ITEMS) or set(after) != set(ITEMS):
        raise ValueError("Unexpected CLR file inventory")
    result = {"before": {}, "after": {}, "changes": {}}
    for key in ITEMS:
        before_state, before_hash = before[key]
        after_state, after_hash = after[key]
        if before_state not in STATES or after_state not in STATES:
            raise ValueError("Unsupported CLR PE observation")
        result["before"][key] = before_state
        result["after"][key] = after_state
        if before_state == "ABSENT" and after_state.startswith("PE_"):
            change = "CREATED"
        elif before_state.startswith("PE_") and after_state == "ABSENT":
            change = "REMOVED"
        elif before_hash is not None and after_hash is not None:
            change = "UNCHANGED" if before_hash == after_hash else "CHANGED"
        elif before_state == "ABSENT" and after_state == "ABSENT":
            change = "UNCHANGED"
        else:
            change = "UNVERIFIED"
        result["changes"][key] = change
    if not validate(result):
        raise ValueError("Unsafe CLR payload report")
    return result


def blank() -> dict:
    return {
        "before": {key: "ABSENT" for key in ITEMS},
        "after": {key: "ABSENT" for key in ITEMS},
        "changes": {key: "UNVERIFIED" for key in ITEMS},
        "status": "NOT_REQUESTED",
    }


def validate(report: dict) -> bool:
    if not isinstance(report, dict):
        return False
    status = report.get("status")
    if status is None:
        status = "MEASURED"
    if status not in {"NOT_REQUESTED", "MEASURED"}:
        return False
    if set(report) != {"before", "after", "changes"} and set(report) != {
        "before", "after", "changes", "status"
    }:
        return False
    for key, values in [("before", STATES), ("after", STATES), ("changes", CHANGES)]:
        slot = report.get(key)
        if not isinstance(slot, dict) or set(slot) != set(ITEMS):
            return False
        if any(type(slot[name]) is not str or slot[name] not in values for name in ITEMS):
            return False
    return True
