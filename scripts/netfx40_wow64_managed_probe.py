"""Verify real Microsoft .NET 4.0 can run x86 managed code through Wine WoW64.

Original self-authored executable is compiled on native Windows with
Framework csc.exe /platform:x86, verified there, and transferred as a fixture.
The Wine run forces native CLR DLL loading; Wine Mono success is not accepted.
No original Microsoft files, raw Wine output, paths or exception text escape.
"""
from __future__ import annotations

from pathlib import Path
import struct

from scripts.netfx481_trial import probe, validate_prefix

NAMES = {"NOT_RUN", "INVALID_IMAGE", "MANAGED_X86_PASS", "MANAGED_X86_FAIL"}
FAMILY = {"NOT_RUN", "MICROSOFT_CLR_CANDIDATE", "MONO", "UNKNOWN", "NOT_VERIFIED"}
MANAGED = {"NOT_RUN", "PASS", "FAIL", "NOT_VERIFIED"}
FIXTURE_NAME = "netfx40_wow64_managed_probe.exe"


def blank() -> dict:
    return {"status": "NOT_RUN", "family": "NOT_RUN", "managed": "NOT_RUN"}


def valid(result: object) -> bool:
    if type(result) is not dict or set(result) != set(blank()):
        return False
    if (type(result["status"]) is not str or result["status"] not in NAMES
            or type(result["family"]) is not str or result["family"] not in FAMILY
            or type(result["managed"]) is not str or result["managed"] not in MANAGED):
        return False
    if result["status"] == "NOT_RUN":
        return result == blank()
    if result["status"] == "INVALID_IMAGE":
        return result["family"] == "NOT_RUN" and result["managed"] == "NOT_RUN"
    return ((result["status"] == "MANAGED_X86_PASS") ==
            (result["family"] == "MICROSOFT_CLR_CANDIDATE"
             and result["managed"] == "PASS"))


def is_original_x86_cli_image(path: Path) -> bool:
    """Read only fixed Windows PE and CLR headers, never execute on this path."""
    if path.is_symlink() or not path.is_file():
        return False
    try:
        size = path.stat().st_size
        if not 4096 <= size <= 2 * 1024 * 1024:
            return False
        with path.open("rb") as file:
            header = file.read(4096)
    except OSError:
        return False
    if len(header) < 1024 or header[:2] != b"MZ":
        return False
    offset = struct.unpack_from("<I", header, 0x3c)[0]
    if offset > 2048 or header[offset:offset+4] != b"PE\x00\x00":
        return False
    if struct.unpack_from("<H", header, offset+4)[0] != 0x14c:
        return False  # Intel x86, not AMD64, ARM64 or an arbitrary DLL
    optional = offset + 24
    if struct.unpack_from("<H", header, optional)[0] != 0x10b:
        return False  # Genuine PE32, not PE32+
    if struct.unpack_from("<I", header, optional+92)[0] < 15:
        return False  # No CLR directory entry
    cli_rva, cli_size = struct.unpack_from("<II", header, optional+96+14*8)
    return bool(cli_rva and cli_size >= 0x48)


def inspect(wine: Path, prefix: Path, fixture: Path) -> dict:
    validate_prefix(prefix)
    if (wine.is_symlink() or not wine.is_file()
            or fixture.is_symlink() or fixture.name != FIXTURE_NAME):
        raise ValueError("Unrecognized native Microsoft x86 managed trial fixture")
    if not is_original_x86_cli_image(fixture):
        return {"status": "INVALID_IMAGE", "family": "NOT_RUN", "managed": "NOT_RUN"}
    measured = probe(wine, prefix, fixture, timeout=70, override="native_only")
    family = measured["clr_family"]
    managed = measured["managed"]
    result = {
        "status": ("MANAGED_X86_PASS" if family == "MICROSOFT_CLR_CANDIDATE"
                   and managed == "PASS" else "MANAGED_X86_FAIL"),
        "family": family,
        "managed": managed,
    }
    if not valid(result):
        raise ValueError("Invalid finite x86 original Microsoft CLR trial")
    return result
