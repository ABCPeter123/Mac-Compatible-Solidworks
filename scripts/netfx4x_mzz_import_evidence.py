"""Inspect authenticated .NET 4.8 x64 native PE imports without running vendor code.

Workflow authenticates original Microsoft installer before extracting one MZZ.
No DLL names from untrusted media, raw binary bytes, paths, import function
names, hashes or logs appear in reports. Fixed, bounded dependency families
only. Static imports do not establish runtime loader or managed readiness.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import struct
import subprocess
import tempfile

from scripts.netfx4x_mzz_pe_evidence import matching_names, TARGETS

MAX_BYTES = 100 * 1024 * 1024
MAX_LIST_BYTES = 8 * 1024 * 1024
MAX_SECTIONS = 96
MAX_IMPORTS = 256
FAMILIES = (
    "NTDLL", "KERNEL32", "KERNELBASE", "ADVAPI32", "OLE32", "OLEAUT32",
    "USER32", "GDI32", "RPCRT4", "SHELL32", "SHLWAPI", "VERSION",
    "MSCOREE", "MSCOREI", "FUSION", "CLR", "MSVCRT", "UCRTBASE",
    "VCRUNTIME", "MSVC_RUNTIME", "CRYPTO", "NETWORK", "API_SET",
    "OTHER",
)
KINDS = {"NOT_FOUND", "NOT_PE", "NOT_AMD64", "PE_AMD64",
         "INVALID_IMPORT_TABLE", "EXTRACT_FAILED", "INVALID_SIZE"}
DIR_STATES = {"NONE", "READABLE", "INVALID", "UNSUPPORTED"}
STATUS = {"NO_MZZ", "MEASURED", "PARTIAL"}
MAX_ARCHIVES = 24


def family(dll: str) -> str:
    """Map names to an allowlisted family. Never return an original name."""
    name = dll.casefold()
    if name.startswith(("api-ms-win-", "ext-ms-win-")):
        return "API_SET"
    stem = name.removesuffix(".dll").upper()
    direct = set(FAMILIES) - {
        "OTHER", "API_SET", "VCRUNTIME", "MSVC_RUNTIME", "CRYPTO", "NETWORK",
    }
    if stem in direct:
        return stem
    if stem.startswith("VCRUNTIME"):
        return "VCRUNTIME"
    if stem.startswith(("MSVCR", "MSVCP")):
        return "MSVC_RUNTIME"
    if stem in {"CRYPT32", "CRYPTBASE", "BCRYPT", "BCRYPTPRIMITIVES", "WINTRUST"}:
        return "CRYPTO"
    if stem in {"WS2_32", "WINHTTP", "WININET", "DNSAPI", "IPHLPAPI"}:
        return "NETWORK"
    return "OTHER"


def _u16(data: bytes, pos: int) -> int:
    if pos < 0 or pos + 2 > len(data):
        raise ValueError("truncated PE ushort")
    return struct.unpack_from("<H", data, pos)[0]


def _u32(data: bytes, pos: int) -> int:
    if pos < 0 or pos + 4 > len(data):
        raise ValueError("truncated PE dword")
    return struct.unpack_from("<I", data, pos)[0]


def empty_member() -> dict:
    return {
        "pe": "NOT_FOUND", "import_table": "NONE", "delay_import_table": "NONE",
        "import_count": 0, "delay_import_count": 0,
        "import_families": {key: 0 for key in FAMILIES},
        "delay_families": {key: 0 for key in FAMILIES},
        "cli_metadata_directory": False,
        "native_loader_tested": False,
    }


def empty() -> dict:
    return {"status": "NO_MZZ", "members": {key: empty_member() for key in TARGETS},
            "genuine_dotnet48_running": False}


def validate(result: object) -> bool:
    if type(result) is not dict or set(result) != set(empty()):
        return False
    if (result["status"] not in STATUS or result["genuine_dotnet48_running"] is not False
            or type(result["members"]) is not dict or set(result["members"]) != set(TARGETS)):
        return False
    for item in result["members"].values():
        if type(item) is not dict or set(item) != set(empty_member()):
            return False
        if (item["pe"] not in KINDS or item["import_table"] not in DIR_STATES
                or item["delay_import_table"] not in DIR_STATES
                or item["cli_metadata_directory"] not in (True, False)
                or type(item["cli_metadata_directory"]) is not bool
                or item["native_loader_tested"] is not False):
            return False
        for count, group in (("import_count", "import_families"),
                             ("delay_import_count", "delay_families")):
            if type(item[count]) is not int or not 0 <= item[count] <= MAX_IMPORTS:
                return False
            if type(item[group]) is not dict or set(item[group]) != set(FAMILIES):
                return False
            if any(type(n) is not int or n < 0 for n in item[group].values()):
                return False
            if sum(item[group].values()) != item[count]:
                return False
        if (item["pe"] != "PE_AMD64" and (item["import_count"] or item["delay_import_count"]
                or item["cli_metadata_directory"])):
            return False
    if result["status"] == "NO_MZZ":
        return result == empty()
    return True


def parse_pe(data: bytes) -> dict:
    """Read standard PE32+ import and delay-import descriptor tables by RVA."""
    out = empty_member()
    try:
        if not 512 <= len(data) <= MAX_BYTES or data[:2] != b"MZ":
            out["pe"] = "NOT_PE"
            return out
        pe = _u32(data, 0x3C)
        if pe > 4096 or data[pe:pe + 4] != b"PE\x00\x00":
            out["pe"] = "NOT_PE"
            return out
        machine = _u16(data, pe + 4)
        nsec = _u16(data, pe + 6)
        optlen = _u16(data, pe + 20)
        opt = pe + 24
        if machine != 0x8664 or _u16(data, opt) != 0x20B:
            out["pe"] = "NOT_AMD64"
            return out
        out["pe"] = "PE_AMD64"
        if not 1 <= nsec <= MAX_SECTIONS or optlen < 240 or opt + optlen > len(data):
            raise ValueError("invalid PE section layout")
        if _u32(data, opt + 108) < 15:
            raise ValueError("missing PE data directories")
        headers = _u32(data, opt + 60)
        sections = []
        sec = opt + optlen
        for i in range(nsec):
            pos = sec + 40 * i
            vsz = _u32(data, pos + 8)
            rva = _u32(data, pos + 12)
            rawsz = _u32(data, pos + 16)
            rawoff = _u32(data, pos + 20)
            if rawoff + rawsz > len(data):
                raise ValueError("invalid PE section raw span")
            sections.append((rva, min(vsz or rawsz, rawsz), rawoff))
        def position(rva: int, need: int) -> int:
            if need <= 0 or rva == 0:
                raise ValueError("invalid PE RVA")
            for base, span, off in sections:
                if base <= rva and rva + need <= base + span:
                    return off + rva - base
            if rva + need <= min(headers, len(data)):
                return rva
            raise ValueError("PE RVA outside mapped sections")

        def directory(index: int, size_per: int, name_offset: int, attr: bool) -> tuple[str, dict]:
            entry = opt + 112 + 8 * index
            rva, size = _u32(data, entry), _u32(data, entry + 4)
            counts = {k: 0 for k in FAMILIES}
            if not rva and not size:
                return "NONE", counts
            if not rva or size < size_per or size > MAX_IMPORTS * size_per + 4096:
                return "INVALID", counts
            seen = set()
            try:
                # Read at most MAX_IMPORTS descriptors and require a null terminator.
                for i in range(min(size // size_per, MAX_IMPORTS + 1)):
                    loc = position(rva + i * size_per, size_per)
                    descriptor = data[loc:loc + size_per]
                    if descriptor == bytes(size_per):
                        return "READABLE", counts
                    if i >= MAX_IMPORTS:
                        raise ValueError("too many PE imports")
                    if attr and (_u32(data, loc) & 1) != 1:
                        return "UNSUPPORTED", {k: 0 for k in FAMILIES}
                    dll_rva = _u32(data, loc + name_offset)
                    start = position(dll_rva, 1)
                    end = data.find(b"\x00", start, min(start + 100, len(data)))
                    if end < 0:
                        raise ValueError("unterminated PE import")
                    dll = data[start:end].decode("ascii").casefold()
                    if not re.fullmatch(r"[a-z0-9_.-]{1,90}\.dll", dll):
                        raise ValueError("unrecognized PE import name")
                    if dll not in seen:
                        counts[family(dll)] += 1
                        seen.add(dll)
                raise ValueError("no PE import terminator")
            except (ValueError, UnicodeError, struct.error):
                return "INVALID", {k: 0 for k in FAMILIES}
        out["cli_metadata_directory"] = any(
            (_u32(data, opt + 112 + 8 * 14), _u32(data, opt + 112 + 8 * 14 + 4)))
        out["import_table"], out["import_families"] = directory(1, 20, 12, False)
        out["delay_import_table"], out["delay_families"] = directory(13, 32, 4, True)
        out["import_count"] = sum(out["import_families"].values())
        out["delay_import_count"] = sum(out["delay_families"].values())
        if out["import_table"] == "INVALID" or out["delay_import_table"] == "INVALID":
            out["pe"] = "INVALID_IMPORT_TABLE"
            # Do not claim CLI readiness from a malformed PE.
            out["cli_metadata_directory"] = False
            out["import_table"] = "INVALID"
            out["delay_import_table"] = "INVALID"
            out["import_families"] = {k: 0 for k in FAMILIES}
            out["delay_families"] = {k: 0 for k in FAMILIES}
            out["import_count"] = out["delay_import_count"] = 0
    except (ValueError, struct.error, IndexError, OverflowError):
        out = empty_member()
        out["pe"] = "INVALID_IMPORT_TABLE"
        out["import_table"] = "INVALID"
        out["delay_import_table"] = "INVALID"
    return out


def scan(directory: Path, sevenzip: Path) -> dict:
    if (directory.is_symlink() or not directory.is_dir()
            or sevenzip.is_symlink() or not sevenzip.is_file()):
        raise ValueError("Private original Microsoft MZZ source/reader required")
    files = sorted(directory.iterdir())
    if len(files) > 64 or any(x.is_symlink() or not x.is_file() for x in files):
        raise ValueError("Unexpected private MZZ extraction directory")
    archives = [p for p in files if p.suffix.casefold() == ".mzz"]
    if len(archives) > MAX_ARCHIVES:
        raise ValueError("Unexpected MZZ archive count")
    if not archives:
        return empty()
    report = empty()
    report["status"] = "MEASURED"
    for archive in archives:
        with tempfile.TemporaryFile() as output:
            try:
                proc = subprocess.run(
                    [str(sevenzip), "l", "-slt", str(archive)], stdin=subprocess.DEVNULL,
                    stdout=output, stderr=subprocess.DEVNULL, timeout=65, check=False)
                output.seek(0)
                listing = output.read(MAX_LIST_BYTES + 1)
                names = matching_names(listing) if proc.returncode == 0 else {}
            except (OSError, subprocess.TimeoutExpired):
                names = {}
        if not names:
            report["status"] = "PARTIAL"
            continue
        for key, name in names.items():
            if report["members"][key]["pe"] != "NOT_FOUND":
                continue
            if not TARGETS[key].fullmatch(name):
                raise ValueError("Invalid original PE selection")
            with tempfile.TemporaryFile() as output:
                try:
                    proc = subprocess.run(
                        [str(sevenzip), "e", "-so", str(archive), name],
                        stdin=subprocess.DEVNULL, stdout=output,
                        stderr=subprocess.DEVNULL, timeout=75, check=False)
                    output.seek(0)
                    payload = output.read(MAX_BYTES + 1) if proc.returncode == 0 else b""
                    state = ("EXTRACT_FAILED" if proc.returncode else
                             "INVALID_SIZE" if not 512 <= len(payload) <= MAX_BYTES else None)
                except (OSError, subprocess.TimeoutExpired):
                    payload, state = b"", "EXTRACT_FAILED"
            report["members"][key] = parse_pe(payload) if state is None else dict(empty_member(), pe=state)
            if state or report["members"][key]["pe"] != "PE_AMD64":
                report["status"] = "PARTIAL"
    if not validate(report):
        raise ValueError("Invalid original signed payload import report")
    return report


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Authenticated .NET 4.8 MZZ x64 PE import census")
    ap.add_argument("--directory", type=Path, required=True)
    ap.add_argument("--sevenzip", type=Path, required=True)
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args(argv)
    if args.output.is_symlink() or args.output.resolve().is_relative_to(args.directory.resolve()):
        ap.error("Unsafe private archive/output destination")
    result = scan(args.directory, args.sevenzip)
    assert validate(result)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, sort_keys=True), encoding="utf-8")
    for key, item in result["members"].items():
        print("AUTHENTIC_NETFX_IMPORT", key, item["pe"],
              "direct", item["import_table"], item["import_count"],
              "delay", item["delay_import_table"], item["delay_import_count"],
              "cli", item["cli_metadata_directory"])
        for family_name in FAMILIES:
            if item["import_families"][family_name]:
                print("AUTHENTIC_NETFX_DEPENDENCY", key, family_name,
                      item["import_families"][family_name])
    print("DOTNET48_RUNNING", False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
