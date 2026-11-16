"""Read-only census of MZZ payloads extracted from signed Microsoft .NET media.

The caller authenticates the original signed installer first. Archive names,
members, original byte streams, hashes, paths and Windows logs never leave the
private runner. No file is copied into a Wine prefix. Presence is not proof
that a Windows runtime can install or load under Wine.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import subprocess
import tempfile

MAX_MZZ = 24
MAX_BYTES = 300 * 1024 * 1024
MAX_LIST_BYTES = 8 * 1024 * 1024
MAX_ENTRIES = 50000
STATES = {"NO_MZZ", "SCANNED", "PARTIAL", "TOO_MANY_MZZ"}
TYPES = ("DLL", "EXE", "CAB", "MSI", "MUM", "OTHER")
SIGNALS = ("CLR_LIKE", "MSCORLIB_LIKE", "WPF_LIKE",
           "AMD64_NAMED", "X86_NAMED", "SERVICE_MANIFEST")
MEMBER = re.compile(r"^Path = (.{1,512})$")
METADATA_DIVIDER = re.compile(r"^-{10,}$")


def empty(status: str = "NO_MZZ") -> dict:
    if status not in STATES:
        raise ValueError("Invalid private original MZZ state")
    return {
        "status": status, "mzz_found": 0, "mzz_listed": 0, "entries": 0,
        "types": {key: 0 for key in TYPES},
        "signals": {key: False for key in SIGNALS},
        "runtime_installation_proven": False,
    }


def validate(r: object) -> bool:
    if type(r) is not dict or set(r) != set(empty()):
        return False
    if (r["status"] not in STATES or r["runtime_installation_proven"] is not False
            or any(type(r[key]) is not int for key in ("mzz_found", "mzz_listed", "entries"))
            or not 0 <= r["mzz_listed"] <= r["mzz_found"] <= MAX_MZZ
            or not 0 <= r["entries"] <= MAX_ENTRIES * MAX_MZZ
            or type(r["types"]) is not dict or set(r["types"]) != set(TYPES)
            or any(type(value) is not int or value < 0 for value in r["types"].values())
            or sum(r["types"].values()) != r["entries"]
            or type(r["signals"]) is not dict or set(r["signals"]) != set(SIGNALS)
            or any(type(value) is not bool for value in r["signals"].values())):
        return False
    if r["status"] == "NO_MZZ":
        return r == empty()
    if r["status"] == "TOO_MANY_MZZ":
        return r["mzz_listed"] == 0 and r["entries"] == 0
    if r["status"] == "SCANNED":
        return r["mzz_found"] > 0 and r["mzz_found"] == r["mzz_listed"]
    return r["mzz_found"] > 0


def classify_listing(raw: bytes) -> dict | None:
    """Parse only 7z -slt file metadata, never publish original member names."""
    if not raw or len(raw) > MAX_LIST_BYTES or b"\x00" in raw:
        return None
    try:
        lines = raw.decode("utf-8-sig").splitlines()
    except UnicodeError:
        return None
    try:
        begin = next(i for i, line in enumerate(lines) if METADATA_DIVIDER.fullmatch(line))
    except StopIteration:
        return None
    result = {"entries": 0,
              "types": {key: 0 for key in TYPES},
              "signals": {key: False for key in SIGNALS}}
    for line in lines[begin + 1:]:
        m = MEMBER.fullmatch(line)
        if not m:
            continue
        path = m.group(1).replace("\\", "/").casefold()
        name = path.rsplit("/", 1)[-1]
        if not name or name in {".", ".."}:
            return None
        suffix = name.rsplit(".", 1)[-1] if "." in name else ""
        typ = suffix.upper() if suffix.upper() in TYPES[:-1] else "OTHER"
        result["types"][typ] += 1
        result["entries"] += 1
        if result["entries"] > MAX_ENTRIES:
            return None
        base = name.split(".")[0]
        result["signals"]["CLR_LIKE"] |= bool(re.match(r"^clr(?:[-_.]|$)", base))
        result["signals"]["MSCORLIB_LIKE"] |= bool(re.match(r"^mscorlib(?:[-_.]|$)", base))
        result["signals"]["WPF_LIKE"] |= any(s in name for s in (
            "presentationframework", "presentationcore", "presentationnative", "system_xaml", "system.xaml"))
        result["signals"]["AMD64_NAMED"] |= bool(re.search(r"(?:^|[_\-.])(?:amd64|x64)(?:[_\-.]|$)", name))
        result["signals"]["X86_NAMED"] |= bool(re.search(r"(?:^|[_\-.])x86(?:[_\-.]|$)", name))
        result["signals"]["SERVICE_MANIFEST"] |= suffix in {"mum", "cat", "manifest"}
    return result if result["entries"] else None


def scan(directory: Path, sevenzip: Path) -> dict:
    if (directory.is_symlink() or not directory.is_dir()
            or sevenzip.is_symlink() or not sevenzip.is_file()):
        raise ValueError("Only an existing private MZZ directory and package reader")
    all_files = sorted(directory.iterdir())
    if len(all_files) > 64 or any(p.is_symlink() or not p.is_file() for p in all_files):
        raise ValueError("Unexpected original Microsoft private archive directory")
    mzzs = [p for p in all_files if p.suffix.casefold() == ".mzz"]
    if len(mzzs) > MAX_MZZ:
        return empty("TOO_MANY_MZZ")
    if not mzzs:
        return empty()
    report = empty("SCANNED")
    report["mzz_found"] = len(mzzs)
    for archive in mzzs:
        try:
            if archive.stat().st_size > MAX_BYTES or archive.stat().st_size < 128:
                report["status"] = "PARTIAL"
                continue
            with tempfile.TemporaryFile() as out:
                child = subprocess.run(
                    [str(sevenzip), "l", "-slt", str(archive)],
                    stdin=subprocess.DEVNULL, stdout=out,
                    stderr=subprocess.DEVNULL, timeout=75, check=False)
                out.seek(0)
                raw = out.read(MAX_LIST_BYTES + 1)
            census = classify_listing(raw) if child.returncode == 0 else None
        except (OSError, subprocess.TimeoutExpired):
            census = None
        if census is None:
            report["status"] = "PARTIAL"
            continue
        report["mzz_listed"] += 1
        report["entries"] += census["entries"]
        for key in TYPES:
            report["types"][key] += census["types"][key]
        for key in SIGNALS:
            report["signals"][key] |= census["signals"][key]
    if not validate(report):
        raise ValueError("Unexpected private Microsoft MZZ evidence")
    return report


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Classify authenticated original .NET embedded MZZ archives")
    ap.add_argument("--directory", required=True, type=Path)
    ap.add_argument("--sevenzip", required=True, type=Path)
    ap.add_argument("--output", required=True, type=Path)
    args = ap.parse_args(argv)
    if args.output.is_symlink() or args.output.resolve().is_relative_to(args.directory.resolve()):
        ap.error("Unsafe diagnostic output destination")
    result = scan(args.directory, args.sevenzip)
    assert validate(result)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, sort_keys=True), encoding="utf-8")
    print("Original Microsoft MZZ census", result["status"])
    print("MZZ classified", result["mzz_listed"], "/", result["mzz_found"])
    print("Original Microsoft MZZ member count", result["entries"])
    for key, value in result["signals"].items():
        print("MZZ known member class", key, value)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
