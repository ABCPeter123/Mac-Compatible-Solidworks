"""Classify the contents of the signed official Microsoft .NET 4.8.1 offline EXE.

Runs on native Windows with a locally installed 7-Zip reader. No contents
are extracted. Neither original filenames nor archive listing are uploaded,
logged, or persisted outside the short-lived Windows runner.

The scanner distinguishes a servicing CAB/MSU redistributable from a direct
DLL/MSI file collection, without claiming Wine installation compatibility.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re

MAX_INPUT_BYTES = 8 * 1024 * 1024
MAX_RECORDS = 20000
STATUSES = {"LISTED", "NOT_LISTABLE", "INVALID_LISTING", "TOO_LARGE"}
GROUPS = ("CAB", "MSU", "MSI", "MSP", "DLL", "EXE", "OTHER")
FEATURES = ("X64_WINDOWS_UPDATE", "X86_WINDOWS_UPDATE", "DIRECT_CLR_DLL",
            "DIRECT_MSCORLIB_DLL", "WINDOWS_SERVICING_PACKAGE")
FIELD = re.compile(r"^(Path|Size|Folder) = (.*)$")
WINDOWS_8 = re.compile(r"(?i)(?:^|[\\/])(?:x64|amd64)[-_]windows(?:10|11|8|6|server)?")
WINDOWS_32 = re.compile(r"(?i)(?:^|[\\/])(?:x86|i386)[-_]windows(?:10|11|8|6|server)?")


def empty(status: str) -> dict:
    if status not in STATUSES:
        raise ValueError("Unknown archive observation")
    return {"status": status, "entries": 0,
            "groups": {name: 0 for name in GROUPS},
            "features": {name: False for name in FEATURES}}


def analyze(raw: bytes, reader_ok: bool) -> dict:
    if not reader_ok:
        return empty("NOT_LISTABLE")
    if len(raw) > MAX_INPUT_BYTES or b"\x00" in raw:
        return empty("TOO_LARGE")
    try:
        lines = raw.decode("utf-8-sig").splitlines()
    except UnicodeDecodeError:
        return empty("INVALID_LISTING")
    # Seven-Zip's -slt format contains archive metadata before the divider.
    # Only parse file entry Path fields following the ---- divider.
    try:
        first = next(i for i, line in enumerate(lines) if line.startswith("----------"))
    except StopIteration:
        return empty("INVALID_LISTING")
    result = empty("LISTED")
    entries = 0
    for line in lines[first + 1:]:
        m = FIELD.fullmatch(line)
        if not m or m.group(1) != "Path":
            continue
        path = m.group(2).strip().replace("\\", "/")
        if not path or len(path) > 600:
            return empty("INVALID_LISTING")
        # Prevent any paths from being copied or reconstituted in result.
        name = path.rsplit("/", 1)[-1].lower()
        suffix = name.rsplit(".", 1)[-1] if "." in name else ""
        group = {
            "cab": "CAB", "msu": "MSU", "msi": "MSI",
            "msp": "MSP", "dll": "DLL", "exe": "EXE",
        }.get(suffix, "OTHER")
        result["groups"][group] += 1
        entries += 1
        if entries > MAX_RECORDS:
            return empty("TOO_LARGE")
        if suffix in {"cab", "msu", "msp"}:
            result["features"]["WINDOWS_SERVICING_PACKAGE"] = True
            if WINDOWS_8.search(path):
                result["features"]["X64_WINDOWS_UPDATE"] = True
            if WINDOWS_32.search(path):
                result["features"]["X86_WINDOWS_UPDATE"] = True
        if name == "clr.dll":
            result["features"]["DIRECT_CLR_DLL"] = True
        if name == "mscorlib.dll":
            result["features"]["DIRECT_MSCORLIB_DLL"] = True
    if not entries:
        return empty("INVALID_LISTING")
    result["entries"] = entries
    return result


def validate(report: dict) -> bool:
    if not isinstance(report, dict) or set(report) != {
        "status", "entries", "groups", "features"
    } or report["status"] not in STATUSES:
        return False
    if type(report["entries"]) is not int or not 0 <= report["entries"] <= MAX_RECORDS:
        return False
    if not isinstance(report["groups"], dict) or set(report["groups"]) != set(GROUPS):
        return False
    if any(type(v) is not int or not 0 <= v <= MAX_RECORDS
           for v in report["groups"].values()):
        return False
    if not isinstance(report["features"], dict) or set(report["features"]) != set(FEATURES):
        return False
    if any(type(v) is not bool for v in report["features"].values()):
        return False
    return (sum(report["groups"].values()) == report["entries"] and
            (report["status"] == "LISTED" or (
                report["entries"] == 0 and
                all(v is False for v in report["features"].values()))))


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Private Microsoft .NET installer archive classifier")
    p.add_argument("--listing", type=Path, required=True)
    p.add_argument("--reader-exit", type=int, required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args(argv)
    if (args.listing.is_symlink() or args.output.is_symlink()
            or args.listing.resolve() == args.output.resolve()):
        p.error("Unsafe scanner input/output")
    with args.listing.open("rb") as stream:
        data = stream.read(MAX_INPUT_BYTES + 1)
    report = analyze(data, args.reader_exit == 0)
    if not validate(report):
        p.error("Unexpected archive evidence")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print("Original signed Microsoft package listing:", report["status"])
    print("Private archive members classified:", report["entries"])
    for key in FEATURES:
        print("Fixed package marker", key, report["features"][key])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
