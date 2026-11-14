"""Inspect only the embedded Microsoft CAB packages from a verified offline EXE.

The workflow extracts CAB containers to a private Windows runner directory.
No CAB contents are extracted, and neither the extracted CAB files nor any raw
archive filenames/listings are uploaded. Results are fixed enums and counts.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import subprocess
import tempfile

from scripts.netfx481_archive_evidence import analyze, MAX_INPUT_BYTES

MAX_CABS = 12
MAX_CAB_BYTES = 250 * 1024 * 1024
MAX_CAB_MEMBERS = 30000
STATUSES = {"SCANNED", "NO_CAB", "PARTIAL", "TOO_MANY_CABS"}
EXTENSIONS = ("DLL", "MUM", "CAT", "MANIFEST", "MSI", "EXE", "OTHER")
FEATURES = ("CLR_MEMBER", "MSCORLIB_MEMBER", "SERVICING_MANIFEST")
ENTRY = re.compile(r"^Path = (.+)$")


def empty(status: str = "NO_CAB") -> dict:
    if status not in STATUSES:
        raise ValueError("Unknown embedded CAB result")
    return {
        "status": status, "cab_count": 0, "cabs_listed": 0,
        "entries": 0,
        "types": {name: 0 for name in EXTENSIONS},
        "features": {name: False for name in FEATURES},
    }


def summarize_cab_listing(raw: bytes) -> dict | None:
    """Only inspect 7z -slt file entries after its archive metadata divider."""
    result = analyze(raw, True)
    if result["status"] != "LISTED":
        return None
    text = raw.decode("utf-8-sig")
    try:
        div = next(i for i, line in enumerate(text.splitlines()) if line.startswith("----------"))
    except StopIteration:
        return None
    types = {name: 0 for name in EXTENSIONS}
    flags = {name: False for name in FEATURES}
    count = 0
    for line in text.splitlines()[div + 1:]:
        match = ENTRY.fullmatch(line)
        if match is None:
            continue
        name = match.group(1).strip().replace("\\", "/").rsplit("/", 1)[-1].lower()
        suffix = name.rsplit(".", 1)[-1] if "." in name else ""
        key = {
            "dll": "DLL", "mum": "MUM", "cat": "CAT",
            "manifest": "MANIFEST", "msi": "MSI", "exe": "EXE",
        }.get(suffix, "OTHER")
        types[key] += 1
        count += 1
        if name in {"clr.dll", "clr.dl_"}:
            flags["CLR_MEMBER"] = True
        if name in {"mscorlib.dll", "mscorlib.dl_"}:
            flags["MSCORLIB_MEMBER"] = True
        if suffix in {"mum", "cat", "manifest"}:
            flags["SERVICING_MANIFEST"] = True
    return {"types": types, "features": flags, "entries": count}


def scan(cab_directory: Path, sevenzip: Path) -> dict:
    if (cab_directory.is_symlink() or not cab_directory.is_dir()
            or not sevenzip.is_file() or sevenzip.is_symlink()):
        raise ValueError("Expected fixed private CAB directory and reader")
    all_items = sorted(cab_directory.iterdir())
    if any(path.is_symlink() for path in all_items):
        raise ValueError("Private CAB directory must not contain symlinks")
    cabs = [path for path in all_items if path.is_file() and path.suffix.lower() == ".cab"]
    if len(cabs) > MAX_CABS:
        return empty("TOO_MANY_CABS")
    if not cabs:
        return empty()
    report = empty("SCANNED")
    report["cab_count"] = len(cabs)
    for cab in cabs:
        try:
            if cab.stat().st_size > MAX_CAB_BYTES:
                report["status"] = "PARTIAL"
                continue
            with tempfile.TemporaryFile() as stdout:
                proc = subprocess.run(
                    [str(sevenzip), "l", "-slt", str(cab)],
                    stdin=subprocess.DEVNULL, stdout=stdout,
                    stderr=subprocess.DEVNULL,
                    timeout=70, check=False,
                )
                stdout.seek(0)
                raw = stdout.read(MAX_INPUT_BYTES + 1)
            parsed = summarize_cab_listing(raw) if proc.returncode == 0 else None
        except (OSError, subprocess.TimeoutExpired):
            parsed = None
        if parsed is None or parsed["entries"] > MAX_CAB_MEMBERS:
            report["status"] = "PARTIAL"
            continue
        report["cabs_listed"] += 1
        report["entries"] += parsed["entries"]
        for key in EXTENSIONS:
            report["types"][key] += parsed["types"][key]
        for key in FEATURES:
            report["features"][key] |= parsed["features"][key]
    if not validate(report):
        raise ValueError("Unexpected nested Microsoft CAB report")
    return report


def validate(report: dict) -> bool:
    if not isinstance(report, dict) or set(report) != {
        "status", "cab_count", "cabs_listed", "entries", "types", "features"
    } or report["status"] not in STATUSES:
        return False
    if any(type(report[key]) is not int for key in ("cab_count", "cabs_listed", "entries")):
        return False
    if not 0 <= report["cab_count"] <= MAX_CABS:
        return False
    if not 0 <= report["cabs_listed"] <= report["cab_count"]:
        return False
    if not 0 <= report["entries"] <= MAX_CAB_MEMBERS * MAX_CABS:
        return False
    types = report["types"]
    flags = report["features"]
    if not isinstance(types, dict) or set(types) != set(EXTENSIONS):
        return False
    if not isinstance(flags, dict) or set(flags) != set(FEATURES):
        return False
    if any(type(value) is not int or value < 0 for value in types.values()):
        return False
    if any(type(value) is not bool for value in flags.values()):
        return False
    if sum(types.values()) != report["entries"]:
        return False
    if report["status"] == "SCANNED" and (
        report["cab_count"] == 0 or report["cabs_listed"] != report["cab_count"]
    ):
        return False
    if report["status"] in {"NO_CAB", "TOO_MANY_CABS"} and (
        report["entries"] != 0 or report["cabs_listed"] != 0
    ):
        return False
    return True


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Private nested Microsoft servicing CAB classifier")
    p.add_argument("--cab-directory", type=Path, required=True)
    p.add_argument("--sevenzip", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args(argv)
    if args.output.is_symlink() or args.output.resolve().is_relative_to(args.cab_directory.resolve()):
        p.error("Invalid output location")
    report = scan(args.cab_directory, args.sevenzip)
    if not validate(report):
        p.error("Invalid embedded package summary")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print("Authentic embedded Microsoft CAB inventory:", report["status"])
    print("CAB containers inspected:", report["cabs_listed"])
    print("CAB member count (no member paths):", report["entries"])
    for key in FEATURES:
        print("Fixed embedded package flag", key, report["features"][key])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
