"""Inspect PE architecture of known .NET 4.8 MZZ archive members without executing them.

Original installer authentication is the workflow's prerequisite. The selected
Microsoft member files remain in private temporary files. The report exposes
only fixed classification enums, no bytes/paths/filenames/versions/hashes.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import re
import subprocess
import tempfile
from scripts.netfx481_payload_audit import pe_type

# Original MZZ archives may encode the extension before the architecture
# ("clr_dll_amd64") or after it ("clr_amd64.dll"). Accept only these
# explicit CLR-related x64 shapes, not arbitrary Microsoft member names.
TARGETS = {
    "CLR_AMD64": re.compile(r"^clr(?:[-_.]dll)?[-_.](?:amd64|x64)(?:[-_.]dll)?$", re.I),
    "MSCORLIB_AMD64": re.compile(r"^mscorlib(?:[-_.]dll)?[-_.](?:amd64|x64)(?:[-_.]dll)?$", re.I),
    "WPF_NATIVE_AMD64": re.compile(
        r"^presentationnative[-_.]v0400(?:[-_.]dll)?[-_.](?:amd64|x64)(?:[-_.]dll)?$", re.I),
}
KINDS = {"NOT_FOUND", "PE_AMD64", "PE_I386", "PE_OTHER", "NOT_PE",
         "EXTRACT_FAILED", "INVALID_SIZE"}
STATES = {"NO_MZZ", "MEASURED", "PARTIAL"}
MAX_LIST = 8 * 1024 * 1024
MAX_MEMBER = 100 * 1024 * 1024
MAX_ARCHIVES = 24
NAME = re.compile(r"^Path = (.{1,512})$")


def empty() -> dict:
    return {"status": "NO_MZZ",
            "members": {key: "NOT_FOUND" for key in TARGETS},
            "executed_original_code": False}


def validate(report: object) -> bool:
    return (type(report) is dict and set(report) == set(empty())
            and report["status"] in STATES
            and report["executed_original_code"] is False
            and type(report["members"]) is dict
            and set(report["members"]) == set(TARGETS)
            and all(value in KINDS for value in report["members"].values())
            and (report["status"] != "NO_MZZ" or report == empty()))


def matching_names(raw: bytes) -> dict[str, str]:
    """Keep original member names only inside the disposable process."""
    if len(raw) > MAX_LIST or b"\\x00" in raw:
        return {}
    try:
        lines = raw.decode("utf-8-sig").splitlines()
    except UnicodeError:
        return {}
    if not any(line.startswith("----------") for line in lines):
        return {}
    result: dict[str, str] = {}
    started = False
    for line in lines:
        if line.startswith("----------"):
            started = True
            continue
        if not started:
            continue
        m = NAME.fullmatch(line)
        if not m:
            continue
        # No path components, traversal syntax, arbitrary extensions, or
        # unbounded names may be supplied to the private archive reader.
        name = m.group(1).replace("\\\\", "/").rsplit("/", 1)[-1]
        if not name or len(name) > 96 or "/" in name or "\\\\" in name:
            continue
        for key, pattern in TARGETS.items():
            if key not in result and pattern.fullmatch(name):
                result[key] = name
    return result


def _read_member(sevenzip: Path, archive: Path, member: str) -> str:
    # An original member is permitted only if a fixed x64 name pattern
    # matched it. Neither the selected name nor the original bytes are logged.
    if not any(p.fullmatch(member) for p in TARGETS.values()):
        raise ValueError("Unsafe original MZZ PE member selection")
    with tempfile.TemporaryFile() as private:
        try:
            child = subprocess.run(
                [str(sevenzip), "e", "-so", str(archive), member],
                stdin=subprocess.DEVNULL, stdout=private,
                stderr=subprocess.DEVNULL, timeout=60, check=False)
        except (OSError, subprocess.TimeoutExpired):
            return "EXTRACT_FAILED"
        if child.returncode != 0:
            return "EXTRACT_FAILED"
        private.seek(0)
        raw = private.read(MAX_MEMBER + 1)
    if not 512 <= len(raw) <= MAX_MEMBER:
        return "INVALID_SIZE"
    return pe_type(raw[:8192])


def scan(directory: Path, sevenzip: Path) -> dict:
    if (directory.is_symlink() or not directory.is_dir()
            or sevenzip.is_symlink() or not sevenzip.is_file()):
        raise ValueError("Read-only original MZZ PE probe requires private archive directory")
    all_files = sorted(directory.iterdir())
    if len(all_files) > 64 or any(f.is_symlink() or not f.is_file() for f in all_files):
        raise ValueError("Unsafe original Microsoft MZZ directory")
    archives = [f for f in all_files if f.suffix.casefold() == ".mzz"]
    if len(archives) > MAX_ARCHIVES:
        raise ValueError("Too many private MZZ sources")
    if not archives:
        return empty()
    result = empty()
    result["status"] = "MEASURED"
    for archive in archives:
        with tempfile.TemporaryFile() as stdout:
            try:
                proc = subprocess.run(
                    [str(sevenzip), "l", "-slt", str(archive)],
                    stdin=subprocess.DEVNULL, stdout=stdout,
                    stderr=subprocess.DEVNULL, timeout=60, check=False)
                stdout.seek(0)
                raw = stdout.read(MAX_LIST + 1)
                names = matching_names(raw) if proc.returncode == 0 else set()
            except (OSError, subprocess.TimeoutExpired):
                names = set()
        if not names:
            result["status"] = "PARTIAL"
            continue
        for key, member in names.items():
            if result["members"][key] != "NOT_FOUND":
                continue
            outcome = _read_member(sevenzip, archive, member)
            result["members"][key] = outcome
            if outcome in {"EXTRACT_FAILED", "INVALID_SIZE"}:
                result["status"] = "PARTIAL"
    if not validate(result):
        raise ValueError("Original Microsoft PE architecture report invalid")
    return result


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="PE architecture of authenticated original .NET MZZ members")
    ap.add_argument("--directory", type=Path, required=True)
    ap.add_argument("--sevenzip", type=Path, required=True)
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args(argv)
    if args.output.is_symlink() or args.output.resolve().is_relative_to(args.directory.resolve()):
        ap.error("Unsafe private original source and report path")
    result = scan(args.directory, args.sevenzip)
    assert validate(result)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, sort_keys=True), encoding="utf-8")
    for key, value in result["members"].items():
        print("AUTHENTIC_ORIGINAL_NETFX_PE", key, value)
    print("ORIGINAL_PAYLOAD_EXECUTED", False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
