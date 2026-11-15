"""Inventory the genuine Microsoft .NET 4.8.1 servicing package, read-only.

The official offline installer is SHA256-verified here and Authenticode-verified
by the separate Windows CI stage. 7-Zip performs container inspection only.
No Microsoft installer execution, servicing, DLL copying, registration, CAB
content, names, paths or raw listing output is retained in the report.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

from scripts.netfx481_trial import verify_media
from scripts.netfx481_mum_semantics import (
    blank as blank_mum, valid as valid_mum, inspect_cab_mums,
    combine as combine_mums,
)

EXTENSIONS = ("CAB", "MSU", "MUM", "MANIFEST", "MSI", "DLL")
STATES = {"OK", "UNSUPPORTED", "TIMEOUT", "START_FAILED", "TOO_LARGE", "INVALID"}
NESTED = {"NOT_RUN", "NOT_FOUND", "MEASURED", "PARTIAL", "EXTRACTION_FAILED"}
MAX_LISTING = 4 * 1024 * 1024
MAX_FILES = 25000
MAX_EMBEDDED = 16
MAX_EXTRACTED_BYTES = 2 * 1024 * 1024 * 1024
MAX_EMBEDDED_BYTES = 1024 * 1024 * 1024
MAX_DIRS = 60
PACKAGE_EXT = {".cab", ".msu"}
PATH_ROW = re.compile(r"^Path = (.{1,1024})$")
CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")


def counters() -> dict:
    return {key: 0 for key in EXTENSIONS}


def blank() -> dict:
    return {
        "scope": "AUTHENTIC_MICROSOFT_NETFX481_SERVICING_INVENTORY",
        "original_sha256_verified": True,
        "outer_status": "INVALID",
        "outer_types": counters(),
        "outer_entries": 0,
        "outer_arch_x64": False,
        "outer_kb5011048_hint": False,
        "embedded_candidates": 0,
        "embedded_checked": 0,
        "nested_status": "NOT_RUN",
        "nested_types": counters(),
        "nested_entries": 0,
        "nested_update_mum_hint": False,
        "mum_semantics": blank_mum(),
        "genuine_servicing_installed": False,
    }


def valid(r: dict) -> bool:
    if type(r) is not dict or set(r) != set(blank()) or not valid_mum(r["mum_semantics"]):
        return False
    b = blank()
    if (r["scope"] != b["scope"] or r["original_sha256_verified"] is not True
            or r["genuine_servicing_installed"] is not False
            or r["outer_status"] not in STATES
            or r["nested_status"] not in NESTED
            or type(r["outer_arch_x64"]) is not bool
            or type(r["outer_kb5011048_hint"]) is not bool
            or type(r["nested_update_mum_hint"]) is not bool):
        return False
    for part in ("outer_types", "nested_types"):
        d = r[part]
        if type(d) is not dict or set(d) != set(counters()):
            return False
        if any(type(v) is not int or not 0 <= v <= MAX_FILES for v in d.values()):
            return False
    return (all(type(r[key]) is int and 0 <= r[key] <= MAX_FILES
                for key in ("outer_entries", "nested_entries", "embedded_candidates",
                            "embedded_checked"))
            and r["embedded_checked"] <= r["embedded_candidates"]
            and r["embedded_checked"] <= MAX_EMBEDDED)


def summarize_listing(raw: bytes, *, exit_code: int) -> dict:
    """Only predefined counts leave this function. Never return original paths."""
    result = {"status": "INVALID", "types": counters(), "entries": 0,
              "arch_x64": False, "kb5011048": False, "update_mum": False}
    if exit_code != 0:
        return {**result, "status": "UNSUPPORTED"}
    if len(raw) > MAX_LISTING:
        return {**result, "status": "TOO_LARGE"}
    try:
        data = raw.decode("utf-8-sig", errors="strict")
    except UnicodeDecodeError:
        return result
    items = 0
    for line in data.splitlines():
        match = PATH_ROW.fullmatch(line)
        if not match:
            continue
        name = match[1]
        if CONTROL_CHARS.search(name):
            continue
        items += 1
        if items > MAX_FILES:
            return result
        base = name.replace("\\", "/").rsplit("/", 1)[-1]
        ext = Path(base).suffix[1:].upper()
        if ext in EXTENSIONS:
            result["types"][ext] += 1
        lower = name.lower()
        if any(token in lower for token in ("amd64", "x64")):
            result["arch_x64"] = True
        if "kb5011048" in lower:
            result["kb5011048"] = True
        if base.casefold() == "update.mum":
            result["update_mum"] = True
    result["status"] = "OK"
    result["entries"] = items
    return result


def _invoke_sevenzip(ziptool: Path, args: list[str], cwd: Path,
                     *, timeout: int = 100) -> tuple[str, bytes]:
    """Private bounded output in temp file. No raw tool output is ever logged."""
    with tempfile.TemporaryFile(mode="w+b") as output:
        try:
            process = subprocess.run(
                [str(ziptool), *args], cwd=cwd,
                stdin=subprocess.DEVNULL, stdout=output,
                stderr=subprocess.DEVNULL, check=False, timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            return "TIMEOUT", b""
        except OSError:
            return "START_FAILED", b""
        output.seek(0)
        raw = output.read(MAX_LISTING + 1)
        return ("OK" if process.returncode == 0 else "UNSUPPORTED"), raw


def _safe_embedded(root: Path) -> tuple[list[Path], bool]:
    found: list[Path] = []
    scanned = 0
    total = 0
    directories = 0
    partial = False
    for base, dirs, files in os.walk(root, topdown=True, followlinks=False):
        directories += 1
        if directories > MAX_DIRS:
            partial = True
            dirs.clear()
            break
        parent = Path(base)
        dirs[:] = sorted(v for v in dirs if not (parent / v).is_symlink())[:12]
        for name in sorted(files):
            scanned += 1
            if scanned > MAX_FILES:
                partial = True
                break
            f = parent / name
            if f.is_symlink() or not f.is_file():
                partial = True
                continue
            sz = f.stat().st_size
            total += sz
            if total > MAX_EXTRACTED_BYTES:
                partial = True
                break
            if f.suffix.lower() in PACKAGE_EXT:
                if len(found) >= MAX_EMBEDDED or not 32 <= sz <= MAX_EMBEDDED_BYTES:
                    partial = True
                else:
                    found.append(f)
        if partial:
            break
    return found, partial


def inspect(installer: Path, sha_manifest: Path, sevenzip: Path) -> dict:
    if os.name != "nt" or any(x.is_symlink() for x in (installer, sha_manifest, sevenzip)):
        raise ValueError("Only a native Windows authenticated-media reference")
    installer, sha_manifest, sevenzip = [
        x.resolve(strict=True) for x in (installer, sha_manifest, sevenzip)]
    verify_media(installer, sha_manifest)
    if (installer.name != "NDP481-x86-x64-AllOS-ENU.exe"
            or sevenzip.name.lower() not in {"7z.exe", "7za.exe"}
            or not sevenzip.is_file()):
        raise ValueError("Expected signed Microsoft package and 7-Zip executable")

    report = blank()
    with tempfile.TemporaryDirectory(prefix="swcompat-netfx481-servicing-") as td:
        root = Path(td)
        state, raw = _invoke_sevenzip(sevenzip, ["l", "-slt", str(installer)], root)
        outer = summarize_listing(raw, exit_code=0 if state == "OK" else 1)
        if state in {"TIMEOUT", "START_FAILED"}:
            outer["status"] = state
        report.update(outer_status=outer["status"],
                      outer_types=outer["types"], outer_entries=outer["entries"],
                      outer_arch_x64=outer["arch_x64"],
                      outer_kb5011048_hint=outer["kb5011048"])
        if outer["status"] != "OK":
            assert valid(report)
            return report

        extracted = root / "embedded"
        extracted.mkdir(mode=0o700)
        # Extract container members ONLY, never execute the Microsoft setup.
        state, _ = _invoke_sevenzip(
            sevenzip, ["x", "-y", "-r", "-o" + str(extracted),
                       str(installer), "*.cab", "*.msu"], root, timeout=150)
        if state != "OK":
            report["nested_status"] = "EXTRACTION_FAILED"
            assert valid(report)
            return report
        packages, partial = _safe_embedded(extracted)
        report["embedded_candidates"] = len(packages)
        if not packages:
            report["nested_status"] = "NOT_FOUND"
        else:
            report["nested_status"] = "PARTIAL" if partial else "MEASURED"
        mummetas = []
        for index, package in enumerate(packages):
            if package.suffix.casefold() == ".cab":
                mummetas.append(inspect_cab_mums(
                    sevenzip, package, root / ("extracted-mums-" + str(index))))
            state, raw = _invoke_sevenzip(
                sevenzip, ["l", "-slt", str(package)], root)
            inner = summarize_listing(raw, exit_code=0 if state == "OK" else 1)
            if inner["status"] != "OK":
                report["nested_status"] = "PARTIAL"
                continue
            report["embedded_checked"] += 1
            report["nested_entries"] = min(MAX_FILES,
                                            report["nested_entries"] + inner["entries"])
            report["nested_update_mum_hint"] |= inner["update_mum"]
            for ext in EXTENSIONS:
                report["nested_types"][ext] = min(
                    MAX_FILES, report["nested_types"][ext] + inner["types"][ext])
        report["mum_semantics"] = combine_mums(mummetas)
        assert valid(report)
        return report


def main() -> int:
    p = argparse.ArgumentParser(description="Read-only authenticated .NET 4.8.1 CAB/MSU inventory")
    for key in ("installer", "sha256-file", "sevenzip", "output"):
        p.add_argument("--" + key, type=Path, required=True)
    args = p.parse_args()
    result = inspect(args.installer, args.sha256_file, args.sevenzip)
    assert valid(result)
    if args.output.is_symlink():
        raise ValueError("Linked output")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, sort_keys=True), encoding="ascii")
    for key, value in result.items():
        if key not in {"outer_types", "nested_types", "mum_semantics"}:
            print("Authentic .NET 4.8.1 package inventory", key, value)
    for key in ("outer_types", "nested_types"):
        for ext, n in result[key].items():
            print("Authentic .NET 4.8.1 package inventory", key, ext, n)
    for key, value in result["mum_semantics"].items():
        if key not in {"tags", "architectures"}:
            print("Original Microsoft 4.8.1 MUM semantics", key, value)
    for field in ("tags", "architectures"):
        for key, number in result["mum_semantics"][field].items():
            print("Original Microsoft 4.8.1 MUM semantics", field, key, number)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
