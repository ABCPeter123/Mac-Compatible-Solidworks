"""Official /x offline extraction trial of genuine signed .NET Framework 4.0.

No install, no original MSI contents or names in public output. The executable
is independently SHA-256 pinned and Authenticode checked by Windows CI.
An OLE container signature is only a format hint, not cryptographic proof.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import subprocess

from scripts.netfx40_legacy import verify_media
from scripts.netfx481_trial import validate_prefix

EXTRACT_FOLDER = "swcompat-netfx40-original-extract"
EXTRACT_WINDOWS = r"C:\swcompat-netfx40-original-extract"
MAX_DIRS = 30
MAX_FILES = 160
MAX_DEPTH = 4
MAX_MSIS = 24
MAX_BYTES = 200 * 1024 * 1024
OLE_SIGNATURE = bytes.fromhex("D0CF11E0A1B11AE1")
MSI_NAME = re.compile(r"(?i)^[a-z0-9_. -]{1,110}\.msi\Z")
STATUSES = {
    "EXTRACTED_MSI_CANDIDATES", "NO_OLE_MSI_CANDIDATES", "PARTIAL_SCAN",
    "EXTRACTION_NONZERO", "EXTRACTION_TIMEOUT", "EXTRACTION_START_FAILED",
}
PROCESS = {"ZERO", "NONZERO", "TIMEOUT", "START_FAILED"}


def blank() -> dict:
    return {"status": "NO_OLE_MSI_CANDIDATES", "process": "ZERO",
            "msi_entries": 0, "ole_msi_candidates": 0,
            "core_x64_ole_candidate": False, "directories_scanned": 0,
            "file_entries_scanned": 0}


def validate(report: dict) -> bool:
    if type(report) is not dict or set(report) != {
        "status", "process", "msi_entries", "ole_msi_candidates",
        "core_x64_ole_candidate", "directories_scanned", "file_entries_scanned",
    }:
        return False
    if (report["status"] not in STATUSES or report["process"] not in PROCESS
            or type(report["core_x64_ole_candidate"]) is not bool
            or any(type(report[k]) is not int for k in (
                "msi_entries", "ole_msi_candidates", "directories_scanned",
                "file_entries_scanned"))):
        return False
    n, ole = report["msi_entries"], report["ole_msi_candidates"]
    if (not 0 <= ole <= n <= MAX_MSIS
            or not 0 <= report["directories_scanned"] <= MAX_DIRS
            or not 0 <= report["file_entries_scanned"] <= MAX_FILES
            or (report["core_x64_ole_candidate"] and ole == 0)):
        return False
    state, process = report["status"], report["process"]
    if process == "ZERO":
        if state == "EXTRACTED_MSI_CANDIDATES":
            return ole > 0
        if state == "NO_OLE_MSI_CANDIDATES":
            return ole == 0
        return state == "PARTIAL_SCAN"
    return {
        "NONZERO": "EXTRACTION_NONZERO",
        "TIMEOUT": "EXTRACTION_TIMEOUT",
        "START_FAILED": "EXTRACTION_START_FAILED",
    }[process] == state and n == 0 and ole == 0


def scan(root: Path) -> dict:
    """Inspect only files beneath an already-created marked extraction root."""
    if root.is_symlink() or not root.is_dir():
        raise ValueError("Invalid source-extraction directory")
    report = blank()
    incomplete = False
    dirs = 0
    files = 0
    msis = 0
    ole_count = 0
    core = False
    for base, subdirs, names in os.walk(root, topdown=True, followlinks=False):
        directory = Path(base)
        if dirs >= MAX_DIRS:
            incomplete = True
            subdirs.clear()
            break
        dirs += 1
        if len(directory.relative_to(root).parts) >= MAX_DEPTH:
            subdirs.clear()
        else:
            subdirs[:] = sorted(
                n for n in subdirs if not (directory / n).is_symlink()
            )[:16]
        for name in sorted(names):
            if files >= MAX_FILES:
                incomplete = True
                break
            files += 1
            if not MSI_NAME.fullmatch(name):
                continue
            path = directory / name
            if path.is_symlink() or not path.is_file():
                continue
            try:
                size = path.stat().st_size
                if not 4096 <= size <= MAX_BYTES:
                    continue
                if msis >= MAX_MSIS:
                    incomplete = True
                    break
                msis += 1
                with path.open("rb") as stream:
                    signature = stream.read(8)
                if signature == OLE_SIGNATURE:
                    ole_count += 1
                    if name.casefold() == "netfx_core_x64.msi":
                        core = True
            except OSError:
                incomplete = True
        if files >= MAX_FILES or msis >= MAX_MSIS:
            incomplete = True
            break
    report.update(
        msi_entries=msis, ole_msi_candidates=ole_count,
        core_x64_ole_candidate=core, directories_scanned=dirs,
        file_entries_scanned=files,
        status=("PARTIAL_SCAN" if incomplete else
                "EXTRACTED_MSI_CANDIDATES" if ole_count else
                "NO_OLE_MSI_CANDIDATES"),
    )
    return report


def inspect(wine: Path, prefix: Path, installer: Path, *, timeout: int = 120) -> dict:
    if os.name == "nt" or any(p.is_symlink() for p in (wine, prefix, installer)):
        raise ValueError("Original media extraction only in unlinked Wine prefix")
    wine, prefix, installer = (
        p.resolve(strict=True) for p in (wine, prefix, installer)
    )
    validate_prefix(prefix)
    if not wine.is_file() or not os.access(wine, os.X_OK):
        raise ValueError("Unexpected Wine executable")
    verify_media(installer)
    if not 30 <= timeout <= 180:
        raise ValueError("Unbounded offline extraction disallowed")
    root = prefix / "drive_c" / EXTRACT_FOLDER
    if root.exists() or root.is_symlink() or root.parent.is_symlink():
        raise ValueError("Private original extraction directory not fresh")
    root.mkdir(mode=0o700)
    env = os.environ.copy()
    env.pop("WINEDLLOVERRIDES", None)
    env.update({"WINEPREFIX": str(prefix), "WINEARCH": "win64", "WINEDEBUG": "-all"})
    try:
        run = subprocess.run(
            [str(wine), str(installer), "/x:" + EXTRACT_WINDOWS, "/q"],
            cwd=installer.parent, env=env, stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            check=False, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return {**blank(), "status": "EXTRACTION_TIMEOUT", "process": "TIMEOUT"}
    except OSError:
        return {**blank(), "status": "EXTRACTION_START_FAILED",
                "process": "START_FAILED"}
    if run.returncode != 0:
        return {**blank(), "status": "EXTRACTION_NONZERO", "process": "NONZERO"}
    result = scan(root)
    assert validate(result)
    return result


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Official .NET 4.0 original /x extraction check")
    for field in ("wine", "prefix", "installer", "output"):
        p.add_argument("--" + field, type=Path, required=True)
    p.add_argument("--timeout", type=int, default=120)
    p.add_argument("--agree-disposable-prefix", action="store_true")
    args = p.parse_args(argv)
    if not args.agree_disposable_prefix:
        raise ValueError("Explicit disposable-prefix agreement required")
    result = inspect(args.wine, args.prefix, args.installer, timeout=args.timeout)
    if not validate(result):
        raise ValueError("Unsafe original Microsoft extraction report")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, sort_keys=True), encoding="utf-8")
    for key in ("status", "process", "msi_entries", "ole_msi_candidates",
                "core_x64_ole_candidate", "directories_scanned",
                "file_entries_scanned"):
        print("Original Microsoft offline extraction", key, result[key])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
