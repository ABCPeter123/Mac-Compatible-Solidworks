"""Native Windows reference for the authenticated .NET 4.0 offline /x extraction.

This checks the extraction switch, not CLR installation. Only finite categories
leave the Windows runner. Do not upload extracted Microsoft packages or logs.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import shutil
import subprocess

from scripts.netfx40_legacy import verify_media
from scripts.netfx40_offline_extract import blank, scan, validate

ROOT_NAME = "netfx40-native-reference-extract"


def _is_windows() -> bool:
    return os.name == "nt"


def inspect(installer: Path, *, timeout: int = 120) -> dict:
    if not _is_windows() or not 30 <= timeout <= 180:
        raise ValueError("Native Windows reference only, bounded runtime")
    if installer.is_symlink():
        raise ValueError("Linked original installer refused")
    installer = installer.resolve(strict=True)
    if not installer.is_file() or installer.name.lower() != "dotnetfx40_full_x86_x64.exe":
        raise ValueError("Unexpected original installer")
    verify_media(installer)
    if installer.parent.is_symlink():
        raise ValueError("Linked installer directory refused")
    root = installer.parent / ROOT_NAME
    if root.exists() or root.is_symlink():
        raise ValueError("Native reference extraction must use a fresh target")
    root.mkdir()
    try:
        try:
            child = subprocess.run(
                [str(installer), "/x:" + str(root), "/q"],
                cwd=installer.parent, stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                timeout=timeout, check=False,
            )
        except subprocess.TimeoutExpired:
            return {**blank(), "status": "EXTRACTION_TIMEOUT", "process": "TIMEOUT"}
        except OSError:
            return {**blank(), "status": "EXTRACTION_START_FAILED",
                    "process": "START_FAILED"}
        if child.returncode:
            return {**blank(), "status": "EXTRACTION_NONZERO", "process": "NONZERO"}
        return scan(root)
    finally:
        # The original Microsoft MSI files must never become an artifact.
        shutil.rmtree(root)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Native Windows .NET 4.0 /x reference")
    p.add_argument("--installer", type=Path, required=True)
    args = p.parse_args(argv)
    report = inspect(args.installer)
    if not validate(report):
        raise ValueError("Invalid privacy-safe Microsoft reference")
    for key in ("status", "process", "msi_entries", "ole_msi_candidates",
                "core_x64_ole_candidate", "directories_scanned",
                "file_entries_scanned"):
        print("Native Windows .NET 4.0 extraction", key, report[key])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
