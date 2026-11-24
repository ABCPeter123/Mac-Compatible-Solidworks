"""Bounded, fail-closed fresh-prefix retry after real Microsoft CLR4 MSI 1603.

The first signed Microsoft .NET 4.0 installer attempt is never retried in its
partially modified prefix. Only the isolated Apple Silicon signed MSP CI run
can park that marked disposable prefix, then initialize an entirely new one
at the canonical path. This does not bypass native CLR or MSP success gates.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from scripts.netfx40_legacy import (
    validate as valid_original, _terminate_private_setup_wineserver,
)
from scripts.netfx40_msxml3_restart import validate as valid_restart

CANONICAL = "netfx40-msxml3-prefix"
ARCHIVE = "netfx40-msxml3-failed-first-prefix"
MARKER = ".swcompat-netfx481-disposable"


def decision(original: object, restarted: object) -> str:
    if not valid_original(original) or not valid_restart(restarted):
        return "DENIED"
    if (restarted["persistent_native_managed"] is True
            and restarted["native_only_managed"] == "PASS"
            and original["candidate_native40"] is True):
        return "ALREADY_VERIFIED"
    if not (
        original["installer_status"] == "EXIT_CAPTURED"
        and original["installer_exit"] == "MSI_FATAL_ERROR"
        and original["installer_exit_hex"] == "00000643"
        and original["installer_child_lifecycle"] == "ALL_EXITED"
        and original["candidate_native40"] is False
        and original["clr64_after"] == "ABSENT"
        and original["clr32_after"] == "ABSENT"
        and original["mscorlib64_after"] == "ABSENT"
        and restarted["status"] == "NOT_ELIGIBLE"
        and restarted["persistent_native_managed"] is False
    ):
        return "DENIED"
    return "RETRY_ELIGIBLE"


def prepare(wine: Path, prefix: Path, original: object, restarted: object,
            *, agreed: bool = False) -> str:
    state = decision(original, restarted)
    if state != "RETRY_ELIGIBLE":
        return state
    runner = os.environ.get("RUNNER_TEMP", "")
    if not agreed or os.name == "nt" or not runner:
        return "DENIED"
    root = Path(runner)
    archive = root / ARCHIVE
    try:
        if (root.is_symlink() or not root.is_dir()
                or prefix.is_symlink() or prefix.name != CANONICAL
                or prefix.parent.resolve(strict=True) != root.resolve(strict=True)
                or not prefix.is_dir()
                or not (prefix / MARKER).is_file()
                or (prefix / MARKER).is_symlink()
                or archive.exists() or archive.is_symlink()):
            return "DENIED"
        # The existing CI-safe helper checks Wine installation provenance,
        # marker, prefix identity and symlinks, and waits for wineserver exit.
        if not _terminate_private_setup_wineserver(wine, prefix):
            return "DENIED"
        prefix.rename(archive)
        return "FRESH_PREFIX_REQUIRED"
    except (OSError, ValueError):
        return "DENIED"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--wine", type=Path, required=True)
    parser.add_argument("--prefix", type=Path, required=True)
    parser.add_argument("--original", type=Path, required=True)
    parser.add_argument("--restart", type=Path, required=True)
    parser.add_argument("--agree-disposable-prefix", action="store_true")
    args = parser.parse_args()
    try:
        original = json.loads(args.original.read_text(encoding="utf-8"))
        restarted = json.loads(args.restart.read_text(encoding="utf-8"))
        result = prepare(args.wine, args.prefix, original, restarted,
                         agreed=args.agree_disposable_prefix)
    except (OSError, ValueError, json.JSONDecodeError):
        result = "DENIED"
    print(result)  # One fixed value. No installer, prefix, logs or secrets.
    return 0 if result in {"ALREADY_VERIFIED", "FRESH_PREFIX_REQUIRED"} else 2


if __name__ == "__main__":
    raise SystemExit(main())
