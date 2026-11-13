"""Controlled synthetic Win32 GDI reference in an isolated Wine prefix.

Runs only our original, nonproprietary Windows x64 window probe.
Exports allowlisted status only; never window data, binary bytes, paths,
process logs, URL, serial numbers, or user-provided content.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess

from scripts.solidworks_bootstrap_trial import validate_prefix

REPORT_SCHEMA = 1
STATES = {
    "REFERENCE_PASS",
    "REFERENCE_FAILED",
    "REFERENCE_TIMEOUT",
    "REFERENCE_UNAVAILABLE",
    "REFERENCE_UNEXPECTED",
}


def run_reference(wine: Path, prefix: Path, probe: Path, *, timeout: int = 40) -> dict:
    if os.name == "nt":
        raise ValueError("Wine reference must not run on native Windows")
    validate_prefix(prefix)
    if not wine.is_file() or not os.access(wine, os.X_OK):
        raise ValueError("Wine must be an executable file")
    if probe.suffix.lower() != ".exe" or probe.is_symlink() or not probe.is_file():
        raise ValueError("Original Windows window probe executable required")
    if not 10 <= timeout <= 60:
        raise ValueError("Reference timeout outside allowed limits")

    env = os.environ.copy()
    env.update({"WINEPREFIX": str(prefix), "WINEARCH": "win64", "WINEDEBUG": "-all"})
    state = "REFERENCE_UNAVAILABLE"
    try:
        outcome = subprocess.run(
            [str(wine), str(probe), "--self-test"], cwd=str(prefix), env=env,
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, timeout=timeout, check=False,
            start_new_session=True,
        )
        # Zero tolerance for arbitrary text in report or CI output.
        if len(outcome.stdout) <= 256:
            marker = outcome.stdout.decode("ascii", errors="replace").strip()
            if marker == "SWCOMPAT_SW_UI_SELF_TEST=PASS" and outcome.returncode == 0:
                state = "REFERENCE_PASS"
            elif marker == "SWCOMPAT_SW_UI_SELF_TEST=FAIL" and outcome.returncode != 0:
                state = "REFERENCE_FAILED"
            else:
                state = "REFERENCE_UNEXPECTED"
        else:
            state = "REFERENCE_UNEXPECTED"
    except subprocess.TimeoutExpired:
        state = "REFERENCE_TIMEOUT"
    except OSError:
        state = "REFERENCE_UNAVAILABLE"
    return {
        "schema": REPORT_SCHEMA,
        "component": "Original synthetic Win32 HWND and GDI reference under Wine",
        "reference": state,
        "synthetic_only": True,
        "original_solidworks_installer": "NOT_USED",
        "macos_onscreen_pixels": "NOT_VERIFIED",
        "solidworks_compatibility": "NOT_DEMONSTRATED",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Synthetic Win32 GDI reference, sanitized diagnostics")
    parser.add_argument("--wine", type=Path, required=True)
    parser.add_argument("--prefix", type=Path, required=True)
    parser.add_argument("--probe", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        out = args.output.expanduser().resolve()
        prefix = args.prefix.expanduser().resolve()
        if out.is_relative_to(prefix) or out == args.probe.expanduser().resolve():
            raise ValueError("Output must be outside Wine prefix and executable")
        report = run_reference(
            args.wine.expanduser(), prefix, args.probe.expanduser().resolve()
        )
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    except (OSError, ValueError):
        parser.error("Synthetic Win32 GDI reference could not run safely")
    print("Apple Silicon Wine synthetic GDI reference:", report["reference"])
    print("Original SOLIDWORKS installer in reference: NOT_USED")
    print("macOS onscreen pixel output: NOT_VERIFIED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
