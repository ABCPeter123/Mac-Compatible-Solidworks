"""Require a genuine, ready WebView2 controller before launching SOLIDWORKS.

The independent runtime installer runs only in a disposable Wine prefix.
Never print raw report fields, file paths, browser versions or license data.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path

def evaluate(report: object) -> dict[str, str | bool]:
    if not isinstance(report, dict) or report.get("schema") != 1:
        raise ValueError("Invalid report schema")
    if report.get("scope") != "OFFICIAL_INSTALLER_TRIAL_NOT_SOLIDWORKS":
        raise ValueError("Unexpected report source")
    if report.get("installer_execution") not in {"EXIT_ZERO", "EXIT_NONZERO", "TIMEOUT", "PROCESS_ERROR"}:
        raise ValueError("Invalid installer status")
    if report.get("controller_transition") not in {
        "BECAME_READY", "REMAINED_READY", "REGRESSED", "REMAINED_UNAVAILABLE", "UNKNOWN"
    }:
        raise ValueError("Invalid controller transition")
    for key in ("installer_sha256_verified", "runtime_installation_confirmed", "browser_controller_confirmed"):
        if type(report.get(key)) is not bool:
            raise ValueError("Missing boolean prerequisite field")
    after = report.get("after")
    if not isinstance(after, dict):
        raise ValueError("Missing post-install probe")
    ready = (
        report["installer_execution"] == "EXIT_ZERO"
        and report["installer_sha256_verified"]
        and report["runtime_installation_confirmed"]
        and report["browser_controller_confirmed"]
        and report["controller_transition"] == "BECAME_READY"
        and after.get("probe_result") == "COMPLETE"
        and after.get("controller_creation") == "READY"
    )
    return {"ready": ready, "prerequisite": "WEBVIEW2_READY" if ready else "WEBVIEW2_NOT_READY"}

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Fail-closed Microsoft WebView2 prereq gate")
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--require-ready", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.input.stat().st_size > 16384:
            raise ValueError("Oversized report")
        verdict = evaluate(json.loads(args.input.read_text(encoding="utf-8")))
    except (OSError, ValueError, UnicodeError):
        verdict = {"ready": False, "prerequisite": "WEBVIEW2_NOT_READY"}
    print("WebView2 prerequisite: " + verdict["prerequisite"])
    print("SOLIDWORKS installation: NOT_VERIFIED")
    return 0 if verdict["ready"] or not args.require_ready else 1

if __name__ == "__main__":
    raise SystemExit(main())
