"""Strict report for an original Windows service single-SCM-handle lifecycle."""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

PATTERN = re.compile(r"^SWCOMPAT_SERVICE_SINGLE_([A-Z0-9_]+)=([0-9A-Z]+)$")
REQUIRED = {
    "CREATE": "PASS",
    "START_ERROR": "0",
    "RUNNING_STATE": "4",
    "STOP_ERROR": "0",
    "STOPPED_STATE": "1",
    "DELETE_ERROR": "0",
    "REMOVED": "1",
    "PROCESS": "PASS",
}


def analyze(output: str, exit_code: int) -> dict:
    fields = {}
    for line in output.splitlines():
        match = PATTERN.fullmatch(line.strip())
        if match:
            fields[match.group(1)] = match.group(2)
    failures = [key for key, expected in REQUIRED.items()
                if fields.get(key) != expected]
    pid = fields.get("RUNNING_PID", "0")
    if not pid.isdecimal() or int(pid) <= 0:
        failures.append("RUNNING_PID")
    if exit_code != 0:
        failures.append("EXIT_CODE")
    return {
        "scenario": "single_process_windows_service_lifecycle",
        "passed": not failures,
        "exit_code": exit_code,
        "markers": fields,
        "failed_checks": failures,
        "scope": "One original harmless Win64 service with one retained SCM handle. "
                 "Does not establish multi-process services, kernel drivers, "
                 "licensed SOLIDWORKS services, or production readiness.",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--exit-code", type=int, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--summary", type=Path)
    args = parser.parse_args()
    report = analyze(args.input.read_text(encoding="utf-8", errors="replace"), args.exit_code)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    result = "PASS" if report["passed"] else "FAIL"
    print("Single-process Windows service lifecycle:", result)
    if not report["passed"]:
        print("Failed markers:", ", ".join(report["failed_checks"]))
    if args.summary:
        with args.summary.open("a", encoding="utf-8") as dest:
            dest.write(f"## Windows service single-process compatibility: {result}\n\n")
            dest.write(f"Observed running PID: {report['markers'].get('RUNNING_PID', 'none')}\n\n")
            dest.write("Tests original user-level SCM service only, not SOLIDWORKS.\n")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
