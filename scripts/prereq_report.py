"""Turn read-only Windows probe output into constrained, machine-readable evidence.

A registry key or DLL export is not proof of a working runtime or SOLIDWORKS.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import re

MARKER = re.compile(r"^SWCOMPAT_PREREQ_([A-Z0-9_]+)=([^\r\n]{0,512})$")


def parse_probe(output: str) -> dict[str, str]:
    findings = {}
    for line in output.splitlines():
        match = MARKER.fullmatch(line.strip())
        if match:
            findings[match.group(1)] = match.group(2)
    if findings.get("SCHEMA") != "1" or findings.get("PROBE") != "PASS":
        raise ValueError("Incomplete or unsupported prerequisite probe (expected schema 1 and PASS).")
    return findings


def make_report(probe: dict[str, str], catalog: dict, *, host: str) -> dict:
    rows = []
    for req in catalog["requirements"]:
        key = req["probe"]
        signal = probe.get(key, "NOT_TESTED") if key else "NOT_TESTED"
        if signal not in ("PRESENT", "ABSENT", "NOT_TESTED"):
            signal = "UNKNOWN"
        rows.append({
            "id": req["id"], "name": req["name"],
            "classification": req["classification"],
            "signal": signal, "evidence_type": req["verification"],
        })
    return {
        "target": catalog["product"], "host_label": host,
        "probe_executed": True,
        "windows_reported_version": {
            "major": probe.get("WINDOWS_MAJOR"),
            "minor": probe.get("WINDOWS_MINOR"),
            "build": probe.get("WINDOWS_BUILD"),
        },
        "windows_process_arch": probe.get("PROCESSOR_ARCH"),
        "netfx_registry_release": probe.get("NETFX_RELEASE"),
        "runtime_signals": rows,
        "warning": "Diagnostics only. DLL exports and registry indicators do not demonstrate functional dependencies, installer success, licensing, or SOLIDWORKS CAD compatibility.",
    }


def markdown_report(report: dict) -> str:
    parts = [
        f"## SOLIDWORKS prerequisite reconnaissance: {report['host_label']}",
        "",
        "Probe completed. Statuses represent limited technical signals, not installation readiness.",
        "",
        "| Requirement | Signal | What we measured |",
        "| --- | --- | --- |",
    ]
    for row in report["runtime_signals"]:
        parts.append(f"| {row['name']} | {row['signal']} | {row['evidence_type']} |")
    parts.extend(("", report["warning"], ""))
    return "\n".join(parts)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--catalog", type=Path, default=Path("config/prerequisites_2026.json"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--host", required=True)
    parser.add_argument("--summary", type=Path)
    args = parser.parse_args()
    catalog = json.loads(args.catalog.read_text(encoding="utf-8"))
    probe = parse_probe(args.input.read_text(encoding="utf-8", errors="replace"))
    report = make_report(probe, catalog, host=args.host)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    summary = markdown_report(report)
    print(summary)
    if args.summary:
        with args.summary.open("a", encoding="utf-8") as stream:
            stream.write(summary + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
