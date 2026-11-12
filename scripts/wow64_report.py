"""Validate functional 32-bit Windows helper compatibility on a 64-bit host."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
from scripts.prereq_report import parse_probe

CHECKS = ("MSI_EXPORTS", "COM_APARTMENT", "SHELLLINK_COM", "SCM_CONNECT", "TEMP_PATH")


def assess(markers: dict[str, str], host: str) -> dict:
    results = {name: markers.get(name, "NOT_REPORTED") for name in CHECKS}
    bits = markers.get("PROCESS_BITS")
    return {
        "host": host,
        "windows_process_bits": bits,
        "native_cpu_arch": markers.get("PROCESSOR_ARCH"),
        "functional_signals": results,
        "vc_x86_registry_indicator": markers.get("VC_X86_REGISTRY", "NOT_REPORTED"),
        "passed": bits == "32" and all(value == "PRESENT" for value in results.values()),
        "scope": "Verifies a 32-bit Windows process and narrow Win32/COM/MSI capabilities; does not test the Microsoft VC++ 2022 x86 redistributable or SOLIDWORKS.",
    }


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--input", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--host", required=True)
    args = p.parse_args()
    try:
        markers = parse_probe(args.input.read_text(encoding="utf-8", errors="replace"))
        result = assess(markers, args.host)
    except ValueError as exc:
        result = {"host": args.host, "passed": False, "reason": str(exc)}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
