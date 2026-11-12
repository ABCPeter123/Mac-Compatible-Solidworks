"""Machine-readable diagnostics collected on macOS GitHub Actions runners."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import platform

from swcompat.cli import DEFAULT_PREFIX, diagnostic, find_wine

def build_report():
    data = diagnostic(find_wine(), DEFAULT_PREFIX)
    data["reported_at_utc"] = datetime.now(timezone.utc).isoformat()
    data["github_runner_os"] = os.environ.get("RUNNER_OS")
    data["github_runner_arch"] = os.environ.get("RUNNER_ARCH")
    data["github_image"] = os.environ.get("ImageOS")
    data["github_image_version"] = os.environ.get("ImageVersion")
    metal = Path("build/metal-probe.txt")
    data["native_metal_probe"] = metal.read_text() if metal.exists() else None
    return data

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--require-macos", action="store_true")
    args = p.parse_args()
    report = build_report()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(f"wrote {args.output}, host={report['host_os']}, cpu={report['cpu_arch']}")
    if args.require_macos and report["host_os"] != "Darwin":
        return 1
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
