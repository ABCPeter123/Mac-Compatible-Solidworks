"""Test dynamic MSVC-built x86/x64 programs under Wine and native Windows."""
from __future__ import annotations
import argparse
import json
from pathlib import Path

from scripts.functional_smoke import execute, wine_environment
from swcompat.cli import find_wine

REQUIRED = ("STL", "ASYNC", "STREAM", "FILEIO", "RUNTIME")


def passed(run: dict, bits: int) -> bool:
    lines = set(run.get("output", "").splitlines())
    return (run.get("exit_code") == 0
            and all(f"SWCOMPAT_MSVC_{section}=PASS" in lines for section in REQUIRED)
            and f"SWCOMPAT_MSVC_PROCESS_BITS={bits}" in lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", choices=["native", "wine"], required=True)
    parser.add_argument("--arch", choices=["x64", "x86"], required=True)
    parser.add_argument("--prefix", type=Path, default=Path.home() / ".wine")
    parser.add_argument("--wine")
    parser.add_argument("--exe", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    exe = args.exe.expanduser().resolve()
    if not exe.is_file():
        parser.error(f"MSVC test program missing: {exe}")
    wine = find_wine(args.wine) if args.host == "wine" else None
    if args.host == "wine" and not wine:
        parser.error("Wine unavailable")
    env = wine_environment(args.prefix.expanduser().resolve(), args.host)
    command = [str(exe)] if args.host == "native" else [str(wine), str(exe)]
    run = execute(command, env, timeout=90)
    bits = 64 if args.arch == "x64" else 32
    report = {
        "host": args.host,
        "architecture": args.arch,
        "test": "MSVC /MD dynamic runtime C++17",
        "execution": run,
        "passed": passed(run, bits),
        "scope": "Limited C++ standard library and runtime behavior, not official VC++ redistributable installation or SOLIDWORKS support.",
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"MSVC {args.arch}: {'PASS' if report['passed'] else 'FAIL'}")
    for line in run["output"].splitlines():
        if line.startswith("SWCOMPAT_MSVC_"):
            print(line[:400])
    print("Process exit:", run["exit_code"])
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
