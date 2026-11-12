"""Functional Windows Installer and .NET Framework probes, without SOLIDWORKS files.

Runs only original harmless test binaries in a disposable Wine prefix or CI Windows.
Reports installation, registration, uninstall and managed execution separately.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

from swcompat.cli import find_wine

PRODUCT_CODE = "{EB00D74E-5D24-49C6-BFB1-FF694AE23719}"


def wine_path(path: Path) -> str:
    absolute = path.expanduser().resolve()
    if not absolute.is_absolute() or not str(absolute).startswith("/"):
        raise ValueError("Wine path conversion needs an absolute Unix path.")
    return "Z:" + str(absolute).replace("/", "\\")


def execute(command: list[str], env: dict[str, str], timeout: int = 120) -> dict:
    try:
        result = subprocess.run(command, capture_output=True, text=True, errors="replace",
                                env=env, timeout=timeout, check=False)
        return {
            "exit_code": result.returncode,
            "output": (result.stdout + "\n" + result.stderr)[-6000:],
        }
    except subprocess.TimeoutExpired:
        return {"exit_code": 124, "output": "SWCOMPAT_PROCESS_TIMED_OUT=1"}
    except OSError as exc:
        return {"exit_code": 127, "output": "SWCOMPAT_PROCESS_ERROR=" + type(exc).__name__}


def validate_marker(run: dict, label: str) -> bool:
    return run["exit_code"] == 0 and label in run["output"].splitlines()


def wine_environment(prefix: Path, host: str) -> dict[str, str]:
    env = os.environ.copy()
    if host == "wine":
        if not (prefix / "drive_c").is_dir():
            raise ValueError("Wine prefix not initialized.")
        env.update({"WINEPREFIX": str(prefix), "WINEARCH": "win64", "WINEDEBUG": "-all"})
    return env


def run_msi(host: str, wine: str | None, prefix: Path, msi: Path, helper: Path) -> dict:
    if not msi.is_file() or not helper.is_file():
        raise ValueError("Both the self-authored MSI and checker executable must exist.")
    env = wine_environment(prefix, host)
    path = wine_path(msi) if host == "wine" else str(msi)
    def check(phase: str) -> dict:
        argv = [str(helper), phase]
        if host == "wine":
            argv.insert(0, wine)
        return execute(argv, env)

    def transaction(action: str) -> dict:
        argv = (["msiexec.exe"] if host == "native" else [wine, "msiexec.exe"])
        argv.extend([action, path if action == "/i" else PRODUCT_CODE, "/qn", "/norestart"])
        return execute(argv, env, timeout=180)

    output = {"scenario": "msi_roundtrip", "host": host}
    output["before"] = check("removed")
    if not validate_marker(output["before"], "SWCOMPAT_MSI_CHECK=PASS"):
        output["passed"] = False
        output["reason"] = "Package was already installed or initial state check failed."
        return output
    output["install"] = transaction("/i")
    try:
        output["installed_check"] = check("installed")
        output["uninstall"] = transaction("/x")
        output["removed_check"] = check("removed")
    finally:
        # Failed assertions or tests should not leave test packages installed.
        if not validate_marker(output.get("removed_check", {}), "SWCOMPAT_MSI_CHECK=PASS"):
            output["cleanup_attempt"] = transaction("/x")

    output["passed"] = (
        output["install"]["exit_code"] == 0
        and validate_marker(output["installed_check"], "SWCOMPAT_MSI_CHECK=PASS")
        and output["uninstall"]["exit_code"] == 0
        and validate_marker(output["removed_check"], "SWCOMPAT_MSI_CHECK=PASS")
    )
    return output


def run_managed(host: str, wine: str | None, prefix: Path, exe: Path) -> dict:
    if not exe.is_file():
        raise ValueError("Missing the self-authored .NET Framework executable.")
    env = wine_environment(prefix, host)
    cmd = [str(exe)] if host == "native" else [wine, str(exe)]
    run = execute(cmd, env, timeout=90)
    markers = ["SWCOMPAT_DOTNET=PASS", "SWCOMPAT_DOTNET_TASKS=PASS",
               "SWCOMPAT_DOTNET_XML=PASS", "SWCOMPAT_DOTNET_CRYPTO=PASS",
               "SWCOMPAT_DOTNET_FILEIO=PASS"]
    return {"scenario": "dotnet_framework_smoke", "host": host,
            "execution": run, "passed": all(validate_marker(run, x) for x in markers),
            "scope": "CLR 4 managed code execution; does not prove .NET Framework 4.8.1 is installed."}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("scenario", choices=["msi", "managed"])
    p.add_argument("--host", choices=["wine", "native"], required=True)
    p.add_argument("--wine", default=None)
    p.add_argument("--prefix", type=Path, default=Path.home() / ".wine")
    p.add_argument("--msi", type=Path, default=Path("build/msi_probe.msi"))
    p.add_argument("--checker", type=Path, default=Path("build/msi_check.exe"))
    p.add_argument("--exe", type=Path, default=Path("build/dotnet_smoke.exe"))
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args(argv)
    wine = find_wine(args.wine) if args.host == "wine" else None
    if args.host == "wine" and not wine:
        p.error("Wine executable missing. Supply --wine or SWCOMPAT_WINE.")
    try:
        prefix = args.prefix.expanduser().resolve()
        report = (run_msi(args.host, str(wine) if wine else None, prefix,
                          args.msi.resolve(), args.checker.resolve())
                  if args.scenario == "msi" else
                  run_managed(args.host, str(wine) if wine else None, prefix, args.exe.resolve()))
    except ValueError as exc:
        report = {"scenario": args.scenario, "host": args.host, "passed": False,
                  "error": str(exc)}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"{args.scenario}: {'PASS' if report['passed'] else 'FAIL'} ({args.host})")
    for key, item in report.items():
        if isinstance(item, dict) and "exit_code" in item:
            print(f"{key}: exit_code={item['exit_code']}")
            for line in item.get("output", "").splitlines():
                if line.startswith("SWCOMPAT_"):
                    print("  " + line[:200])
    print("Report:", args.output)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
