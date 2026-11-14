"""Run self-authored, read-only Windows Installer probe under a disposable Wine prefix.

Output is restricted to six enumerated strings. Native Windows and Wine run
the exact same MSVC x64 binary. No MSI install, service start/stop, registry
mutation, raw Wine stdout/stderr or vendor media inspection is performed.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile

from scripts.netfx481_trial import validate_prefix

FIELDS = {
    "SCHEMA": {"1"},
    "REGISTRY": {"PRESENT", "ABSENT", "UNAVAILABLE"},
    "SERVICE": {"PRESENT", "ABSENT", "UNAVAILABLE"},
    "SERVICE_STATE": {"STOPPED", "RUNNING", "START_PENDING", "OTHER",
                      "UNAVAILABLE", "NOT_VERIFIED"},
    "DLL_API": {"BOTH_PRESENT", "PARTIAL", "NO_EXPORTS", "LOAD_FAILED"},
    "EXEC": {"PRESENT", "ABSENT", "UNAVAILABLE"},
}
FIELD_NAMES = tuple(key.lower() for key in FIELDS if key != "SCHEMA")
MAX_OUTPUT = 2048
NO_REPORT = {key: "NOT_VERIFIED" for key in FIELD_NAMES}


def parse(raw: bytes, process_code: int) -> dict[str, str]:
    if process_code != 0 or len(raw) > MAX_OUTPUT or b"\x00" in raw:
        return NO_REPORT.copy()
    try:
        lines = raw.decode("ascii").splitlines()
    except UnicodeDecodeError:
        return NO_REPORT.copy()
    values: dict[str, str] = {}
    for line in lines:
        if not line.startswith("SWCOMPAT_MSI_"):
            continue
        if "=" not in line:
            return NO_REPORT.copy()
        key, value = line[len("SWCOMPAT_MSI_"):].split("=", 1)
        if key not in FIELDS or key in values or value not in FIELDS[key]:
            return NO_REPORT.copy()
        values[key] = value
    if set(values) != set(FIELDS) or values["SCHEMA"] != "1":
        return NO_REPORT.copy()
    report = {name.lower(): values[name] for name in FIELDS if name != "SCHEMA"}
    if ((report["service"] == "ABSENT" and report["service_state"] != "NOT_VERIFIED")
            or (report["service"] == "PRESENT"
                and report["service_state"] == "NOT_VERIFIED")):
        return NO_REPORT.copy()
    return report


def validate(report: dict) -> bool:
    if type(report) is not dict or set(report) != set(FIELD_NAMES):
        return False
    for name in FIELDS:
        if name == "SCHEMA":
            continue
        if type(report[name.lower()]) is not str or (
                report[name.lower()] not in (FIELDS[name] | {"NOT_VERIFIED"})):
            return False
    if report == NO_REPORT:
        return True
    return (report["registry"] != "NOT_VERIFIED"
            and report["service"] != "NOT_VERIFIED"
            and report["service_state"] != "NOT_VERIFIED" if report["service"] == "PRESENT"
            else (report["registry"] != "NOT_VERIFIED"
                  and report["service"] != "NOT_VERIFIED"
                  and report["service_state"] == "NOT_VERIFIED"))


def run(wine: Path, prefix: Path, fixture: Path, timeout: int = 35) -> dict[str, str]:
    validate_prefix(prefix)
    if fixture.is_symlink() or fixture.name.casefold() != "msi_service_capability.exe" or not fixture.is_file():
        raise ValueError("Expected self-authored MSI read-only probe")
    if wine.is_symlink() or not wine.is_file():
        raise ValueError("Wine binary missing")
    fixture = fixture.resolve(strict=True)
    wine = wine.resolve(strict=True)
    prefix = prefix.resolve(strict=True)
    env = os.environ.copy()
    env.pop("WINEDLLOVERRIDES", None)
    env.update({"WINEPREFIX": str(prefix), "WINEARCH": "win64", "WINEDEBUG": "-all"})
    with tempfile.TemporaryFile() as output:
        try:
            result = subprocess.run(
                [str(wine), str(fixture)], cwd=fixture.parent,
                env=env, stdin=subprocess.DEVNULL, stdout=output,
                stderr=subprocess.DEVNULL, timeout=timeout, check=False)
            code = result.returncode
        except (OSError, subprocess.TimeoutExpired):
            code = 124
        output.seek(0)
        data = output.read(MAX_OUTPUT + 1)
    report = parse(data, code)
    if not validate(report):
        raise ValueError("Unsafe Windows Installer infrastructure report")
    return report


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Read-only Windows Installer service and DLL probe")
    for name in ("wine", "prefix", "fixture", "output"):
        p.add_argument("--" + name, required=True, type=Path)
    args = p.parse_args(argv)
    try:
        if args.output.is_symlink() or args.output.resolve() in {
            args.wine.resolve(), args.fixture.resolve(), args.prefix.resolve()}:
            raise ValueError("Unsafe diagnostic output path")
        report = run(args.wine, args.prefix, args.fixture)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    except (OSError, ValueError):
        p.error("Read-only MSI probe refused")
    for name in FIELD_NAMES:
        print("Windows Installer probe", name, report[name])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
