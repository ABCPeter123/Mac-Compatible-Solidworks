"""Execute a read-only self-authored Win32 Windows component servicing probe.

The probe checks the presence of CBS metadata, TrustedInstaller service and
DISM APIs on real Windows vs the pinned Apple Silicon Wine build. No servicing
operation, package installation or mutation occurs. Do not infer that a
present API implements real package application.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile

FIELDS = {
    "SCHEMA": {"1"},
    "REGISTRY": {"PRESENT", "ABSENT", "UNAVAILABLE"},
    "PACKAGES": {"PRESENT", "ABSENT", "UNAVAILABLE"},
    "TRUSTEDINSTALLER": {"PRESENT", "ABSENT", "UNAVAILABLE"},
    "DISMAPI": {"EXPORT_PRESENT", "EXPORT_MISSING", "LOAD_FAILED", "ABSENT", "UNAVAILABLE"},
}
MAX_OUTPUT = 2048


def blank() -> dict[str, str]:
    return {name.lower(): "NOT_VERIFIED" for name in FIELDS if name != "SCHEMA"}


def parse(raw: bytes, code: int) -> dict[str, str]:
    if code != 0 or len(raw) > MAX_OUTPUT or b"\0" in raw:
        return blank()
    try:
        lines = raw.decode("ascii").splitlines()
    except UnicodeDecodeError:
        return blank()
    fields: dict[str, str] = {}
    for line in lines:
        if not line.startswith("SWCOMPAT_CBS_"):
            continue
        if "=" not in line:
            return blank()
        name, value = line[len("SWCOMPAT_CBS_"):].split("=", 1)
        if name in fields or name not in FIELDS or value not in FIELDS[name]:
            return blank()
        fields[name] = value
    if set(fields) != set(FIELDS):
        return blank()
    return {name.lower(): fields[name] for name in FIELDS if name != "SCHEMA"}


def validate(report: dict) -> bool:
    if not isinstance(report, dict) or set(report) != {
        name.lower() for name in FIELDS if name != "SCHEMA"
    }:
        return False
    return all(type(report[name.lower()]) is str
               and report[name.lower()] in (values | {"NOT_VERIFIED"})
               for name, values in FIELDS.items() if name != "SCHEMA")


def run(wine: Path, prefix: Path, executable: Path, timeout: int = 30) -> dict:
    from scripts.netfx481_trial import validate_prefix

    validate_prefix(prefix)
    if (executable.is_symlink() or not executable.is_file()
            or executable.name.casefold() != "netfx481_cbs_capability.exe"):
        raise ValueError("Expected self-authored signed-on-Windows CBS capability probe")
    if not wine.is_file() or wine.is_symlink():
        raise ValueError("Expected fixed Wine binary")
    env = os.environ.copy()
    env.pop("WINEDLLOVERRIDES", None)
    env.update({"WINEPREFIX": str(prefix), "WINEARCH": "win64", "WINEDEBUG": "-all"})
    with tempfile.TemporaryFile() as stdout:
        try:
            proc = subprocess.run(
                [str(wine), str(executable)], cwd=executable.parent,
                env=env, stdin=subprocess.DEVNULL,
                stdout=stdout, stderr=subprocess.DEVNULL,
                check=False, timeout=timeout,
            )
            rc = proc.returncode
        except (OSError, subprocess.TimeoutExpired):
            rc = 124
        stdout.seek(0)
        raw = stdout.read(MAX_OUTPUT + 1)
        result = parse(raw, rc)
    # Never show raw Wine output or private paths. Only fixed lifecycle states
    # and a bounded count of our own expected markers may enter job logs.
    if rc == 124:
        status = "TIMED_OUT_OR_LAUNCH_FAILED"
    elif rc != 0:
        status = "PROCESS_NONZERO"
    elif result == blank():
        status = "INVALID_OR_INCOMPLETE_REPORT"
    else:
        status = "STRUCTURED_REPORT"
    count = min(len(FIELDS), sum(
        1 for line in raw.splitlines() if line.startswith(b"SWCOMPAT_CBS_")
    ))
    print("Win32 CBS fixture execution:", status)
    print("Self-authored CBS marker lines:", count)
    if not validate(result):
        raise ValueError("Invalid CBS capability evidence")
    return result


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Read-only Wine component servicing capability inventory")
    p.add_argument("--wine", type=Path, required=True)
    p.add_argument("--prefix", type=Path, required=True)
    p.add_argument("--fixture", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args(argv)
    if any(path.is_symlink() for path in (args.wine, args.prefix, args.fixture, args.output)):
        p.error("Linked inputs or output forbidden")
    if args.output.resolve() in {args.wine.resolve(), args.fixture.resolve()}:
        p.error("Result would overwrite diagnostic binary")
    result = run(args.wine, args.prefix, args.fixture)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    for name in ("registry", "packages", "trustedinstaller", "dismapi"):
        print("Windows component servicing", name, result[name])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
