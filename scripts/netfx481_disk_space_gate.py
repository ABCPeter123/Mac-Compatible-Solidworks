"""Classify .NET 4.8.1 disk-space Win32 API behavior without recording bytes.

This source-authored probe is read-only. It cannot authenticate the original
Microsoft installer, infer its checks, or install a CLR. Only finite categories
can leave the runner.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import subprocess

from scripts.netfx481_trial import validate_prefix

CAPACITIES = {"ABOVE_5GB", "BORDERLINE_4P5_5GB",
              "BELOW_4P5GB", "API_FAILED"}
TEMP_CAPACITIES = CAPACITIES | {"TEMP_PATH_FAILED"}
SAME_VOLUME = {"YES", "NO", "UNKNOWN"}
PATTERN = re.compile(rb"SWCOMPAT_DISK_(SCHEMA|C|TEMP|LEGACY|TEMP_SAME_VOLUME)=([A-Z0-9_]+)\Z")
FIELDS = {"SCHEMA", "C", "TEMP", "LEGACY", "TEMP_SAME_VOLUME"}
MAX_BYTES = 512


def empty() -> dict[str, str]:
    return {"status": "INVALID", "c_drive": "NOT_VERIFIED",
            "temp": "NOT_VERIFIED", "legacy_c": "NOT_VERIFIED",
            "temp_same_volume": "UNKNOWN"}


def valid(value: object) -> bool:
    if type(value) is not dict or set(value) != set(empty()):
        return False
    if value["status"] == "INVALID":
        return value == empty()
    return (value["status"] == "MEASURED"
            and value["c_drive"] in CAPACITIES
            and value["temp"] in TEMP_CAPACITIES
            and value["legacy_c"] in CAPACITIES
            and value["temp_same_volume"] in SAME_VOLUME)


def parse(raw: bytes, rc: int) -> dict[str, str]:
    if (not isinstance(raw, bytes) or len(raw) > MAX_BYTES or rc != 0
            or b"\x00" in raw):
        return empty()
    fields: dict[str, str] = {}
    for line in raw.splitlines():
        match = PATTERN.fullmatch(line)
        if match is None:
            return empty()
        key, value = (item.decode("ascii") for item in match.groups())
        if key in fields:
            return empty()
        fields[key] = value
    if set(fields) != FIELDS or fields["SCHEMA"] != "1":
        return empty()
    result = {"status": "MEASURED", "c_drive": fields["C"],
              "temp": fields["TEMP"], "legacy_c": fields["LEGACY"],
              "temp_same_volume": fields["TEMP_SAME_VOLUME"]}
    return result if valid(result) else empty()


def run(wine: Path, prefix: Path, fixture: Path, timeout: int = 45) -> dict[str, str]:
    if os.name == "nt" or not 15 <= timeout <= 90:
        raise ValueError("Read-only differential requires bounded Wine context")
    if any(p.is_symlink() for p in (wine, prefix, fixture)):
        raise ValueError("Symlinked probe inputs rejected")
    wine, prefix, fixture = (p.resolve(strict=True) for p in (wine, prefix, fixture))
    validate_prefix(prefix)
    if (fixture.name != "netfx481_disk_space_gate.exe"
            or not wine.is_file() or not os.access(wine, os.X_OK)
            or not fixture.is_file()):
        raise ValueError("Unexpected source-authored disk probe")
    env = os.environ.copy()
    env.pop("WINEDLLOVERRIDES", None)
    env.update({"WINEPREFIX": str(prefix), "WINEARCH": "win64", "WINEDEBUG": "-all"})
    try:
        output = subprocess.run(
            [str(wine), str(fixture)], cwd=prefix, env=env,
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, timeout=timeout, check=False,
        )
        result = parse(output.stdout[:MAX_BYTES + 1], output.returncode)
    except (OSError, subprocess.TimeoutExpired):
        result = empty()
    assert valid(result)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Read-only .NET disk capacity prerequisite")
    for name in ("wine", "prefix", "fixture", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--agree-disposable-prefix", action="store_true", required=True)
    args = parser.parse_args()
    result = run(args.wine, args.prefix, args.fixture)
    if args.output.is_symlink():
        raise ValueError("Symlinked evidence output")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, sort_keys=True), encoding="ascii")
    for name, value in result.items():
        print("Original .NET 4.8.1 disk prerequisite differential", name, value)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
