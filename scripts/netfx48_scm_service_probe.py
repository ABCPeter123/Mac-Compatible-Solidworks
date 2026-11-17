"""Read-only source-authored Windows x64 SCM fixture, bounded private results.

Runs only in an existing marked disposable Wine prefix. It cannot configure
services or copy raw Wine/Windows output to logs or GitHub artifacts.
"""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile

from scripts.netfx481_trial import validate_prefix

FIELDS = ("TRUSTEDINSTALLER", "MSISERVER", "WUAUSERV", "BITS")
VALUES = {"NOT_RUN", "PRESENT", "ABSENT", "ACCESS_DENIED", "UNKNOWN"}
STATUSES = {"NOT_RUN", "COMPLETE", "UNAVAILABLE", "MALFORMED", "TIMEOUT",
            "PROCESS_FAILED", "EMPTY_OUTPUT", "OVERSIZED_OUTPUT", "NONZERO_EXIT"}
MAX_BYTES = 512
PREFIX = "SWCOMPAT_SCM_API_"


def blank(status: str = "NOT_RUN") -> dict:
    if status not in STATUSES:
        raise ValueError("Invalid SCM status")
    return {"status": status, "services": {field: "NOT_RUN" for field in FIELDS}}


def valid(report: object) -> bool:
    if type(report) is not dict or set(report) != {"status", "services"}:
        return False
    if (report["status"] not in STATUSES
            or type(report["services"]) is not dict
            or set(report["services"]) != set(FIELDS)
            or any(type(value) is not str or value not in VALUES
                   for value in report["services"].values())):
        return False
    if report["status"] in {"NOT_RUN", "MALFORMED", "TIMEOUT", "PROCESS_FAILED",
                            "EMPTY_OUTPUT", "OVERSIZED_OUTPUT", "NONZERO_EXIT"}:
        return report == blank(report["status"])
    if report["status"] == "UNAVAILABLE":
        return all(value == "UNKNOWN" for value in report["services"].values())
    return all(value != "NOT_RUN" for value in report["services"].values())


def parse(raw: bytes, exit_code: int) -> dict:
    if exit_code != 0:
        return blank("NONZERO_EXIT")
    if not raw:
        return blank("EMPTY_OUTPUT")
    if len(raw) > MAX_BYTES:
        return blank("OVERSIZED_OUTPUT")
    if b"\x00" in raw:
        return blank("MALFORMED")
    try:
        lines = raw.decode("ascii").splitlines()
    except UnicodeDecodeError:
        return blank("MALFORMED")
    values: dict[str, str] = {}
    for line in lines:
        if not line.startswith(PREFIX) or "=" not in line:
            return blank("MALFORMED")
        key, value = line[len(PREFIX):].split("=", 1)
        if key in values or key not in set(FIELDS) | {"SCHEMA", "STATUS"}:
            return blank("MALFORMED")
        values[key] = value
    if (set(values) != set(FIELDS) | {"SCHEMA", "STATUS"}
            or values["SCHEMA"] != "1"
            or values["STATUS"] not in {"COMPLETE", "UNAVAILABLE"}
            or any(values[field] not in VALUES - {"NOT_RUN"} for field in FIELDS)):
        return blank("MALFORMED")
    report = {
        "status": values["STATUS"],
        "services": {field: values[field] for field in FIELDS},
    }
    if not valid(report):
        return blank("MALFORMED")
    return report


def measure(wine: Path, prefix: Path, fixture: Path) -> dict:
    validate_prefix(prefix)
    if (wine.is_symlink() or fixture.is_symlink()
            or not wine.is_file() or not fixture.is_file()
            or fixture.name.casefold() != "netfx48_scm_service_probe.exe"):
        raise ValueError("SCM probe requires the independently built x64 fixture")
    env = os.environ.copy()
    env.pop("WINEDLLOVERRIDES", None)
    env.update({"WINEPREFIX": str(prefix), "WINEARCH": "win64",
                "WINEDEBUG": "-all"})
    with tempfile.TemporaryFile() as stream:
        try:
            result = subprocess.run(
                [str(wine), str(fixture)], cwd=fixture.parent,
                env=env, stdin=subprocess.DEVNULL, stdout=stream,
                stderr=subprocess.DEVNULL, timeout=20, check=False)
        except subprocess.TimeoutExpired:
            return blank("TIMEOUT")
        except OSError:
            return blank("PROCESS_FAILED")
        stream.seek(0)
        output = stream.read(MAX_BYTES + 1)
    return parse(output, result.returncode)
