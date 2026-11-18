"""Read-only native Windows x64 SCM presence and live-state fixture.

The native code queries the actual service controller in a disposable Wine
prefix. It never starts a service, exposes PIDs, or publishes raw Wine output.
"""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile

from scripts.netfx481_trial import validate_prefix

FIELDS = ("TRUSTEDINSTALLER", "MSISERVER", "WUAUSERV", "BITS",
          "CLR_OPTIMIZATION_64", "CLR_OPTIMIZATION_32", "MSDTC")
VALUES = {"NOT_RUN", "PRESENT", "ABSENT", "ACCESS_DENIED", "UNKNOWN"}
RUN_STATES = {
    "NOT_RUN", "NOT_APPLICABLE", "QUERY_FAILED", "STOPPED", "START_PENDING",
    "STOP_PENDING", "RUNNING", "CONTINUE_PENDING", "PAUSE_PENDING", "PAUSED", "OTHER",
}
SERVICE_ACTIVE = RUN_STATES - {"NOT_RUN", "NOT_APPLICABLE"}
STATUSES = {"NOT_RUN", "COMPLETE", "UNAVAILABLE", "MALFORMED", "TIMEOUT",
            "PROCESS_FAILED", "EMPTY_OUTPUT", "OVERSIZED_OUTPUT", "NONZERO_EXIT",
            "NONASCII_OUTPUT", "UNEXPECTED_TEXT", "INVALID_FIELD", "INCOMPLETE_FIELDS",
            "NONZERO_WITH_REPORT", "NONZERO_WITHOUT_REPORT"}
MAX_BYTES = 2048
PREFIX = "SWCOMPAT_SCM_API_"
STATE_PREFIX = "SWCOMPAT_SCM_STATE_"
SELFTEST_MARKER = b"SWCOMPAT_SCM_FIXTURE_SELFTEST=PASS\n"
SELFTEST_STATUSES = {"NOT_RUN", "PASS", "NONZERO_EXIT", "EMPTY_OUTPUT",
                     "UNEXPECTED_OUTPUT", "TIMEOUT", "PROCESS_FAILED"}


def parse_selftest(raw: bytes, exit_code: int) -> str:
    if exit_code != 0:
        return "NONZERO_EXIT"
    if not raw:
        return "EMPTY_OUTPUT"
    return ("PASS" if raw in {SELFTEST_MARKER, SELFTEST_MARKER[:-1] + b"\r\n"}
            else "UNEXPECTED_OUTPUT")


def blank(status: str = "NOT_RUN") -> dict:
    if status not in STATUSES:
        raise ValueError("Invalid SCM status")
    return {
        "status": status,
        "services": {field: "NOT_RUN" for field in FIELDS},
        "states": {field: "NOT_RUN" for field in FIELDS},
    }


def valid(report: object) -> bool:
    if type(report) is not dict or set(report) != {"status", "services", "states"}:
        return False
    if (report["status"] not in STATUSES
            or type(report["services"]) is not dict
            or type(report["states"]) is not dict
            or set(report["services"]) != set(FIELDS)
            or set(report["states"]) != set(FIELDS)
            or any(type(value) is not str or value not in VALUES
                   for value in report["services"].values())
            or any(type(value) is not str or value not in RUN_STATES
                   for value in report["states"].values())):
        return False
    if report["status"] not in {"COMPLETE", "UNAVAILABLE"}:
        return report == blank(report["status"])
    if report["status"] == "UNAVAILABLE":
        return (all(v == "UNKNOWN" for v in report["services"].values())
                and all(v == "NOT_APPLICABLE" for v in report["states"].values()))
    if any(v == "NOT_RUN" for v in report["services"].values()):
        return False
    return all(
        (report["states"][field] in SERVICE_ACTIVE)
        if report["services"][field] == "PRESENT"
        else report["states"][field] == "NOT_APPLICABLE"
        for field in FIELDS
    )


def parse(raw: bytes, exit_code: int) -> dict:
    if exit_code != 0:
        packet = parse(raw, 0) if raw else blank("EMPTY_OUTPUT")
        return blank("NONZERO_WITH_REPORT" if packet["status"] in {
            "COMPLETE", "UNAVAILABLE"} else "NONZERO_WITHOUT_REPORT")
    if not raw:
        return blank("EMPTY_OUTPUT")
    if len(raw) > MAX_BYTES:
        return blank("OVERSIZED_OUTPUT")
    if b"\x00" in raw:
        return blank("MALFORMED")
    try:
        lines = raw.decode("ascii").splitlines()
    except UnicodeDecodeError:
        return blank("NONASCII_OUTPUT")
    values: dict[str, str] = {}
    expected = set(FIELDS) | {"SCHEMA", "STATUS"} | {"STATE_" + f for f in FIELDS}
    for line in lines:
        if "=" not in line:
            return blank("UNEXPECTED_TEXT")
        if line.startswith(STATE_PREFIX):
            key, value = line[len(STATE_PREFIX):].split("=", 1)
            key = "STATE_" + key
        elif line.startswith(PREFIX):
            key, value = line[len(PREFIX):].split("=", 1)
        else:
            return blank("UNEXPECTED_TEXT")
        if key in values or key not in expected:
            return blank("INVALID_FIELD")
        values[key] = value
    if set(values) != expected:
        return blank("INCOMPLETE_FIELDS")
    if (values["SCHEMA"] != "2"
            or values["STATUS"] not in {"COMPLETE", "UNAVAILABLE"}
            or any(values[field] not in VALUES - {"NOT_RUN"} for field in FIELDS)
            or any(values["STATE_" + field] not in RUN_STATES - {"NOT_RUN"}
                   for field in FIELDS)):
        return blank("MALFORMED")
    report = {
        "status": values["STATUS"],
        "services": {field: values[field] for field in FIELDS},
        "states": {field: values["STATE_" + field] for field in FIELDS},
    }
    return report if valid(report) else blank("MALFORMED")


def selftest(wine: Path, prefix: Path, fixture: Path) -> str:
    """Run one no-SCM native x64 startup control before service inspection.

    A passing selftest establishes Windows process/CRT startup only, never
    SCM correctness or the existence of any Windows service.
    """
    validate_prefix(prefix)
    if (wine.is_symlink() or fixture.is_symlink()
            or not wine.is_file() or not fixture.is_file()
            or fixture.name.casefold() != "netfx48_scm_service_probe.exe"):
        raise ValueError("SCM startup control requires the independently built x64 fixture")
    # The CI argument is build/<fixture>.exe, but cwd below is build/.
    # Always hand Wine a fully resolved executable path, or it may look
    # for build/build/<fixture>.exe and exit before the Win32 entry point.
    wine = wine.resolve(strict=True)
    fixture = fixture.resolve(strict=True)
    env = os.environ.copy()
    env.pop("WINEDLLOVERRIDES", None)
    env.update({"WINEPREFIX": str(prefix), "WINEARCH": "win64",
                "WINEDEBUG": "-all"})
    with tempfile.TemporaryFile() as stream:
        try:
            result = subprocess.run(
                [str(wine), str(fixture), "--selftest"], cwd=fixture.parent,
                env=env, stdin=subprocess.DEVNULL, stdout=stream,
                stderr=subprocess.DEVNULL, timeout=20, check=False)
        except subprocess.TimeoutExpired:
            return "TIMEOUT"
        except OSError:
            return "PROCESS_FAILED"
        stream.seek(0)
        output = stream.read(len(SELFTEST_MARKER) + 1)
    status = parse_selftest(output, result.returncode)
    assert status in SELFTEST_STATUSES
    return status


def measure(wine: Path, prefix: Path, fixture: Path) -> dict:
    validate_prefix(prefix)
    if (wine.is_symlink() or fixture.is_symlink()
            or not wine.is_file() or not fixture.is_file()
            or fixture.name.casefold() != "netfx48_scm_service_probe.exe"):
        raise ValueError("SCM probe requires the independently built x64 fixture")
    wine = wine.resolve(strict=True)
    fixture = fixture.resolve(strict=True)
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
