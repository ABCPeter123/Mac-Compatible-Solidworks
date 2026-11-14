"""Capture an ORIGINAL Windows process's entire DWORD exit status under Wine.

Run only our own Windows x64 CreateProcess probe, compiled on Windows CI,
against the independently hash-verified official Microsoft setup executable.
Do not copy raw stdout, process names, paths or original installer logs into
the report. Child observation is best effort, not proof of no handoff.
"""
from __future__ import annotations

from pathlib import Path
import os
import re
import subprocess
import tempfile

MARKER = "SWCOMPAT_WIN32_SETUP_"
FIELDS = {
    "SCHEMA": {"1"},
    "STATUS": {"EXIT", "START_FAILED", "WAIT_FAILED", "TIMEOUT", "INVALID_ARGUMENT"},
    "CHILD_SEEN": {"OBSERVED", "NOT_OBSERVED", "UNKNOWN"},
    "CHILD_LIFECYCLE": {"ALL_EXITED", "STILL_ACTIVE", "PARTIAL", "NOT_OBSERVED", "UNKNOWN"},
    "CHILD_EXIT": {"ALL_ZERO", "REBOOT_REQUIRED", "NONZERO", "NOT_VERIFIED"},
}
HEX = re.compile(r"[A-F0-9]{8}\Z")
MAX_BYTES = 4096
VALID_STATUSES = {
    "NOT_REQUESTED", "EXIT_CAPTURED", "START_FAILED", "WAIT_FAILED",
    "TIMEOUT", "INVALID_ARGUMENT", "BAD_REPORT", "PROCESS_FAILED",
}
CATEGORIES = {
    "NOT_AVAILABLE", "SUCCESS", "REBOOT_REQUIRED", "MSI_FATAL_ERROR",
    "INSTALL_ALREADY_PRESENT", "OTHER",
}
CHILD_VALUES = FIELDS["CHILD_SEEN"] | {"NOT_VERIFIED"}
LIFECYCLE_VALUES = FIELDS["CHILD_LIFECYCLE"] | {"NOT_VERIFIED"}
EXIT_VALUES = FIELDS["CHILD_EXIT"]


def blank(status: str = "NOT_REQUESTED") -> dict:
    if status not in VALID_STATUSES:
        raise ValueError("Invalid Win32 launcher status")
    return {
        "status": status,
        "exit_hex": "NOT_VERIFIED",
        "category": "NOT_AVAILABLE",
        "child_seen": "NOT_VERIFIED",
        "child_lifecycle": "NOT_VERIFIED", "child_exit": "NOT_VERIFIED",
    }


def categorize_exit(code: int) -> str:
    if not 0 <= code <= 0xFFFFFFFF:
        raise ValueError("Invalid Win32 code")
    return {0: "SUCCESS", 3010: "REBOOT_REQUIRED",
            1603: "MSI_FATAL_ERROR", 1638: "INSTALL_ALREADY_PRESENT"
            }.get(code, "OTHER")


def parse(raw: bytes, process_code: int) -> dict:
    if len(raw) > MAX_BYTES or b"\x00" in raw or process_code not in (0, 1, 2):
        return blank("BAD_REPORT")
    try:
        lines = raw.decode("ascii").splitlines()
    except UnicodeDecodeError:
        return blank("BAD_REPORT")
    values: dict[str, str] = {}
    for line in lines:
        if not line.startswith(MARKER):
            continue
        if "=" not in line:
            return blank("BAD_REPORT")
        key, value = line[len(MARKER):].split("=", 1)
        if key in values or key not in (set(FIELDS) | {"EXIT_HEX"}):
            return blank("BAD_REPORT")
        values[key] = value
    if set(values) != (set(FIELDS) | {"EXIT_HEX"}):
        return blank("BAD_REPORT")
    if any(values[key] not in allowed for key, allowed in FIELDS.items()):
        return blank("BAD_REPORT")
    if not HEX.fullmatch(values["EXIT_HEX"]):
        return blank("BAD_REPORT")
    status = values["STATUS"]
    if status == "EXIT" and process_code == 0:
        child = values["CHILD_SEEN"]
        lifecycle = values["CHILD_LIFECYCLE"]
        child_exit = values["CHILD_EXIT"]
        if ((child == "OBSERVED" and lifecycle not in {"ALL_EXITED", "STILL_ACTIVE", "PARTIAL"})
                or (child == "NOT_OBSERVED" and lifecycle != "NOT_OBSERVED")
                or (child == "UNKNOWN" and lifecycle != "UNKNOWN")
                or (lifecycle == "ALL_EXITED" and child_exit == "NOT_VERIFIED")
                or (lifecycle != "ALL_EXITED" and child_exit != "NOT_VERIFIED")):
            return blank("BAD_REPORT")
        code = int(values["EXIT_HEX"], 16)
        return {
            "status": "EXIT_CAPTURED", "exit_hex": values["EXIT_HEX"],
            "category": categorize_exit(code), "child_seen": values["CHILD_SEEN"],
            "child_lifecycle": lifecycle, "child_exit": child_exit,
        }
    if status != "EXIT" and process_code in (1, 2):
        return {
            "status": status, "exit_hex": "NOT_VERIFIED",
            "category": "NOT_AVAILABLE", "child_seen": "NOT_VERIFIED",
        }
    return blank("BAD_REPORT")


def validate(report: dict) -> bool:
    if not isinstance(report, dict) or set(report) != {
        "status", "exit_hex", "category", "child_seen",
        "child_lifecycle", "child_exit"
    }:
        return False
    if report["status"] not in VALID_STATUSES:
        return False
    if (report["category"] not in CATEGORIES or report["child_seen"] not in CHILD_VALUES
            or report["child_lifecycle"] not in LIFECYCLE_VALUES
            or report["child_exit"] not in EXIT_VALUES):
        return False
    if report["status"] == "EXIT_CAPTURED":
        return (isinstance(report["exit_hex"], str)
                and HEX.fullmatch(report["exit_hex"]) is not None
                and report["category"] == categorize_exit(int(report["exit_hex"], 16))
                and report["child_seen"] in FIELDS["CHILD_SEEN"]
                and report["child_lifecycle"] in FIELDS["CHILD_LIFECYCLE"]
                and report["child_exit"] in FIELDS["CHILD_EXIT"]
                and ((report["child_seen"] == "OBSERVED"
                      and report["child_lifecycle"] in {"ALL_EXITED", "STILL_ACTIVE", "PARTIAL"})
                     or (report["child_seen"] == "NOT_OBSERVED"
                         and report["child_lifecycle"] == "NOT_OBSERVED")
                     or (report["child_seen"] == "UNKNOWN"
                         and report["child_lifecycle"] == "UNKNOWN"))
                and ((report["child_lifecycle"] == "ALL_EXITED"
                      and report["child_exit"] != "NOT_VERIFIED")
                     or (report["child_lifecycle"] != "ALL_EXITED"
                         and report["child_exit"] == "NOT_VERIFIED")))
    return (report["exit_hex"] == "NOT_VERIFIED"
            and report["category"] == "NOT_AVAILABLE"
            and report["child_seen"] == "NOT_VERIFIED"
            and report["child_lifecycle"] == "NOT_VERIFIED"
            and report["child_exit"] == "NOT_VERIFIED")


def launch(wine: Path, prefix: Path, setup: Path, fixture: Path,
           *, timeout: int = 245) -> dict:
    from scripts.netfx481_trial import validate_prefix
    from swcompat.wine_paths import windows_media_path

    validate_prefix(prefix)
    if (fixture.is_symlink() or not fixture.is_file()
            or fixture.name.casefold() != "netfx481_win32_launch.exe"):
        raise ValueError("Signed-on-Windows original launch fixture missing")
    if setup.is_symlink() or setup.name.casefold() != "ndp481-x86-x64-allos-enu.exe":
        raise ValueError("Unrecognized Microsoft setup executable")
    win_path = windows_media_path(wine, prefix, setup)
    env = os.environ.copy()
    env.pop("WINEDLLOVERRIDES", None)
    env.update({"WINEPREFIX": str(prefix), "WINEARCH": "win64", "WINEDEBUG": "-all"})
    with tempfile.TemporaryFile() as stdout:
        try:
            run = subprocess.run(
                [str(wine), str(fixture), win_path], cwd=fixture.parent,
                env=env, stdin=subprocess.DEVNULL, stdout=stdout,
                stderr=subprocess.DEVNULL, check=False, timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            return blank("TIMEOUT")
        except OSError:
            return blank("PROCESS_FAILED")
        stdout.seek(0)
        raw = stdout.read(MAX_BYTES + 1)
    result = parse(raw, run.returncode)
    return result


def termination(report: dict) -> tuple[str, int | None]:
    if not validate(report):
        raise ValueError("Invalid Win32 process report")
    if report["status"] != "EXIT_CAPTURED":
        return ("TIMEOUT", None) if report["status"] == "TIMEOUT" else ("START_FAILED", None)
    code = int(report["exit_hex"], 16)
    return ("EXIT_ZERO" if code == 0 else "EXIT_NONZERO", code)
