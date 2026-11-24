"""Bounded Win32 DWORD result from OUR independently built original MSP launcher.

The original Microsoft-signed x64 MSP and all Windows Installer actions remain
unmodified. The compiled Win32 fixture uses CreateProcessW/GetExitCodeProcess
to prevent Unix/Wine exit-byte truncation. Never log Windows command lines,
vendor names, file paths, or private MSI output. This is NOT MSI success.
"""
from __future__ import annotations

import re

STATES = {
    "NOT_RUN", "SELFTEST_PASS", "EXIT_CAPTURED",
    "START_FAILED", "WAIT_FAILED", "INVALID_ARGUMENT",
    "BAD_REPORT", "START_FAILED_HOST", "TIMED_OUT_PREFIX_REAPED",
    "TIMED_OUT_CLEANUP_DENIED",
}
CATEGORIES = {
    "NOT_AVAILABLE", "SUCCESS", "MSI_FATAL_ERROR",
    "PATCH_TARGET_NOT_FOUND", "UNKNOWN_PRODUCT", "PATCH_PACKAGE_OPEN_FAILED",
    "PATCH_PACKAGE_INVALID", "OTHER_WIN32_ERROR",
}
CODES = {
    0: "SUCCESS",
    1603: "MSI_FATAL_ERROR",
    1642: "PATCH_TARGET_NOT_FOUND",
    1605: "UNKNOWN_PRODUCT",
    1635: "PATCH_PACKAGE_OPEN_FAILED",
    1636: "PATCH_PACKAGE_INVALID",
}
PATTERN = re.compile(r"[A-F0-9]{8}\Z")
PREFIX = "SWCOMPAT_MSP_WIN32_"
MAX_BYTES = 512


def blank(status: str = "NOT_RUN") -> dict:
    if type(status) is not str or status not in STATES:
        raise ValueError("Invalid native original MSP fixture status")
    return {"status": status, "exit_hex": "NOT_VERIFIED",
            "category": "NOT_AVAILABLE"}


def valid(result: object) -> bool:
    if type(result) is not dict or set(result) != set(blank()):
        return False
    if (type(result["status"]) is not str or result["status"] not in STATES
            or type(result["exit_hex"]) is not str
            or type(result["category"]) is not str
            or result["category"] not in CATEGORIES):
        return False
    if result["status"] != "EXIT_CAPTURED":
        return result == blank(result["status"])
    if not PATTERN.fullmatch(result["exit_hex"]):
        return False
    code = int(result["exit_hex"], 16)
    return result["category"] == CODES.get(code, "OTHER_WIN32_ERROR")


def parse(raw: bytes, host_status: str, *, selftest: bool = False) -> dict:
    """Strict exact private status packet; ignore ALL other process output."""
    if (type(raw) is not bytes or len(raw) > MAX_BYTES or not raw
            or b"\x00" in raw or host_status not in {"SUCCESS", "EXIT_NONZERO"}):
        return blank("BAD_REPORT")
    try:
        lines = raw.decode("ascii").splitlines()
    except UnicodeDecodeError:
        return blank("BAD_REPORT")
    data: dict[str, str] = {}
    for line in lines:
        if not line.startswith(PREFIX) or "=" not in line:
            return blank("BAD_REPORT")
        key, value = line[len(PREFIX):].split("=", 1)
        if key in data or key not in {"SCHEMA", "STATUS", "EXIT_HEX"}:
            return blank("BAD_REPORT")
        data[key] = value
    if set(data) != {"SCHEMA", "STATUS", "EXIT_HEX"} or data["SCHEMA"] != "1":
        return blank("BAD_REPORT")
    if selftest:
        if (host_status == "SUCCESS" and data["STATUS"] == "SELFTEST"
                and data["EXIT_HEX"] == "00000643"):
            return blank("SELFTEST_PASS")
        return blank("BAD_REPORT")
    if (data["STATUS"] == "EXIT" and host_status == "SUCCESS"
            and PATTERN.fullmatch(data["EXIT_HEX"])):
        code = int(data["EXIT_HEX"], 16)
        result = {"status": "EXIT_CAPTURED", "exit_hex": data["EXIT_HEX"],
                  "category": CODES.get(code, "OTHER_WIN32_ERROR")}
        assert valid(result)
        return result
    if (data["STATUS"] in {"START_FAILED", "WAIT_FAILED", "INVALID_ARGUMENT"}
            and host_status == "EXIT_NONZERO"
            and data["EXIT_HEX"] == "FFFFFFFF"):
        return blank(data["STATUS"])
    return blank("BAD_REPORT")


def patch_status(result: dict) -> str:
    """A full DWORD zero is required. A green harness return is insufficient."""
    if not valid(result):
        raise ValueError("Invalid native original MSP status packet")
    if result["status"] == "EXIT_CAPTURED":
        return "SUCCESS" if result["exit_hex"] == "00000000" else "EXIT_NONZERO"
    if result["status"] in {"TIMED_OUT_CLEANUP_DENIED", "TIMED_OUT_PREFIX_REAPED"}:
        return result["status"]
    return "EXIT_NONZERO"
