"""Finite, privacy-safe Windows Installer patch-sequencing evidence.

The existing Win32 monitor tests the ORIGINAL signed MSP against the
already-installed original MSI without changing either vendor file or the
unchanged msiexec /p invocation. The two Windows Installer contexts are
separate, so USER-unmanaged UNKNOWN_PRODUCT does not imply absence in
MACHINE context. API eligibility never substitutes for actual MSP success.
"""
from __future__ import annotations

import re

MAX_BYTES = 512
STATES = {
    "UNKNOWN", "APPLICABLE", "EXCLUDED", "TARGET_MISMATCH",
    "NO_SEQUENCE", "PRODUCT_UNKNOWN", "UNSUPPORTED",
    "PATCH_UNOPENABLE", "OTHER_ERROR",
}
STATUSES = {"NOT_RUN", "OBSERVED", "SELFTEST", "BAD_PACKET"}
_PACKET = re.compile(
    rb"SWCOMPAT_MSI_SEQ_SCHEMA=1\r?\n"
    rb"SWCOMPAT_MSI_SEQ_STATUS=([A-Z_]+)\r?\n"
    rb"SWCOMPAT_MSI_SEQ_USER=([A-Z_]+)\r?\n"
    rb"SWCOMPAT_MSI_SEQ_MACHINE=([A-Z_]+)\r?\n?"
)


def blank(status: str = "NOT_RUN") -> dict:
    if type(status) is not str or status not in STATUSES:
        raise ValueError("Unknown signed MSP sequencing status")
    return {"status": status, "user": "UNKNOWN", "machine": "UNKNOWN"}


def valid(report: object) -> bool:
    if type(report) is not dict or set(report) != set(blank()):
        return False
    if (any(type(report[key]) is not str for key in report)
            or report["status"] not in STATUSES
            or report["user"] not in STATES
            or report["machine"] not in STATES):
        return False
    if report["status"] == "SELFTEST":
        return report == {"status": "SELFTEST", "user": "APPLICABLE",
                          "machine": "PRODUCT_UNKNOWN"}
    if report["status"] == "OBSERVED":
        return report["user"] != "UNKNOWN" and report["machine"] != "UNKNOWN"
    return report == blank(report["status"])


def parse(raw: bytes, *, selftest: bool = False) -> dict:
    if type(raw) is not bytes or len(raw) > MAX_BYTES:
        return blank("BAD_PACKET")
    match = _PACKET.fullmatch(raw)
    if not match:
        return blank("BAD_PACKET")
    try:
        status, user, machine = (x.decode("ascii") for x in match.groups())
    except UnicodeError:
        return blank("BAD_PACKET")
    report = {"status": status, "user": user, "machine": machine}
    if not valid(report) or (status == "SELFTEST") != selftest:
        return blank("BAD_PACKET")
    return report
