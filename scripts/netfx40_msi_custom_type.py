"""Privacy-preserving Wine MSI custom-action type telemetry.

Wine's upstream dlls/msi/custom.c emits
    trace:msi:ACTION_CustomAction Handling custom action L"<name>" (<hex-type> ...)
The script's failing action appears in an err:msi:execute_script line. Names,
target DLLs, command lines and properties are used only transiently to pair
these events, never returned or written to disk. The type is metadata, NOT
proof of the missing Windows API.
"""
from __future__ import annotations

import re
from scripts.netfx40_wine_msi_errors import _ACTION_STRING, _failed_action_type

MAX_RETAINED_BYTES = 3 * 1024 * 1024
MAX_RETAINED_LINES = 1024
MAX_LINE_BYTES = 4096
TRACE = re.compile(
    rb'(?i)\btrace:msi:[a-z_0-9]+\s+Handling custom action L"([^"\r\n]{1,350})"'
    rb'\s+\(([0-9a-f]{1,8})\s'
)
FAMILIES = {
    1: "DLL_BINARY", 2: "EXE_BINARY",
    5: "SCRIPT_BINARY", 6: "SCRIPT_BINARY",
    7: "NESTED_MSI", 17: "DLL_FILE", 18: "EXE_FILE",
    19: "ERROR_ACTION", 21: "SCRIPT_FILE", 22: "SCRIPT_FILE",
    23: "NESTED_MSI", 34: "EXE_DIRECTORY", 35: "SET_DIRECTORY",
    37: "SCRIPT_TEXT", 38: "SCRIPT_TEXT",
    50: "EXE_PROPERTY", 51: "SET_PROPERTY",
    53: "SCRIPT_PROPERTY", 54: "SCRIPT_PROPERTY",
}
STATUSES = {
    "NOT_REQUESTED", "TRACE_MATCHED", "TRACE_MISSING", "TRACE_AMBIGUOUS",
    "NO_NONSTANDARD_FAILURE", "CAPTURE_TRUNCATED",
}
EXECUTION = {"NOT_VERIFIED", "IMMEDIATE", "DEFERRED", "ROLLBACK", "COMMIT"}
IMPERSONATION = {"NOT_VERIFIED", "DEFAULT", "NO_IMPERSONATE"}
ASYNC = {"NOT_VERIFIED", "SYNCHRONOUS", "ASYNCHRONOUS"}


def relevant(line: bytes) -> bool:
    """Only fixed Wine subsystem evidence may enter the bounded private buffer."""
    if len(line) > MAX_LINE_BYTES:
        return False
    return (b"err:msi:" in line or b"fixme:msi:" in line or
            (b"trace:msi:" in line and b"Handling custom action " in line))


def empty(status: str = "NOT_REQUESTED") -> dict:
    if status not in STATUSES:
        raise ValueError("Invalid custom-action trace state")
    return {
        "status": status, "family": "NOT_VERIFIED", "base_type": None,
        "execution": "NOT_VERIFIED", "impersonation": "NOT_VERIFIED",
        "asynchronous": "NOT_VERIFIED", "ts_aware": False,
    }


def _private_failed_action(raw: bytes) -> bytes | None:
    candidates = []
    for line in raw.splitlines():
        if b"err:msi:" not in line:
            continue
        if _failed_action_type(line) is not None:
            match = _ACTION_STRING.search(line)
            if match:
                candidates.append((_failed_action_type(line), match.group(1)))
    for kind, name in candidates:
        if kind not in {"FINALIZE_ONLY"}:
            return name if kind == "OTHER_ACTION" else None
    return None


def parse(raw: bytes, *, truncated: bool = False) -> dict:
    if not isinstance(raw, bytes) or truncated or len(raw) > MAX_RETAINED_BYTES:
        return empty("CAPTURE_TRUNCATED")
    failed = _private_failed_action(raw)
    if failed is None:
        return empty("NO_NONSTANDARD_FAILURE")
    # Wine's deferred action form "[CustomActionData<=>SID<=>Product]Action"
    # is stripped before querying MSI's CustomAction table. Do the same.
    action = failed.rsplit(b"]", 1)[-1] if b"]" in failed else failed
    candidates = set()
    for line in raw.splitlines():
        if len(line) > MAX_LINE_BYTES:
            continue
        trace = TRACE.search(line)
        if trace and trace.group(1) == action:
            candidates.add(int(trace.group(2), 16))
    if not candidates:
        return empty("TRACE_MISSING")
    if len(candidates) != 1:
        return empty("TRACE_AMBIGUOUS")
    type_value = next(iter(candidates))
    base_type = type_value & 0x3F
    if type_value & 0x100:
        execution = "ROLLBACK"
    elif type_value & 0x200:
        execution = "COMMIT"
    elif type_value & 0x400:
        execution = "DEFERRED"
    else:
        execution = "IMMEDIATE"
    return {
        "status": "TRACE_MATCHED",
        "family": FAMILIES.get(base_type, "OTHER_TYPE"),
        "base_type": base_type,
        "execution": execution,
        "impersonation": "NO_IMPERSONATE" if type_value & 0x800 else "DEFAULT",
        "asynchronous": "ASYNCHRONOUS" if type_value & 0x80 else "SYNCHRONOUS",
        "ts_aware": bool(type_value & 0x4000),
    }


def validate(result: dict) -> bool:
    if type(result) is not dict or set(result) != {
        "status", "family", "base_type", "execution", "impersonation",
        "asynchronous", "ts_aware",
    }:
        return False
    if (result["status"] not in STATUSES
            or result["family"] not in set(FAMILIES.values()) | {"NOT_VERIFIED", "OTHER_TYPE"}
            or result["execution"] not in EXECUTION
            or result["impersonation"] not in IMPERSONATION
            or result["asynchronous"] not in ASYNC
            or type(result["ts_aware"]) is not bool):
        return False
    if result["status"] != "TRACE_MATCHED":
        return result == empty(result["status"])
    return (
        type(result["base_type"]) is int
        and 0 <= result["base_type"] <= 63
        and result["family"] == FAMILIES.get(result["base_type"], "OTHER_TYPE")
        and result["execution"] != "NOT_VERIFIED"
        and result["impersonation"] != "NOT_VERIFIED"
        and result["asynchronous"] != "NOT_VERIFIED"
    )
