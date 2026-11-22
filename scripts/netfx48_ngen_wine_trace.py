"""Only finite Wine NGen stall signatures, never vendor or Wine log text.

Used solely on a marked disposable authenticated CLR4 CI prefix. Raw stderr
lives in an anonymous, short-lived local temporary file, never an artifact.
These classifications are clues, not proof of a Wine or Microsoft defect.
"""
from __future__ import annotations

import re

MAX_BYTES = 1024 * 1024
STATUSES = {"NOT_RUN", "CLASSIFIED", "NO_SIGNATURE", "TOO_LARGE", "UNREADABLE"}
SIGNALS = {
    "STACK_OVERFLOW", "CRITICAL_SECTION_WAIT", "RPC_DISCONNECTED",
    "ACCESS_VIOLATION", "SERVICE_NOT_FOUND",
}
PATTERNS = {
    "STACK_OVERFLOW": re.compile(r"(?i)\b(?:stack overflow|STATUS_STACK_OVERFLOW|0xc00000fd)\b"),
    "CRITICAL_SECTION_WAIT": re.compile(r"(?i)\bRtlpWaitForCriticalSection\b|"
                                        r"\bwait timed out\b.{0,100}\bcritical\s+section\b"),
    "RPC_DISCONNECTED": re.compile(r"(?i)\b0x800706be\b|\bRPC_S_CALL_FAILED\b|"
                                   r"\bRPC server is unavailable\b"),
    "ACCESS_VIOLATION": re.compile(r"(?i)\b0xc0000005\b|\baccess violation\b"),
    "SERVICE_NOT_FOUND": re.compile(r"(?i)\b0x80070424\b|\bservice does not exist\b"),
}


def blank(status: str = "NOT_RUN") -> dict:
    if status not in STATUSES:
        raise ValueError("Unknown Wine diagnostics state")
    return {"status": status, "signals": []}


def valid(value: object) -> bool:
    return (
        type(value) is dict and set(value) == {"status", "signals"}
        and value["status"] in STATUSES
        and type(value["signals"]) is list
        and value["signals"] == sorted(set(value["signals"]))
        and all(type(s) is str and s in SIGNALS for s in value["signals"])
        and (bool(value["signals"]) == (value["status"] == "CLASSIFIED"))
        and (value["status"] not in {"TOO_LARGE", "UNREADABLE", "NOT_RUN"}
             or value == blank(value["status"]))
    )


def classify(raw: bytes) -> dict:
    if type(raw) is not bytes:
        return blank("UNREADABLE")
    if len(raw) > MAX_BYTES:
        return blank("TOO_LARGE")
    if b"\x00" in raw:
        return blank("UNREADABLE")
    try:
        decoded = raw.decode("utf-8", errors="strict")
    except UnicodeError:
        return blank("UNREADABLE")
    signals = sorted(key for key, pattern in PATTERNS.items()
                     if pattern.search(decoded))
    result = {"status": "CLASSIFIED" if signals else "NO_SIGNATURE",
              "signals": signals}
    assert valid(result)
    return result


def classify_private_stream(stream) -> dict:
    """One bounded read only; no bytes or strings escape to caller."""
    try:
        stream.seek(0)
        return classify(stream.read(MAX_BYTES + 1))
    except (OSError, ValueError):
        return blank("UNREADABLE")
