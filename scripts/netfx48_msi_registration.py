"""Privacy-safe, read-only original Microsoft x64 MSI registration evidence.

The native Win32 monitor reads ProductCode privately from the unmodified
signed MSI. It prints ONLY four fixed-schema enums. No product IDs, paths,
vendor text or original media are stored in the report. A probe failure never
turns a failed original Microsoft MSP into success.
"""
from __future__ import annotations

import re

MAX_BYTES = 512
STATUSES = {"NOT_RUN", "OBSERVED", "SELFTEST", "OPEN_FAILED",
            "QUERY_FAILED", "BAD_PACKET", "HOST_ERROR"}
PRODUCTS = {"UNKNOWN", "INSTALLED", "ADVERTISED", "ABSENT", "OTHER"}
CACHES = {"UNKNOWN", "PRESENT", "MISSING"}
_PACKET = re.compile(
    rb"SWCOMPAT_MSI_REG_SCHEMA=1\r?\n"
    rb"SWCOMPAT_MSI_REG_STATUS=([A-Z_]+)\r?\n"
    rb"SWCOMPAT_MSI_REG_PRODUCT=([A-Z_]+)\r?\n"
    rb"SWCOMPAT_MSI_REG_CACHE=([A-Z_]+)\r?\n?"
)


def blank(status: str = "NOT_RUN") -> dict:
    if type(status) is not str or status not in STATUSES:
        raise ValueError("Invalid native signed-MSI registration state")
    return {"status": status, "product": "UNKNOWN", "cache": "UNKNOWN"}


def valid(value: object) -> bool:
    if type(value) is not dict or set(value) != set(blank()):
        return False
    if any(type(value[k]) is not str for k in value):
        return False
    if (value["status"] not in STATUSES
            or value["product"] not in PRODUCTS
            or value["cache"] not in CACHES):
        return False
    if value["status"] == "SELFTEST":
        return value == {"status": "SELFTEST", "product": "INSTALLED",
                         "cache": "PRESENT"}
    if value["status"] == "OBSERVED":
        return True
    return value == blank(value["status"])


def parse(raw: bytes, host_status: str, *, selftest: bool = False) -> dict:
    if host_status != "SUCCESS":
        return blank("HOST_ERROR")
    if type(raw) is not bytes or len(raw) > MAX_BYTES:
        return blank("BAD_PACKET")
    match = _PACKET.fullmatch(raw)
    if match is None:
        return blank("BAD_PACKET")
    try:
        status, product, cache = (part.decode("ascii") for part in match.groups())
    except UnicodeError:
        return blank("BAD_PACKET")
    report = {"status": status, "product": product, "cache": cache}
    if not valid(report) or (status == "SELFTEST") != selftest:
        return blank("BAD_PACKET")
    return report
