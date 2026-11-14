"""Private, allowlisted WINEDEBUG=err+msi diagnosis of original .NET4 setup.

No raw Winetricks or Microsoft logs, paths, command lines, DLL names other
than the public .NET package hint, or license/media information leave CI.
A fixed error marker is only a hypothesis; it does not identify a root API.
"""
from __future__ import annotations

import re

MAX_BYTES = 8 * 1024 * 1024
MAX_LINE_BYTES = 4096
STATUS = {"NOT_REQUESTED", "SCANNED", "TRUNCATED", "UNREADABLE"}
CLASSES = {
    "CABINET_MEDIA_MISSING", "NETFX_CORE_CAB_MISSING", "CUSTOM_ACTION_BAD_EXE",
    "CUSTOM_ACTION_DLL_LOAD", "MSI_ACTION_INSTALLFILES", "MSI_ACTION_FINALIZE",
    "MSI_CUSTOM_ACTION_UNSUPPORTED", "OTHER_MSI_ERROR",
}
_MSI_ERR = re.compile(rb"(?i)\berr:msi:[a-z_0-9]+\s")
_CAB = re.compile(rb"(?i)\bready_media\s+cabinet\s+not\s+found")
_NETFX_CAB = re.compile(rb"(?i)\bnetfx_core\.mzz\b")
_CUSTOM_DLL = re.compile(rb"(?i)\b__wine_msi_call_dll_function\s+failed\s+to\s+load\s+dll")
_BAD_EXE = re.compile(rb"(?i)\(193\)\s*$")
_INSTALLFILES = re.compile(rb"(?i)\b(?:ACTION_InstallFiles|action L[\"']?InstallFiles)\b")
_FINALIZE = re.compile(rb"(?i)\b(?:action L[\"']?InstallFinalize|InstallFinalize)\b")
_UNSUPPORTED = re.compile(rb"(?i)\b(?:msidbCustomActionTypeTSAware|custom action.*not handled)\b")


def empty() -> dict:
    return {"status": "NOT_REQUESTED", "classes": [], "msi_error_lines": 0}


def parse(raw: bytes, *, oversized: bool = False) -> dict:
    if not isinstance(raw, bytes):
        return {"status": "UNREADABLE", "classes": [], "msi_error_lines": 0}
    if len(raw) > MAX_BYTES or oversized:
        return {"status": "TRUNCATED", "classes": [], "msi_error_lines": 0}
    classes: set[str] = set()
    lines = 0
    for line in raw.splitlines():
        if len(line) > MAX_LINE_BYTES or not _MSI_ERR.search(line):
            continue
        lines += 1
        if _CAB.search(line):
            classes.add("CABINET_MEDIA_MISSING")
            if _NETFX_CAB.search(line):
                classes.add("NETFX_CORE_CAB_MISSING")
        elif _CUSTOM_DLL.search(line):
            classes.add("CUSTOM_ACTION_DLL_LOAD")
            if _BAD_EXE.search(line):
                classes.add("CUSTOM_ACTION_BAD_EXE")
        elif _INSTALLFILES.search(line):
            classes.add("MSI_ACTION_INSTALLFILES")
        elif _FINALIZE.search(line):
            classes.add("MSI_ACTION_FINALIZE")
        elif _UNSUPPORTED.search(line):
            classes.add("MSI_CUSTOM_ACTION_UNSUPPORTED")
        else:
            classes.add("OTHER_MSI_ERROR")
    return {"status": "SCANNED", "classes": sorted(classes),
            "msi_error_lines": min(lines, 9999)}


def validate(result: dict) -> bool:
    if type(result) is not dict or set(result) != {
        "status", "classes", "msi_error_lines"
    }:
        return False
    if (result["status"] not in STATUS or type(result["classes"]) is not list
            or result["classes"] != sorted(set(result["classes"]))
            or any(v not in CLASSES for v in result["classes"])
            or type(result["msi_error_lines"]) is not int
            or not 0 <= result["msi_error_lines"] <= 9999):
        return False
    if result["status"] != "SCANNED":
        return result["classes"] == [] and result["msi_error_lines"] == 0
    return (result["msi_error_lines"] >= 1) == bool(result["classes"])
