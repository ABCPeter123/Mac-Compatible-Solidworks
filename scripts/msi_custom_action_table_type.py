"""Strict metadata-only MSI CustomAction Type lookup through Windows MSI APIs.

Never send action names in argv or published reports. The test uses the original
self-authored MSI; the same tool can later inspect available original Microsoft
MSI media in a disposable Wine prefix, if and only if those files exist.
"""
from __future__ import annotations

import os
from pathlib import Path
import re
import subprocess

from scripts.netfx481_trial import validate_prefix
from scripts.netfx40_msi_custom_type import FAMILIES
from swcompat.wine_paths import windows_media_path

STATUSES = {
    "ACTION_FOUND", "ACTION_ABSENT", "DATABASE_UNAVAILABLE", "TABLE_UNAVAILABLE",
    "QUERY_FAILED", "INVALID_ARGUMENT", "PROCESS_FAILED", "TIMED_OUT",
    "MALFORMED", "BAD_EXIT",
}
LINE = re.compile(rb"SWCOMPAT_CA_TABLE_(STATUS|TYPE|STAGE)=([A-Z_]+|[0-9]{1,10})\\Z")
STAGES = {
    "NOT_OBSERVED", "ENTRY", "INPUT_OK", "DATABASE_OPEN", "VIEW_OPEN",
    "PARAMETER_SET", "VIEW_EXECUTED", "ROW_FETCHED",
}
ACTIONS = {"ServiceTypeControlSentinel"}


def parse(raw: bytes, code: int) -> dict:
    r = {"status": "MALFORMED", "base_type": None,
         "family": "NOT_VERIFIED", "stage": "NOT_OBSERVED"}
    if not isinstance(raw, bytes) or len(raw) > 2048:
        return r
    fields: dict[str, str] = {}
    stage = "NOT_OBSERVED"
    stages = []
    for line in raw.splitlines():
        found = LINE.fullmatch(line.strip())
        if not found:
            return r
        key = found.group(1).decode("ascii")
        value = found.group(2).decode("ascii")
        if key == "STAGE":
            if value not in STAGES or value == "NOT_OBSERVED" or len(stages) >= 8:
                return r
            stages.append(value)
            stage = value
        else:
            if key in fields:
                return r
            fields[key] = value
    if code != 0:
        return {**r, "status": "BAD_EXIT", "stage": stage}
    if set(fields) != {"STATUS", "TYPE"} or fields["STATUS"] not in STATUSES:
        return {**r, "stage": stage}
    value = int(fields["TYPE"]) if fields["TYPE"].isdigit() else -1
    if fields["STATUS"] == "ACTION_FOUND":
        if not 0 <= value <= 65535:
            return {**r, "stage": stage}
        base = value & 0x3F
        return {"status": "ACTION_FOUND", "base_type": base,
                "family": FAMILIES.get(base, "OTHER_TYPE"), "stage": stage}
    if value == 0:
        return {"status": fields["STATUS"], "base_type": None,
                "family": "NOT_VERIFIED", "stage": stage}
    return {**r, "stage": stage}


def validate(report: dict) -> bool:
    if type(report) is not dict or set(report) != {"status", "base_type", "family", "stage"}:
        return False
    if report["status"] not in STATUSES or report["stage"] not in STAGES:
        return False
    if report["status"] != "ACTION_FOUND":
        return report["base_type"] is None and report["family"] == "NOT_VERIFIED"
    return (type(report["base_type"]) is int
            and 0 <= report["base_type"] <= 63
            and report["family"] == FAMILIES.get(report["base_type"], "OTHER_TYPE"))


def inspect(wine: Path, prefix: Path, probe: Path, msi: Path,
            action: str = "ServiceTypeControlSentinel") -> dict:
    if os.name == "nt":
        raise ValueError("Use native Windows probe directly")
    validate_prefix(prefix)
    if any(p.is_symlink() for p in (wine, probe, msi)):
        raise ValueError("Do not follow linked MSI/probe")
    if action not in ACTIONS:
        raise ValueError("Control only accepts known self-authored action")
    if probe.name != "msi_custom_action_table_probe.exe" or not probe.is_file():
        raise ValueError("Expected original Win32 metadata probe")
    if not msi.is_file():
        raise ValueError("Expected original self-authored MSI")
    path = windows_media_path(wine, prefix, msi)
    env = os.environ.copy()
    env.update({"WINEPREFIX": str(prefix), "WINEARCH": "win64", "WINEDEBUG": "-all"})
    try:
        result = subprocess.run(
            [str(wine), str(probe), path], input=action.encode("utf-8"),
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            env=env, cwd=prefix, timeout=25, check=False,
        )
    except subprocess.TimeoutExpired:
        return {"status": "TIMED_OUT", "base_type": None, "family": "NOT_VERIFIED", "stage": "NOT_OBSERVED"}
    except OSError:
        return {"status": "PROCESS_FAILED", "base_type": None, "family": "NOT_VERIFIED", "stage": "NOT_OBSERVED"}
    return parse(result.stdout, result.returncode)
