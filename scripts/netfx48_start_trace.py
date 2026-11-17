"""Privacy-safe Wine diagnostic of original Microsoft .NET 4.8 CLR Start.

Only the source-authored CLR host fixture is executed. Wine loader, module and
SEH diagnostics remain in anonymous temporary files; exported evidence has
fixed enums and booleans, never Microsoft bytes, original paths or log lines.
"""
from __future__ import annotations

import os
from pathlib import Path
import re
import subprocess
import tempfile

from scripts.netfx40_host_api_diagnostic import (
    STATUS as HOST_STATUSES, CLR_PATH, classify,
)
from scripts.netfx40_native_mscoree_provenance import LOADED

MAX_TRACE = 16 * 1024 * 1024
CHANNELS = ("module", "mscoree", "ole", "reg", "seh", "other")
COUNTS = {"NONE", "ONE", "FEW", "MANY"}
WINE_MESSAGE = re.compile(r"\\b(err|fixme):([a-z0-9_]+):", re.IGNORECASE)
MAX_STDOUT = 256 * 1024
STATES = {"NOT_RUN", "MEASURED", "PARTIAL"}
PROCESSES = {"NOT_RUN", "EXIT_ZERO", "EXIT_NONZERO", "TIMEOUT", "SPAWN_ERROR"}
TRACE = {"NOT_RUN", "READABLE", "TOO_LARGE", "INVALID_ENCODING"}
MODULE_MISSING = re.compile(
    r"err:module:[^\r\n]{0,300}(?:not found|failed to load|could not be found)",
    re.IGNORECASE,
)
EXPORT_MISSING = re.compile(
    r"err:module:[^\r\n]{0,300}(?:function not found|unresolved import|missing export)",
    re.IGNORECASE,
)
SEH = re.compile(r"(?:err:seh:|unhandled exception)", re.IGNORECASE)
UNIMPLEMENTED = re.compile(
    r"(?:unimplemented function|err:[^\r\n]{0,120}stub)",
    re.IGNORECASE,
)


def blank() -> dict:
    return {
        "status": "NOT_RUN", "host": "NOT_RUN",
        "process": "NOT_RUN", "trace": "NOT_RUN",
        "native_clr_seen": False, "native_mscoree_seen": False,
        "native_mscoreei_seen": False,
        "module_missing": False, "export_missing": False,
        "seh_exception": False, "unimplemented_api": False,
        "error_channels": {k: False for k in CHANNELS},
        "fixme_channels": {k: False for k in CHANNELS},
        "error_count": "NONE", "fixme_count": "NONE",
        "framework48_installed": False,
    }


def valid(value: object) -> bool:
    if type(value) is not dict or set(value) != set(blank()):
        return False
    if (value["status"] not in STATES or value["host"] not in HOST_STATUSES
            or value["process"] not in PROCESSES
            or value["trace"] not in TRACE
            or any(type(value[key]) is not bool for key in (
                "native_clr_seen", "native_mscoree_seen",
                "native_mscoreei_seen", "module_missing", "export_missing",
                "seh_exception", "unimplemented_api"))
            or any(type(value.get(key)) is not dict
                   or set(value[key]) != set(CHANNELS)
                   or any(type(v) is not bool for v in value[key].values())
                   for key in ("error_channels", "fixme_channels"))
            or value["error_count"] not in COUNTS
            or value["fixme_count"] not in COUNTS
            or value["framework48_installed"] is not False):
        return False
    if value["status"] == "NOT_RUN":
        return value == blank()
    if value["process"] == "NOT_RUN" or value["host"] == "NOT_RUN":
        return False
    if value["status"] == "MEASURED":
        return value["process"] == "EXIT_ZERO" and value["trace"] == "READABLE"
    return True


def classify_trace(raw: bytes, *, truncated: bool = False) -> dict:
    """Return only a fixed schema. Never include raw loader paths or strings."""
    result = blank()
    result["status"] = "PARTIAL" if truncated else "MEASURED"
    result["trace"] = "TOO_LARGE" if truncated else "READABLE"
    if truncated:
        return result
    try:
        text = raw.decode("utf-8")
    except UnicodeError:
        result["status"] = "PARTIAL"
        result["trace"] = "INVALID_ENCODING"
        return result
    result["module_missing"] = bool(MODULE_MISSING.search(text))
    result["export_missing"] = bool(EXPORT_MISSING.search(text))
    result["seh_exception"] = bool(SEH.search(text))
    result["unimplemented_api"] = bool(UNIMPLEMENTED.search(text))
    counts = {"err": 0, "fixme": 0}
    for message in WINE_MESSAGE.finditer(text):
        level, channel = message.group(1).casefold(), message.group(2).casefold()
        counts[level] += 1
        target = "error_channels" if level == "err" else "fixme_channels"
        result[target][channel if channel in CHANNELS else "other"] = True
    def bucket(count: int) -> str:
        return "NONE" if count == 0 else "ONE" if count == 1 else "FEW" if count < 10 else "MANY"
    result["error_count"] = bucket(counts["err"])
    result["fixme_count"] = bucket(counts["fixme"])
    for match in LOADED.finditer(text):
        source = match.group(2).casefold()
        if source != "native":
            continue
        name = match.group(1).replace("/", "\\").rsplit("\\", 1)[-1].casefold()
        if name == "clr.dll":
            result["native_clr_seen"] = True
        elif name == "mscoree.dll":
            result["native_mscoree_seen"] = True
        elif name == "mscoreei.dll":
            result["native_mscoreei_seen"] = True
    return result


def probe(wine: Path, prefix: Path, fixture: Path, managed: Path) -> dict:
    wine = wine.resolve(strict=True)
    prefix = prefix.resolve(strict=True)
    fixture = fixture.resolve(strict=True)
    managed = managed.resolve(strict=True)
    if (fixture.name != "netfx48_host_activation.exe"
            or managed.name != "netfx48_managed_host_check.dll"
            or fixture.is_relative_to(prefix)
            or managed.is_relative_to(prefix)):
        raise ValueError("Untrusted source-authored host fixture")
    env = os.environ.copy()
    env.pop("SWCOMPAT_ORIGINAL_SHIM_PATH", None)
    env.pop("SWCOMPAT_SHIM_ONLY", None)
    env.update({
        "WINEPREFIX": str(prefix), "WINEARCH": "win64",
        "WINEDLLOVERRIDES": "mscoree=n;clr=n",
        # Keep all Wine diagnostics in private temp files; only the bounded
        # channel and count categories leave the runner.
        "WINEDEBUG": "-all,+loaddll,+module,+seh,+mscoree,+ole,+reg",
        "SWCOMPAT_CLR_PATH": CLR_PATH,
        "SWCOMPAT_MANAGED_DLL": "Z:" + str(managed).replace("/", "\\"),
    })
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        try:
            proc = subprocess.run(
                [str(wine), str(fixture)], cwd=fixture.parent, env=env,
                stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                timeout=90, check=False)
        except subprocess.TimeoutExpired:
            return dict(blank(), status="PARTIAL", host="TIMEOUT",
                        process="TIMEOUT", trace="READABLE")
        except OSError:
            return dict(blank(), status="PARTIAL", host="PROCESS_FAILED",
                        process="SPAWN_ERROR", trace="READABLE")
        stdout.seek(0)
        host = classify(stdout.read(MAX_STDOUT + 1), proc.returncode)
        stderr.seek(0)
        raw = stderr.read(MAX_TRACE + 1)
        report = classify_trace(raw, truncated=len(raw) > MAX_TRACE)
        report["host"] = host
        report["process"] = "EXIT_ZERO" if proc.returncode == 0 else "EXIT_NONZERO"
        if (report["status"] == "MEASURED" and
                (report["process"] != "EXIT_ZERO" or host == "INVALID_OUTPUT")):
            report["status"] = "PARTIAL"
    assert valid(report)
    return report
