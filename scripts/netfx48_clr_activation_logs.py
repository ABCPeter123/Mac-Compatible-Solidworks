"""Isolated, private Microsoft CLR activation-log differential on Wine.

Microsoft documents COMPLUS_CLRLoadLogDir as a process-scoped switch for
.NET Framework activation diagnostics. It is NOT a CLR-startup fix. Reports
carry only predefined booleans and finite statuses, never vendor log bytes,
paths, error text, Microsoft DLLs, or environment details.
"""
from __future__ import annotations

from pathlib import Path
import re
import tempfile

from scripts.netfx40_host_api_diagnostic import (
    STATUS as HOST_STATUSES, execute as host_execute,
)
from scripts.netfx481_trial import validate_prefix

MAX_FILES = 12
MAX_BYTES = 512 * 1024
TOTAL_BYTES = 2 * 1024 * 1024
PHASES = {"before", "staged", "after"}
STATES = {"NOT_RUN", "NO_LOG", "CAPTURED", "PARTIAL"}
FLAGS = (
    "activation_header", "installed_runtime", "selected_runtime",
    "runtime_load_call", "shim_failure", "install_root_failure",
    "reported_error",
)
SHIM_ERROR = re.compile(
    r"(?i)\b(?:CLR_E_SHIM_[A-Z_]+|runtime(?:load|export)|"
    r"cannot (?:find|load) (?:a )?(?:suitable )?runtime)\b"
)
ROOT_ERROR = re.compile(
    r"(?i)\b(?:install(?:ation)? root|installroot|installcomp|component missing)\b"
)


def blank() -> dict:
    return {
        "status": "NOT_RUN", "host": "NOT_RUN",
        "file_count": 0, "flags": {name: False for name in FLAGS},
        "framework48_installed": False,
    }


def valid(result: object) -> bool:
    if type(result) is not dict or set(result) != set(blank()):
        return False
    if (result["status"] not in STATES or result["host"] not in HOST_STATUSES
            or type(result["file_count"]) is not int
            or not 0 <= result["file_count"] <= MAX_FILES
            or type(result["flags"]) is not dict
            or set(result["flags"]) != set(FLAGS)
            or any(type(x) is not bool for x in result["flags"].values())
            or result["framework48_installed"] is not False):
        return False
    if result["status"] == "NOT_RUN":
        return result == blank()
    if result["host"] == "NOT_RUN":
        return False
    if result["status"] == "NO_LOG":
        return (result["file_count"] == 0
                and not any(result["flags"].values()))
    return result["file_count"] > 0 or result["status"] == "PARTIAL"


def classify_text(raw: bytes) -> dict[str, bool] | None:
    """Recognize only public CLR activation-event tokens, not their values."""
    if len(raw) > MAX_BYTES:
        return None
    try:
        if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
            content = raw.decode("utf-16")
        elif raw.count(b"\x00") > max(8, len(raw) // 8):
            content = raw.decode("utf-16-le")
        else:
            content = raw.decode("utf-8-sig")
    except UnicodeError:
        return None
    flags = {name: False for name in FLAGS}
    for line in content.splitlines()[:12000]:
        if len(line) > 8192:
            continue
        lower = line.casefold()
        flags["activation_header"] |= "clr loading log for" in lower
        flags["installed_runtime"] |= "installed runtime:" in lower
        flags["selected_runtime"] |= (
            "decided on runtime" in lower or "selected runtime" in lower)
        flags["runtime_load_call"] |= (
            "functioncall:" in lower or "loadruntime" in lower)
        flags["shim_failure"] |= SHIM_ERROR.search(line) is not None
        flags["install_root_failure"] |= ROOT_ERROR.search(line) is not None
        flags["reported_error"] |= bool(
            re.search(r"(?i)\b(?:error|failed|failure|exception)\b", line))
    return flags


def inspect(folder: Path, host: str) -> dict:
    if host not in HOST_STATUSES or host == "NOT_RUN":
        raise ValueError("Invalid original CLR host result")
    result = dict(blank(), host=host, status="NO_LOG")
    if folder.is_symlink() or not folder.is_dir():
        return dict(result, status="PARTIAL")
    try:
        entries = list(folder.iterdir())
    except OSError:
        return dict(result, status="PARTIAL")
    if len(entries) > MAX_FILES:
        return dict(result, status="PARTIAL")
    total = 0
    for entry in entries:
        if entry.is_symlink() or not entry.is_file():
            return dict(result, status="PARTIAL")
        try:
            size = entry.stat().st_size
            if size > MAX_BYTES or total + size > TOTAL_BYTES:
                return dict(result, status="PARTIAL")
            with entry.open("rb") as file:
                raw = file.read(MAX_BYTES + 1)
        except OSError:
            return dict(result, status="PARTIAL")
        total += len(raw)
        flags = classify_text(raw)
        if flags is None:
            return dict(result, status="PARTIAL")
        result["file_count"] += 1
        for name in FLAGS:
            result["flags"][name] |= flags[name]
    if result["file_count"]:
        result["status"] = "CAPTURED"
    assert valid(result)
    return result


def probe(wine: Path, prefix: Path, fixture: Path, managed: Path,
          *, phase: str) -> dict:
    """Capture CLR activation logs only during a single source-authored host.

    Directories are under the marked disposable Wine prefix and removed even
    after an exception. No host registry values are modified.
    """
    if phase not in PHASES:
        raise ValueError("Unsupported CLR activation experiment phase")
    validate_prefix(prefix)
    for item in (wine, fixture, managed):
        if item.is_symlink() or not item.is_file():
            raise ValueError("Untrusted CLR hosting fixture")
        if item.resolve().is_relative_to(prefix.resolve()):
            raise ValueError("Probe source inside disposable prefix")
    if (fixture.name != "netfx48_host_activation.exe"
            or managed.name != "netfx48_managed_host_check.dll"):
        raise ValueError("Unexpected CLR host probe")
    drive = prefix / "drive_c"
    if drive.is_symlink() or not drive.is_dir():
        raise ValueError("Unsafe disposable Wine drive")
    with tempfile.TemporaryDirectory(prefix="swcompat-clrload-", dir=drive) as temp:
        folder = Path(temp)
        # Microsoft CLR accepts the Windows path, not a host Z: path.
        path_in_wine = "C:\\" + folder.name
        host = host_execute(
            wine, prefix, fixture, managed, "n",
            clrload_log_dir=path_in_wine,
        )
        result = inspect(folder, host)
    assert valid(result)
    return result
