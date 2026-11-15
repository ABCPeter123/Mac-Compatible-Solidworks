"""Safe import-family census of a Type 1 MSI Binary custom-action stream.

The original action identifier is never passed on argv or printed. Native
Microsoft binary bytes stay in MsiRecordReadStream memory in the child process.
No original DLL is written to a host file or loaded via LoadLibrary.
"""
from __future__ import annotations

import os
from pathlib import Path
import re
import subprocess

from scripts.netfx40_private_action import ACTION_RE
from scripts.netfx481_trial import validate_prefix
from swcompat.wine_paths import windows_media_path

FAMILIES = ("ADVAPI32", "MSI", "KERNEL32", "FUSION", "MSCOREE",
            "OLE32", "RPCRT4", "NTDLL", "OTHER")
API_FAMILIES = ("SCM_READ", "SCM_MODIFY", "SCM_START",
                "REGISTRY_READ", "REGISTRY_WRITE", "MSI_READ",
                "MSI_WRITE", "PROCESS_LOADER", "OTHER_API")
STATUSES = {"PARSED", "NOT_PE", "INVALID_PE", "ACTION_ABSENT", "NOT_DLL_BINARY",
            "BINARY_ABSENT", "INPUT_FAILED", "INVALID_ARGUMENT", "REPORT_FAILED",
            "DATABASE_FAILED", "QUERY_FAILED", "MEMORY_FAILED",
            "STREAM_FAILED", "STREAM_TOO_LARGE", "STREAM_EMPTY",
            "PROCESS_FAILED", "TIMED_OUT", "MALFORMED", "NOT_REQUESTED"}
MACHINES = {"UNKNOWN", "AMD64", "X86", "ARM64", "OTHER"}
LINE = re.compile(rb"SWCOMPAT_BINARY_([A-Z0-9_]+)=([A-Z0-9_]+)\Z")
MAX_OUTPUT = 2048


def empty(status: str = "NOT_REQUESTED") -> dict:
    if status not in STATUSES:
        raise ValueError("Unexpected original MSI import probe state")
    return {"status": status, "machine": "UNKNOWN",
            "imports": {name: 0 for name in FAMILIES},
            "api_imports": {name: 0 for name in API_FAMILIES},
            "native_microsoft_clr": False}


def validate(r: object) -> bool:
    if type(r) is not dict or set(r) != set(empty()):
        return False
    if (r["status"] not in STATUSES or r["machine"] not in MACHINES or
            r["native_microsoft_clr"] is not False):
        return False
    counts = r["imports"]
    if (type(counts) is not dict or set(counts) != set(FAMILIES) or
            any(type(v) is not int or not 0 <= v <= 256 for v in counts.values()) or
            sum(counts.values()) > 256):
        return False
    api = r["api_imports"]
    if (type(api) is not dict or set(api) != set(API_FAMILIES)
            or any(type(v) is not int or not 0 <= v <= 4096 for v in api.values())
            or sum(api.values()) > 4096):
        return False
    if r["status"] != "PARSED":
        return r == empty(r["status"])
    return r["machine"] != "UNKNOWN"


def parse(raw: bytes, code: int) -> dict:
    if not isinstance(raw, bytes) or len(raw) > MAX_OUTPUT:
        return empty("MALFORMED")
    fields: dict[str, str] = {}
    expected = {"STATUS", "MACHINE", *FAMILIES, *(f"API_{k}" for k in API_FAMILIES)}
    for line in raw.splitlines():
        item = LINE.fullmatch(line.strip())
        if not item:
            return empty("MALFORMED")
        key, val = (part.decode("ascii") for part in item.groups())
        if key not in expected or key in fields:
            return empty("MALFORMED")
        fields[key] = val
    if code != 0:
        return empty("PROCESS_FAILED")
    if set(fields) != expected or fields["STATUS"] not in STATUSES:
        return empty("MALFORMED")
    status = fields["STATUS"]
    if status != "PARSED":
        return empty(status)
    if fields["MACHINE"] not in MACHINES - {"UNKNOWN"}:
        return empty("MALFORMED")
    if any(not fields[k].isdigit() for k in FAMILIES) or any(
            not fields[f"API_{k}"].isdigit() for k in API_FAMILIES):
        return empty("MALFORMED")
    result = {"status": status, "machine": fields["MACHINE"],
              "imports": {k: int(fields[k]) for k in FAMILIES},
              "api_imports": {k: int(fields[f"API_{k}"]) for k in API_FAMILIES},
              "native_microsoft_clr": False}
    return result if validate(result) else empty("MALFORMED")


def inspect(wine: Path, prefix: Path, helper: Path, msi: Path, action: str) -> dict:
    if os.name == "nt" or any(p.is_symlink() for p in (wine, prefix, helper, msi)):
        raise ValueError("Original binary query only in isolated Wine")
    if (not isinstance(action, str) or not action.isascii() or
            not ACTION_RE.fullmatch(action.encode("ascii"))):
        raise ValueError("Unsafe original MSI action identifier")
    wine, prefix, helper, msi = (
        p.resolve(strict=True) for p in (wine, prefix, helper, msi)
    )
    validate_prefix(prefix)
    if (helper.name != "msi_original_binary_imports.exe" or
            not helper.is_file() or not msi.is_file() or
            not wine.is_file() or not os.access(wine, os.X_OK)):
        raise ValueError("Unexpected imported action probe inputs")
    msipath = windows_media_path(wine, prefix, msi)
    directory = prefix / "drive_c" / "windows" / "temp"
    if directory.is_symlink():
        raise ValueError("Linked Windows temp refused")
    directory.mkdir(parents=True, exist_ok=True)
    action_file = directory / "swcompat_ca_action_private.input"
    status_file = directory / "swcompat_ca_binary_probe.status"
    if any(p.exists() or p.is_symlink() for p in (action_file, status_file)):
        raise ValueError("Probe private evidence must be fresh")
    fd = os.open(action_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(action.encode("ascii"))
    env = {**os.environ, "WINEPREFIX": str(prefix),
           "WINEARCH": "win64", "WINEDEBUG": "-all"}
    result = None
    try:
        try:
            child = subprocess.run(
                [str(wine), str(helper), msipath,
                 r"C:\windows\temp\swcompat_ca_binary_probe.status",
                 "--private-file"],
                cwd=prefix, env=env, stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                timeout=30, check=False,
            )
        except subprocess.TimeoutExpired:
            result = empty("TIMED_OUT")
        except OSError:
            result = empty("PROCESS_FAILED")
        else:
            if status_file.is_symlink():
                raise ValueError("Linked binary status report refused")
            if status_file.is_file():
                with status_file.open("rb") as f:
                    raw = f.read(MAX_OUTPUT + 1)
                result = parse(raw, child.returncode)
            else:
                result = empty("PROCESS_FAILED")
    finally:
        action_file.unlink(missing_ok=True)
        if status_file.is_file() and not status_file.is_symlink():
            status_file.unlink()
    if result is None or not validate(result):
        raise ValueError("Invalid original action import census")
    return result
