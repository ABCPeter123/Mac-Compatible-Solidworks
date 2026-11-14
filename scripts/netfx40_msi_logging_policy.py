"""Opt-in Windows Installer verbose logging policy for a disposable Wine prefix.

Microsoft documents HKLM\Software\Policies\Microsoft\Windows\Installer
Logging (REG_SZ) = voicewarmupx to create MSI*.LOG files in Windows TEMP.
Never apply to the user's persistent Wine prefix, host registry, real Windows,
or any prefix with an existing policy value. No raw query output is emitted.
"""
from __future__ import annotations

import os
from pathlib import Path
import subprocess

KEY = r"HKLM\Software\Policies\Microsoft\Windows\Installer"
VALUE = "voicewarmupx"
ACTIVATIONS = {"NOT_REQUESTED", "APPLIED", "PREEXISTING", "UNAVAILABLE", "VERIFY_FAILED"}
RESTORATIONS = {"NOT_REQUIRED", "REMOVED", "RESTORE_FAILED"}
TIMEOUT = 35


def blank() -> dict[str, str]:
    return {"activation": "NOT_REQUESTED", "restoration": "NOT_REQUIRED"}


def _reg(wine: Path, prefix: Path, arguments: list[str]) -> tuple[int, bytes]:
    env = os.environ.copy()
    env.pop("WINEDLLOVERRIDES", None)
    env.update({"WINEPREFIX": str(prefix), "WINEARCH": "win64", "WINEDEBUG": "-all"})
    try:
        result = subprocess.run(
            [str(wine), "reg.exe", *arguments],
            cwd=prefix, env=env, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            timeout=TIMEOUT, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return -1, b""
    # Never write raw registry output to logs; only inspect bounded memory.
    return result.returncode, result.stdout[:4096]


def _query(wine: Path, prefix: Path) -> tuple[int, bytes]:
    return _reg(wine, prefix, ["query", KEY, "/v", "Logging"])


def apply(wine: Path, prefix: Path) -> str:
    from scripts.netfx481_trial import validate_prefix
    validate_prefix(prefix)
    if os.name == "nt" or wine.is_symlink() or prefix.is_symlink() or not wine.is_file():
        raise ValueError("Only a disposable Wine prefix is eligible")
    found, _ = _query(wine, prefix)
    if found == 0:
        return "PREEXISTING"
    if found != 1:
        return "UNAVAILABLE"
    result, _ = _reg(wine, prefix, [
        "add", KEY, "/v", "Logging", "/t", "REG_SZ", "/d", VALUE, "/f",
    ])
    if result != 0:
        return "UNAVAILABLE"
    checked, content = _query(wine, prefix)
    if checked == 0 and VALUE.encode("ascii") in content.lower():
        return "APPLIED"
    # The key may have been set, so do not silently leave it installed.
    return "VERIFY_FAILED"


def restore(wine: Path, prefix: Path, activation: str) -> str:
    from scripts.netfx481_trial import validate_prefix
    validate_prefix(prefix)
    if activation not in ACTIVATIONS:
        raise ValueError("Unknown policy action")
    if activation not in {"APPLIED", "VERIFY_FAILED"}:
        return "NOT_REQUIRED"
    code, _ = _reg(wine, prefix, ["delete", KEY, "/v", "Logging", "/f"])
    checked, _ = _query(wine, prefix)
    return "REMOVED" if code == 0 and checked == 1 else "RESTORE_FAILED"


def validate(report: dict) -> bool:
    if (type(report) is not dict or set(report) != {"activation", "restoration"}
            or report["activation"] not in ACTIVATIONS
            or report["restoration"] not in RESTORATIONS):
        return False
    if report["activation"] in {"APPLIED", "VERIFY_FAILED"}:
        return report["restoration"] in {"REMOVED", "RESTORE_FAILED"}
    return report["restoration"] == "NOT_REQUIRED"


def evaluate(wine: Path, prefix: Path) -> dict:
    status = apply(wine, prefix)
    return {"activation": status, "restoration": restore(wine, prefix, status)}
