"""Run self-authored native Win32 monitor against original .NET 4.8 only.

The monitor is compiled from the same source as the 4.8.1 monitor, but
with SWCOMPAT_NETFX48 enabled. The only accepted media is our
separately SHA256-verified, Microsoft-signed 4.8 offline redistributable.
No original Windows process text or raw logs are returned.
"""
from __future__ import annotations
import os
from pathlib import Path
import subprocess
import tempfile

from scripts.netfx481_win32_exit import blank, parse, termination

MAX_OUTPUT = 4096


def launch(wine: Path, prefix: Path, installer: Path,
           fixture: Path, timeout: int = 245) -> dict:
    from scripts.netfx481_trial import validate_prefix
    from swcompat.wine_paths import windows_media_path

    validate_prefix(prefix)
    if (fixture.is_symlink() or not fixture.is_file()
            or fixture.name.casefold() != "netfx48_win32_launch.exe"):
        raise ValueError("Expected .NET 4.8-specific native launcher")
    if (installer.is_symlink() or not installer.is_file()
            or installer.name.casefold() != "ndp48-x86-x64-allos-enu.exe"):
        raise ValueError("Unexpected original Microsoft setup filename")
    path = windows_media_path(wine, prefix, installer)
    env = os.environ.copy()
    env.pop("WINEDLLOVERRIDES", None)
    env.update({"WINEPREFIX": str(prefix), "WINEARCH": "win64", "WINEDEBUG": "-all"})
    with tempfile.TemporaryFile() as output:
        try:
            process = subprocess.run(
                [str(wine), str(fixture), path], cwd=fixture.parent, env=env,
                stdin=subprocess.DEVNULL, stdout=output,
                stderr=subprocess.DEVNULL, check=False, timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            return blank("TIMEOUT")
        except OSError:
            return blank("PROCESS_FAILED")
        output.seek(0)
        raw = output.read(MAX_OUTPUT + 1)
    return parse(raw, process.returncode)


SELFTEST_STATES = {"PASS", "NO_OUTPUT", "UNEXPECTED_OUTPUT", "BAD_REPORT",
                   "PROCESS_FAILED", "TIMEOUT"}


def selftest(wine: Path, prefix: Path, fixture: Path, timeout: int = 50) -> str:
    """Probe Win32 execution of this same x64 fixture without Microsoft setup."""
    from scripts.netfx481_trial import validate_prefix

    validate_prefix(prefix)
    if (fixture.is_symlink() or not fixture.is_file()
            or fixture.name.casefold() != "netfx48_win32_launch.exe"):
        raise ValueError("Unexpected Win32 4.8 selftest fixture")
    env = os.environ.copy()
    env.pop("WINEDLLOVERRIDES", None)
    env.update({"WINEPREFIX": str(prefix), "WINEARCH": "win64", "WINEDEBUG": "-all"})
    with tempfile.TemporaryFile() as out:
        try:
            proc = subprocess.run(
                [str(wine), str(fixture), "--selftest-3010"], cwd=fixture.parent,
                env=env, stdin=subprocess.DEVNULL, stdout=out,
                stderr=subprocess.DEVNULL, timeout=timeout, check=False)
        except subprocess.TimeoutExpired:
            return "TIMEOUT"
        except OSError:
            return "PROCESS_FAILED"
        out.seek(0)
        raw = out.read(MAX_OUTPUT + 1)
    parsed = parse(raw, proc.returncode)
    if parsed["status"] == "EXIT_CAPTURED" and parsed["exit_hex"] == "00000BC2":
        return "PASS"
    if parsed["status"] == "BAD_REPORT":
        return ("UNEXPECTED_OUTPUT" if raw and b"SWCOMPAT_WIN32_SETUP_" not in raw
                else "NO_OUTPUT" if not raw else "BAD_REPORT")
    return "BAD_REPORT"
