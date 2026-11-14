"""A/B run identical self-authored Win32 harness source under one Wine prefix.

This contains no Microsoft installer, SOLIDWORKS program, license or vendor DLL.
Only bounded protocol statuses, Unix process codes and fixed error categories
leave the ephemeral macOS runner. Raw stdout/stderr never enter CI logs.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile

from scripts.netfx481_trial import validate_prefix
from scripts.netfx481_win32_exit import parse as parse_win32

MAX_PROTOCOL = 4096
MAX_STDERR = 128 * 1024
ALLOWED_BINARY_NAMES = {"netfx48_win32_launch.exe", "netfx481_win32_launch.exe"}
PROTOCOL_STATES = {"PASS", "NO_OUTPUT", "BAD_REPORT", "PROCESS_ERROR", "TIMEOUT"}
CMD_STATES = {"PASS", "NO_OUTPUT", "NONZERO", "PROCESS_ERROR", "TIMEOUT"}
ERROR_STATES = {"NONE", "TOO_LARGE", "MODULE_LOAD_FAILED", "BAD_PE", "WINE_CRASH", "OTHER"}
COMPARISONS = {"BOTH_PASS", "ONLY_481_PASS", "ONLY_48_PASS", "BOTH_FAIL"}


def _env(prefix: Path) -> dict[str, str]:
    env = os.environ.copy()
    env.pop("WINEDLLOVERRIDES", None)
    env.update({
        "WINEPREFIX": str(prefix), "WINEARCH": "win64",
        # Wine debug output can include private paths. It is never forwarded.
        "WINEDEBUG": "-all,+module,+seh",
    })
    return env


def _stderr_kind(raw: bytes) -> str:
    if len(raw) > MAX_STDERR:
        return "TOO_LARGE"
    if not raw:
        return "NONE"
    lowered = raw.lower()
    if (b"import_dll" in lowered and b"not found" in lowered) or b"c0000135" in lowered:
        return "MODULE_LOAD_FAILED"
    if b"c000007b" in lowered or b"bad exe format" in lowered:
        return "BAD_PE"
    if b"unhandled exception" in lowered or b"unhandled page fault" in lowered:
        return "WINE_CRASH"
    return "OTHER"


def _capture(wine: Path, prefix: Path, arguments: list[str],
             timeout: int = 65) -> tuple[bytes, bytes, int | None, str | None]:
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        try:
            completed = subprocess.run(
                [str(wine), *arguments], cwd=prefix, env=_env(prefix),
                stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                timeout=timeout, check=False,
            )
            code = completed.returncode
            failure = None
        except subprocess.TimeoutExpired:
            code, failure = None, "TIMEOUT"
        except OSError:
            code, failure = None, "PROCESS_ERROR"
        stdout.seek(0)
        stderr.seek(0)
        return (
            stdout.read(MAX_PROTOCOL + 1),
            stderr.read(MAX_STDERR + 1),
            code if type(code) is int and -255 <= code <= 255 else None,
            failure,
        )


def win_cmd(wine: Path, prefix: Path) -> dict:
    """Control for normal Windows console stdout, independent of our MSVC exe."""
    validate_prefix(prefix)
    output, stderr, code, failure = _capture(
        wine, prefix, ["cmd.exe", "/d", "/c", "echo SWCOMPAT_WIN_CMD_PASS=1"])
    if failure is not None:
        state = failure
    elif code == 0 and b"SWCOMPAT_WIN_CMD_PASS=1" in output:
        state = "PASS"
    elif not output:
        state = "NO_OUTPUT"
    else:
        state = "NONZERO"
    return {"status": state, "unix_code": code, "wine_stderr": _stderr_kind(stderr)}


def win32_selftest(wine: Path, prefix: Path, fixture: Path) -> dict:
    validate_prefix(prefix)
    if (fixture.is_symlink() or not fixture.is_file()
            or fixture.name.casefold() not in ALLOWED_BINARY_NAMES):
        raise ValueError("Only our two self-authored Win32 launchers are permitted")
    output, stderr, code, failure = _capture(
        wine, prefix, [str(fixture), "--selftest-3010"])
    if failure is not None:
        state = failure
    elif not output:
        state = "NO_OUTPUT"
    elif parse_win32(output, code if code is not None else 999)["status"] == "EXIT_CAPTURED" and (
            b"SWCOMPAT_WIN32_SETUP_EXIT_HEX=00000BC2" in output):
        state = "PASS"
    else:
        state = "BAD_REPORT"
    return {"status": state, "unix_code": code, "wine_stderr": _stderr_kind(stderr)}


def validate(report: dict) -> bool:
    if type(report) is not dict or set(report) != {
        "schema", "scope", "wine_cmd", "launcher_481", "launcher_48",
        "comparison", "solidworks_compatibility",
    } or report["schema"] != 1 or report["scope"] != "WIN32_LAUNCHER_AB_NO_VENDOR_MEDIA":
        return False
    for key, allowed in (
        ("wine_cmd", CMD_STATES),
        ("launcher_481", PROTOCOL_STATES),
        ("launcher_48", PROTOCOL_STATES),
    ):
        x = report[key]
        if type(x) is not dict or set(x) != {"status", "unix_code", "wine_stderr"}:
            return False
        if x["status"] not in allowed or x["wine_stderr"] not in ERROR_STATES:
            return False
        if x["unix_code"] is not None and (
                type(x["unix_code"]) is not int or not -255 <= x["unix_code"] <= 255):
            return False
    a = report["launcher_481"]["status"] == "PASS"
    b = report["launcher_48"]["status"] == "PASS"
    expected = ("BOTH_PASS" if a and b else "ONLY_481_PASS" if a
                else "ONLY_48_PASS" if b else "BOTH_FAIL")
    return (report["comparison"] in COMPARISONS
            and report["comparison"] == expected
            and report["solidworks_compatibility"] == "NOT_TESTED")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="A/B diagnostic of two self-authored Windows executables in Wine")
    for key in ("wine", "prefix", "launcher-481", "launcher-48", "output"):
        ap.add_argument("--" + key, required=True, type=Path)
    ap.add_argument("--agree-disposable-prefix", action="store_true", required=True)
    args = ap.parse_args(argv)
    try:
        if args.output.is_symlink() or args.output.resolve() in {
            args.launcher_481.resolve(), args.launcher_48.resolve(),
            args.wine.resolve(),
        }:
            raise ValueError("Refuse overwriting input")
        validate_prefix(args.prefix)
        if args.wine.is_symlink() or not args.wine.is_file() or not os.access(args.wine, os.X_OK):
            raise ValueError("Wine unavailable")
        if (args.launcher_481.name.casefold() != "netfx481_win32_launch.exe"
                or args.launcher_48.name.casefold() != "netfx48_win32_launch.exe"):
            raise ValueError("Unexpected Windows fixtures")
        control = win_cmd(args.wine, args.prefix)
        a = win32_selftest(args.wine, args.prefix, args.launcher_481)
        b = win32_selftest(args.wine, args.prefix, args.launcher_48)
        comparison = ("BOTH_PASS" if a["status"] == b["status"] == "PASS"
                      else "ONLY_481_PASS" if a["status"] == "PASS"
                      else "ONLY_48_PASS" if b["status"] == "PASS"
                      else "BOTH_FAIL")
        result = {"schema": 1, "scope": "WIN32_LAUNCHER_AB_NO_VENDOR_MEDIA",
                  "wine_cmd": control, "launcher_481": a, "launcher_48": b,
                  "comparison": comparison, "solidworks_compatibility": "NOT_TESTED"}
        if not validate(result):
            raise ValueError("Invalid bounded output")
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    except (OSError, ValueError):
        ap.error("Self-authored Windows Wine launcher diagnostic refused")
    print("Wine cmd stdout:", control["status"])
    print("x64 4.8.1 launcher:", a["status"], "Unix code:", a["unix_code"],
          "Wine stderr classification:", a["wine_stderr"])
    print("x64 4.8 launcher:", b["status"], "Unix code:", b["unix_code"],
          "Wine stderr classification:", b["wine_stderr"])
    print("Same-prefix A/B comparison:", comparison)
    print("SOLIDWORKS: NOT TESTED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
