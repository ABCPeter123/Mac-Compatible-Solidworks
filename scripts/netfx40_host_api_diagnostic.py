"""Read-only CLRCreateInstance differential in a genuine installed .NET 4.0 prefix.

Uses the existing source-authored Windows CLR hosting fixture and managed DLL.
The native Microsoft 4.0 install must first survive restart. No original
Microsoft DLLs, paths, Wine traces or arbitrary stdout enter the report.
"""
from __future__ import annotations
import argparse
import json
import os
import re
from pathlib import Path
import subprocess
import tempfile

from scripts.netfx40_msxml3_restart import validate as validate_restart
from scripts.netfx481_trial import validate_prefix

STATUS = {
    "NOT_RUN", "INVALID_INPUT", "ORIGINAL_MISSING", "ORIGINAL_LOAD_FAILED",
    "ORIGINAL_PATH_MISMATCH", "ORIGINAL_SHIM_INVALID_INPUT",
    "ORIGINAL_SHIM_MISSING", "ORIGINAL_SHIM_MISSING_DEPENDENCY",
    "ORIGINAL_SHIM_MISSING_EXPORT", "ORIGINAL_SHIM_BAD_IMAGE",
    "ORIGINAL_SHIM_INIT_FAILED", "ORIGINAL_SHIM_ACCESS_DENIED",
    "ORIGINAL_SHIM_LOAD_FAILED", "ORIGINAL_SHIM_NO_HOST_EXPORT",
    "NO_MSCOREE", "NO_HOST_EXPORT", "META_HOST_FAILED",
    "RUNTIME_DISCOVERY_FAILED", "RUNTIME_DIRECTORY_FAILED",
    "OTHER_RUNTIME_SELECTED", "HOST_INTERFACE_FAILED",
    "PRECHECK_LOADABLE_FAILED", "PRECHECK_STARTED_FAILED",
    "PRECHECK_LOADABLE_ALREADY_STARTED", "PRECHECK_LOADABLE_NOT_STARTED",
    "PRECHECK_UNLOADABLE_ALREADY_STARTED", "PRECHECK_UNLOADABLE_NOT_STARTED",
    "HOST_START_E_FAIL", "HOST_START_NOT_IMPLEMENTED",
               "HOST_START_UNEXPECTED", "HOST_START_ACCESS_DENIED",
               "HOST_START_OUT_OF_MEMORY", "HOST_START_INVALID_ARGUMENT",
               "HOST_START_MISSING_MODULE", "HOST_START_MISSING_EXPORT",
               "HOST_START_BAD_IMAGE", "HOST_START_WIN32_NOT_IMPLEMENTED",
               "HOST_START_WIN32_NOT_SUPPORTED", "HOST_START_CLR_FACILITY",
               "HOST_START_WIN32_FACILITY", "HOST_START_OTHER", "HOST_START_FAILED", "MANAGED_FIXTURE_MISSING",
    "MANAGED_EXECUTION_FAILED", "MANAGED_UNEXPECTED_RESULT",
    "MANAGED_ORIGINAL_PASS", "INVALID_OUTPUT", "PROCESS_FAILED", "TIMEOUT",
}
MAX_BYTES = 256 * 1024
PREFIX = b"SWCOMPAT_NETFX48_HOST_"
CLR_PATH = r"C:\windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll"


def blank() -> dict:
    return {"status": "NOT_ELIGIBLE", "native": "NOT_RUN",
            "builtin": "NOT_RUN", "native_managed_pass": False,
            "framework48_installed": False}


def valid(value: object) -> bool:
    if type(value) is not dict or set(value) != set(blank()):
        return False
    if value["status"] == "NOT_ELIGIBLE":
        return value == blank()
    return (value["status"] == "MEASURED"
            and value["native"] in STATUS and value["builtin"] in STATUS
            and type(value["native_managed_pass"]) is bool
            and value["native_managed_pass"]
                == (value["native"] == "MANAGED_ORIGINAL_PASS")
            and value["framework48_installed"] is False)


def classify(raw: bytes, code: int) -> str:
    if len(raw) > MAX_BYTES or code != 0 or bytes([0]) in raw:
        return "INVALID_OUTPUT"
    lines = [line for line in raw.splitlines() if line.startswith(PREFIX)]
    if len(lines) != 2 or lines[0] != b"SWCOMPAT_NETFX48_HOST_SCHEMA=1":
        return "INVALID_OUTPUT"
    label = b"SWCOMPAT_NETFX48_HOST_STATUS="
    if not lines[1].startswith(label):
        return "INVALID_OUTPUT"
    try:
        value = lines[1][len(label):].decode("ascii")
    except UnicodeDecodeError:
        return "INVALID_OUTPUT"
    return value if value in STATUS and value not in {
        "NOT_RUN", "INVALID_OUTPUT", "PROCESS_FAILED", "TIMEOUT"
    } else "INVALID_OUTPUT"


def execute(wine: Path, prefix: Path, fixture: Path, managed: Path,
            mode: str, *, precheck: bool = False,
            disable_native_images: bool = False,
            clrload_log_dir: str | None = None) -> str:
    if mode not in ("n", "b"):
        raise ValueError("Unsupported CLR hosting override")
    env = os.environ.copy()
    env.pop("SWCOMPAT_ORIGINAL_SHIM_PATH", None)
    env.pop("SWCOMPAT_SHIM_ONLY", None)
    env.pop("SWCOMPAT_HOST_PRECHECK", None)
    env.pop("COMPlus_ZapDisable", None)
    env.pop("COMPLUS_CLRLoadLogDir", None)
    if clrload_log_dir is not None:
        if not re.fullmatch(r"C:\\swcompat-clrload-[a-z0-9_-]{6,60}",
                            clrload_log_dir):
            raise ValueError("Untrusted CLR activation log destination")
        env["COMPLUS_CLRLoadLogDir"] = clrload_log_dir
    if disable_native_images:
        # .NET Framework diagnostic switch: force IL/JIT instead of NGEN
        # native images, without touching registry or vendor files.
        env["COMPlus_ZapDisable"] = "1"
    if precheck:
        env["SWCOMPAT_HOST_PRECHECK"] = "1"
    env["WINEPREFIX"] = str(prefix)
    env["WINEARCH"] = "win64"
    env["WINEDEBUG"] = "-all"
    env["WINEDLLOVERRIDES"] = f"mscoree={mode};clr=n"
    env["SWCOMPAT_CLR_PATH"] = CLR_PATH
    env["SWCOMPAT_MANAGED_DLL"] = "Z:" + str(managed).replace("/", "\\")
    with tempfile.TemporaryFile() as out:
        try:
            proc = subprocess.run([str(wine), str(fixture)], env=env,
                                  cwd=fixture.parent, stdin=subprocess.DEVNULL,
                                  stdout=out, stderr=subprocess.STDOUT,
                                  timeout=75, check=False)
        except subprocess.TimeoutExpired:
            return "TIMEOUT"
        except OSError:
            return "PROCESS_FAILED"
        out.seek(0)
        return classify(out.read(MAX_BYTES + 1), proc.returncode)


def audit(wine: Path, prefix: Path, fixture: Path, managed: Path,
          restart: dict) -> dict:
    validate_prefix(prefix)
    if not validate_restart(restart):
        raise ValueError("Invalid genuine native .NET 4.0 restart report")
    if not (restart["persistent_native_managed"]
            and restart["native_only_managed"] == "PASS"):
        return blank()
    for file in (wine, fixture, managed):
        if file.is_symlink() or not file.is_file():
            raise ValueError("Invalid or linked host fixture")
    if (not os.access(wine, os.X_OK)
            or fixture.name != "netfx48_host_activation.exe"
            or managed.name != "netfx48_managed_host_check.dll"
            or any(file.resolve().is_relative_to(prefix.resolve())
                   for file in (wine, fixture, managed))):
        raise ValueError("Untrusted host fixture or managed DLL location")
    result = {"status": "MEASURED",
              "native": execute(wine.resolve(), prefix.resolve(),
                                fixture.resolve(), managed.resolve(), "n"),
              "builtin": execute(wine.resolve(), prefix.resolve(),
                                 fixture.resolve(), managed.resolve(), "b"),
              "native_managed_pass": False,
              "framework48_installed": False}
    result["native_managed_pass"] = result["native"] == "MANAGED_ORIGINAL_PASS"
    assert valid(result)
    return result


def main(argv=None):
    ap = argparse.ArgumentParser()
    for name in ("wine", "prefix", "fixture", "managed", "restart", "output"):
        ap.add_argument("--" + name, required=True, type=Path)
    ap.add_argument("--agree-disposable-prefix", required=True, action="store_true")
    args = ap.parse_args(argv)
    if args.output.is_symlink() or args.output.resolve().is_relative_to(
            args.prefix.resolve()):
        ap.error("Report must be outside the disposable prefix")
    report = audit(args.wine, args.prefix, args.fixture, args.managed,
                   json.loads(args.restart.read_text(encoding="utf-8")))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, sort_keys=True), encoding="utf-8")
    print("AUTHENTIC_NETFX40_PUBLIC_HOST_API",
          report["status"], report["native"], report["builtin"],
          report["native_managed_pass"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
