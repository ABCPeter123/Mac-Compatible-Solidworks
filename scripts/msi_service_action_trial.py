"""Reproduce MSI InstallServices/StartServices with an original, harmless service.

Compare native Windows and hosted Apple Silicon Wine using the identical
MSVC x64 executable and WiX v5 MSI. Strictly isolated to a marked disposable
Wine prefix; report finite statuses only. Does not run or alter SOLIDWORKS.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

from scripts.netfx481_trial import validate_prefix
from scripts.netfx40_legacy import set_legacy_winver
from swcompat.wine_paths import windows_media_path

MSI_NAME = "swcompat_msi_service_action.msi"
EXE_NAME = "service_smoke.exe"
SERVICE_NAME = "SWCompatOriginalServiceTest"
RESULT_STATES = {"MEASURED", "ALREADY_PRESENT", "WINVER_FAILED"}
PROCESS_STATES = {"NOT_RUN", "ZERO", "NONZERO", "TIMEOUT", "START_FAILED"}
SERVICE_STATES = {"ABSENT", "RUNNING", "STOPPED", "LOCKED", "START_TIMEOUT", "OTHER", "UNKNOWN"}
FILE_STATES = {"ABSENT", "PRESENT_MATCH", "CHANGED", "LINKED", "IO_ERROR"}
SCOPE = "SELF_AUTHORED_MSI_SERVICE_START_NOT_SOLIDWORKS"
MARKERS = {"PHASE", "CHECK", "STATE", "ERROR"}
LINE = re.compile(rb"SWCOMPAT_SERVICE_([A-Z_]+)=([A-Z0-9]+)\Z")


def _env(prefix: Path) -> dict[str, str]:
    env = os.environ.copy()
    env.pop("WINEDLLOVERRIDES", None)
    env.update({"WINEPREFIX": str(prefix), "WINEARCH": "win64",
                "WINEDEBUG": "-all"})
    return env


def validate_media(msi: Path, manifest: Path, executable: Path) -> None:
    if any(x.is_symlink() or not x.is_file() for x in (msi, manifest, executable)):
        raise ValueError("Use only real original self-authored MSI and service fixture files")
    if msi.name.casefold() != MSI_NAME or executable.name.casefold() != EXE_NAME:
        raise ValueError("Unexpected self-authored fixture filenames")
    if not 1024 <= msi.stat().st_size <= 20 * 1024 * 1024:
        raise ValueError("Invalid MSI size")
    if not 2048 <= executable.stat().st_size <= 5 * 1024 * 1024:
        raise ValueError("Invalid Win32 service fixture size")
    expected = manifest.read_text(encoding="ascii").strip().lower()
    if len(expected) != 64 or any(c not in "0123456789abcdef" for c in expected):
        raise ValueError("Invalid SHA256 manifest")
    hasher = hashlib.sha256()
    with msi.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(chunk)
    if hasher.hexdigest() != expected:
        raise ValueError("Self-authored MSI checksum differs")


def installed_binary(prefix: Path) -> Path:
    validate_prefix(prefix)
    path = prefix / "drive_c" / "Program Files" / "SWCompatMsiServiceAction"
    if path.is_symlink():
        raise ValueError("Linked original MSI install directory")
    return path / EXE_NAME


def binary_state(prefix: Path, executable: Path) -> str:
    target = installed_binary(prefix)
    if target.is_symlink():
        return "LINKED"
    if not target.exists():
        return "ABSENT"
    if not target.is_file():
        return "CHANGED"
    try:
        return ("PRESENT_MATCH" if target.read_bytes() == executable.read_bytes()
                else "CHANGED")
    except OSError:
        return "IO_ERROR"


def service_result(raw: bytes, code: int, mode: str) -> str:
    if code not in (0, 1) or len(raw) > 2048 or b"\0" in raw:
        return "UNKNOWN"
    pairs: dict[str, str] = {}
    for line in raw.splitlines():
        if not line.startswith(b"SWCOMPAT_SERVICE_"):
            continue
        match = LINE.fullmatch(line.strip())
        if not match:
            return "UNKNOWN"
        name = match.group(1).decode("ascii")
        value = match.group(2).decode("ascii")
        if name in MARKERS:
            if name in pairs:
                return "UNKNOWN"
            pairs[name] = value
    if set(pairs) != MARKERS or pairs["PHASE"].lower() != mode:
        return "UNKNOWN"
    if mode == "absent":
        return "ABSENT" if code == 0 and pairs["CHECK"] == "PASS" and pairs["ERROR"] == "1060" else "UNKNOWN"
    if mode != "status":
        return "UNKNOWN"
    if code == 0 and pairs["CHECK"] == "PASS":
        return {"4": "RUNNING", "1": "STOPPED"}.get(pairs["STATE"], "OTHER")
    return {"1060": "ABSENT", "1055": "LOCKED", "1053": "START_TIMEOUT"}.get(
        pairs["ERROR"], "OTHER"
    )


def query_service(wine: Path, prefix: Path, exe: Path, mode: str) -> str:
    if mode not in {"absent", "status"}:
        raise ValueError("Invalid original service query mode")
    with tempfile.TemporaryFile() as output:
        try:
            proc = subprocess.run(
                [str(wine), str(exe), mode], cwd=exe.parent,
                env=_env(prefix), stdin=subprocess.DEVNULL,
                stdout=output, stderr=subprocess.DEVNULL,
                timeout=25, check=False,
            )
        except (subprocess.TimeoutExpired, OSError):
            return "UNKNOWN"
        output.seek(0)
        data = output.read(2049)
    return service_result(data, proc.returncode, mode)


def launch_msi(wine: Path, prefix: Path, msi: Path, timeout: int) -> tuple[str, int | None]:
    windowspath = windows_media_path(wine, prefix, msi)
    try:
        result = subprocess.run(
            [str(wine), "msiexec.exe", "/i", windowspath, "/qn", "/norestart"],
            cwd=prefix, env=_env(prefix), stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=timeout, check=False,
        )
    except subprocess.TimeoutExpired:
        return "TIMEOUT", None
    except OSError:
        return "START_FAILED", None
    return ("ZERO" if result.returncode == 0 else "NONZERO",
            result.returncode if -255 <= result.returncode <= 255 else None)


def inspect(wine: Path, prefix: Path, msi: Path, manifest: Path,
            exe: Path, timeout: int = 150) -> dict:
    if os.name == "nt" or any(x.is_symlink() for x in (wine, prefix, msi, manifest, exe)):
        raise ValueError("Only unlinked original disposable Wine prefixes")
    wine, prefix, msi, manifest, exe = (
        x.resolve(strict=True) for x in (wine, prefix, msi, manifest, exe))
    validate_prefix(prefix)
    if not wine.is_file() or not os.access(wine, os.X_OK):
        raise ValueError("Missing Wine executable")
    validate_media(msi, manifest, exe)
    before = query_service(wine, prefix, exe, "absent")
    file_before = binary_state(prefix, exe)
    report = {
        "schema": 1, "scope": SCOPE, "status": "MEASURED",
        "winver": "NOT_RUN", "service_before": before,
        "binary_before": file_before, "msi_process": "NOT_RUN",
        "unix_exit": None, "binary_after": file_before,
        "service_after": "UNKNOWN", "msi_service_start_candidate": False,
        "dotnet_compatibility": False,
        "solidworks_compatibility": "NOT_DEMONSTRATED",
    }
    if before != "ABSENT" or file_before != "ABSENT":
        report["status"] = "ALREADY_PRESENT"
        return report
    report["winver"] = set_legacy_winver(wine, prefix)
    if report["winver"] != "APPLIED":
        report["status"] = "WINVER_FAILED"
        return report
    report["msi_process"], report["unix_exit"] = launch_msi(
        wine, prefix, msi, timeout)
    report["binary_after"] = binary_state(prefix, exe)
    report["service_after"] = query_service(wine, prefix, exe, "status")
    report["msi_service_start_candidate"] = (
        report["msi_process"] == "ZERO"
        and report["binary_after"] == "PRESENT_MATCH"
        and report["service_after"] == "RUNNING"
    )
    return report


def validate(r: dict) -> bool:
    if type(r) is not dict or set(r) != {
        "schema", "scope", "status", "winver", "service_before",
        "binary_before", "msi_process", "unix_exit", "binary_after",
        "service_after", "msi_service_start_candidate",
        "dotnet_compatibility", "solidworks_compatibility"
    }:
        return False
    if (type(r["schema"]) is not int or r["schema"] != 1
            or r["scope"] != SCOPE or r["status"] not in RESULT_STATES
            or r["winver"] not in {"NOT_RUN", "APPLIED", "FAILED"}
            or r["service_before"] not in SERVICE_STATES
            or r["service_after"] not in SERVICE_STATES
            or r["binary_before"] not in FILE_STATES
            or r["binary_after"] not in FILE_STATES
            or r["msi_process"] not in PROCESS_STATES
            or not (r["unix_exit"] is None or
                    type(r["unix_exit"]) is int and -255 <= r["unix_exit"] <= 255)
            or type(r["msi_service_start_candidate"]) is not bool
            or r["dotnet_compatibility"] is not False
            or r["solidworks_compatibility"] != "NOT_DEMONSTRATED"):
        return False
    if r["msi_service_start_candidate"]:
        return (r["status"] == "MEASURED" and r["winver"] == "APPLIED"
                and r["service_before"] == "ABSENT"
                and r["binary_before"] == "ABSENT"
                and r["msi_process"] == "ZERO"
                and r["binary_after"] == "PRESENT_MATCH"
                and r["service_after"] == "RUNNING")
    return True


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Original harmless MSI service action on Apple Silicon Wine")
    for name in ("wine", "prefix", "msi", "sha256", "exe", "output"):
        p.add_argument("--" + name, required=True, type=Path)
    p.add_argument("--timeout", type=int, default=150)
    p.add_argument("--agree-disposable-prefix", action="store_true", required=True)
    args = p.parse_args(argv)
    if not 40 <= args.timeout <= 220:
        p.error("Invalid bounded MSI execution timeout")
    try:
        if args.output.is_symlink() or args.output.resolve() in {
            x.resolve() for x in (args.wine, args.prefix, args.msi, args.sha256, args.exe)
        }:
            raise ValueError("Output cannot overwrite an input")
        result = inspect(args.wine, args.prefix, args.msi, args.sha256,
                         args.exe, args.timeout)
        if not validate(result):
            raise ValueError("Invalid MSI service action report")
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="ascii")
    except (OSError, ValueError):
        p.error("Unsafe or invalid original disposable MSI service experiment")
    for key in ("status", "winver", "service_before", "binary_before",
                "msi_process", "binary_after", "service_after",
                "msi_service_start_candidate"):
        print("Original MSI service action", key, result[key])
    print("Genuine .NET and SOLIDWORKS compatibility: NOT DEMONSTRATED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
