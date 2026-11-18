"""Isolated signed Microsoft .NET 4.8 x64 MSI+MSP control after bootstrapper 5100.

This experiment bypasses the *bootstrapper only*, not Microsoft's MSI content.
It is not a supported Windows installation technique. Never assert a working
4.8, 4.8.1, or SOLIDWORKS without genuine on-disk CLR and managed execution.
Original Microsoft media must be authenticated by Windows CI and SHA256-bound.
Never upload vendor binaries, Windows Installer database or private logs.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile

from scripts.netfx40_msxml3_restart import validate as valid_native40
from scripts.netfx40_to_48_direct import verify_original_media
from scripts.netfx40_to_48_intermediate import _env, _release, _set_winver
from scripts.netfx481_clr_load import run as load_clr, STATUSES as LOAD_STATES
from scripts.netfx481_payload_audit import snapshot
from scripts.netfx481_trial import validate_prefix, probe, wineboot_restart

STEPS = {"NOT_RUN", "SUCCESS", "EXIT_NONZERO", "TIMED_OUT", "START_FAILED"}
MEDIA = {"NOT_RUN", "VERIFIED", "FILES_MISSING", "UNSAFE", "INVALID_PACKAGE"}
WINVER = {"NOT_RUN", "APPLIED", "FAILED"}
RESTART = {"NOT_RUN", "COMPLETED", "EXIT_NONZERO", "START_FAILED", "TIMED_OUT"}
RELEASE = {"UNAVAILABLE", "NOT_FOUND", "BELOW_48", "NETFX48_RANGE", "AT_LEAST_481"}
LOADER = LOAD_STATES | {"NOT_VERIFIED"}
NATIVE = {"NOT_VERIFIED", "PASS", "FAIL"}
TARGET = "swcompat-original-netfx48-msi"
MSI = "netfx_Full_x64.msi"
MSP = "netfx_Patch_x64.msp"
MAX_VENDOR_BYTES = 250 * 1024 * 1024
MIN_MSI_BYTES = 4096
OLE_HEADER = bytes.fromhex("D0 CF 11 E0 A1 B1 1A E1")


def blank() -> dict:
    return {
        "status": "NOT_ELIGIBLE", "native40_persistent": False,
        "win7": "NOT_RUN", "extract": "NOT_RUN", "media": "NOT_RUN",
        "install": "NOT_RUN", "patch": "NOT_RUN",
        "win10": "NOT_RUN", "restart": "NOT_RUN",
        "clr64_changed": False, "release": "UNAVAILABLE",
        "loader": "NOT_VERIFIED", "native_only_managed": "NOT_VERIFIED",
        "native48_candidate": False, "framework481_confirmed": False,
        "solidworks_compatibility": "NOT_DEMONSTRATED",
    }


def validate(result: object) -> bool:
    if type(result) is not dict or set(result) != set(blank()):
        return False
    if (result["status"] not in {"NOT_ELIGIBLE", "MEASURED"}
            or result["win7"] not in WINVER or result["win10"] not in WINVER
            or any(result[k] not in STEPS for k in ("extract", "install", "patch"))
            or result["media"] not in MEDIA or result["restart"] not in RESTART
            or result["release"] not in RELEASE
            or not isinstance(result["loader"], str)
            or result["loader"] not in LOADER
            or result["native_only_managed"] not in NATIVE
            or result["framework481_confirmed"] is not False
            or result["solidworks_compatibility"] != "NOT_DEMONSTRATED"
            or any(type(result[k]) is not bool for k in (
                "native40_persistent", "clr64_changed", "native48_candidate"))):
        return False
    if result["status"] == "NOT_ELIGIBLE":
        return result == blank()
    ready = (
        result["native40_persistent"] and result["win7"] == "APPLIED"
        and result["extract"] == "SUCCESS" and result["media"] == "VERIFIED"
        and result["install"] == "SUCCESS" and result["patch"] == "SUCCESS"
        and result["win10"] == "APPLIED" and result["restart"] == "COMPLETED"
        and result["clr64_changed"] and result["release"] == "NETFX48_RANGE"
        and result["loader"] == "LOADED" and result["native_only_managed"] == "PASS"
    )
    return result["native48_candidate"] is ready


def verify_extracted_media(root: Path) -> str:
    """No arbitrary MSI paths, symlinks, filenames or external MSPs."""
    if root.is_symlink():
        return "UNSAFE"
    if not root.is_dir():
        return "FILES_MISSING"
    for filename in (MSI, MSP):
        file = root / filename
        if file.is_symlink():
            return "UNSAFE"
        if not file.is_file():
            return "FILES_MISSING"
        try:
            size = file.stat().st_size
            with file.open("rb") as stream:
                magic = stream.read(8)
        except OSError:
            return "UNSAFE"
        if not MIN_MSI_BYTES <= size <= MAX_VENDOR_BYTES or magic != OLE_HEADER:
            return "INVALID_PACKAGE"
    return "VERIFIED"


def private_run(args: list[str], env: dict[str, str], cwd: Path,
                timeout: int) -> str:
    """No untrusted installer bytes, paths, exit text or original stdout in CI."""
    with tempfile.TemporaryFile() as sink:
        try:
            child = subprocess.run(
                args, env=env, cwd=cwd, stdin=subprocess.DEVNULL,
                stdout=sink, stderr=sink, timeout=timeout, check=False,
            )
        except subprocess.TimeoutExpired:
            return "TIMED_OUT"
        except OSError:
            return "START_FAILED"
    return "SUCCESS" if child.returncode == 0 else "EXIT_NONZERO"


def inspect(wine: Path, prefix: Path, installer: Path, digest: Path,
            loader: Path, managed: Path, native40: dict) -> dict:
    if os.name == "nt" or any(p.is_symlink() for p in (
            wine, prefix, installer, digest, loader, managed)):
        raise ValueError("Only isolated native Microsoft 4.0 Wine tests permitted")
    wine, prefix, installer, digest, loader, managed = (
        p.resolve(strict=True) for p in
        (wine, prefix, installer, digest, loader, managed)
    )
    validate_prefix(prefix)
    verify_original_media(installer, digest)
    if (loader.name != "netfx481_clr_load.exe"
            or managed.name != "netfx481_runtime_probe.exe"
            or not wine.is_file() or not os.access(wine, os.X_OK)):
        raise ValueError("Unrecognized signed original Microsoft installer fixture")
    if not valid_native40(native40) or not native40["persistent_native_managed"]:
        return blank()
    before = snapshot(prefix)
    initial = probe(wine, prefix, managed, override="native_only")
    if (before["CLR64"][0] != "PE_AMD64"
            or load_clr(wine, prefix, loader) != "LOADED"
            or initial["clr_family"] != "MICROSOFT_CLR_CANDIDATE"
            or initial["managed"] != "PASS"):
        return blank()

    root = prefix / "drive_c" / TARGET
    if root.is_symlink() or root.exists():
        raise ValueError("Original signed MSI extraction must start with empty directory")
    env = _env(wine, prefix)
    win7 = _set_winver(wine, prefix, env, "win7")
    extracted, media, installed, patched = ("NOT_RUN", "NOT_RUN", "NOT_RUN", "NOT_RUN")
    restart = "NOT_RUN"
    try:
        if win7 == "APPLIED":
            # /x extracts the *unmodified* official Microsoft's original MSI
            # and MSP to the dedicated disposable C: directory.
            extracted = private_run(
                [str(wine), str(installer), "/x:C:\\" + TARGET, "/q"],
                env, prefix, 150,
            )
            if extracted == "SUCCESS":
                media = verify_extracted_media(root)
            if media == "VERIFIED":
                installed = private_run(
                    [str(wine), "msiexec.exe", "/i",
                     "C:\\" + TARGET + "\\" + MSI, "/qn", "/norestart"],
                    env, prefix, 420,
                )
                if installed == "SUCCESS":
                    patched = private_run(
                        [str(wine), "msiexec.exe", "/p",
                         "C:\\" + TARGET + "\\" + MSP,
                         "/qn", "/norestart", "EXTUI=1"],
                        env, prefix, 420,
                    )
    finally:
        win10 = _set_winver(wine, prefix, env, "win10")
    if installed == "SUCCESS" and patched == "SUCCESS" and win10 == "APPLIED":
        restart = wineboot_restart(wine, prefix, timeout=90)

    after = snapshot(prefix)
    current = probe(wine, prefix, managed, override="native_only")
    result = {
        "status": "MEASURED", "native40_persistent": True,
        "win7": win7, "extract": extracted, "media": media,
        "install": installed, "patch": patched,
        "win10": win10, "restart": restart,
        "clr64_changed": (before["CLR64"][1] != after["CLR64"][1]
                          and after["CLR64"][0] == "PE_AMD64"),
        "release": _release(wine, prefix, env),
        "loader": load_clr(wine, prefix, loader),
        "native_only_managed": current["managed"],
        "native48_candidate": False, "framework481_confirmed": False,
        "solidworks_compatibility": "NOT_DEMONSTRATED",
    }
    result["native48_candidate"] = (
        result["native40_persistent"] and result["win7"] == "APPLIED"
        and result["extract"] == "SUCCESS" and result["media"] == "VERIFIED"
        and result["install"] == "SUCCESS" and result["patch"] == "SUCCESS"
        and result["win10"] == "APPLIED" and result["restart"] == "COMPLETED"
        and result["clr64_changed"] and result["release"] == "NETFX48_RANGE"
        and result["loader"] == "LOADED" and result["native_only_managed"] == "PASS"
    )
    if not validate(result):
        raise ValueError("Unverifiable original Microsoft .NET 4.8 MSI result")
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Original signed 4.8 x64 MSI isolation experiment")
    for key in ("wine", "prefix", "installer", "sha256-file", "loader",
                "managed", "native40-report", "output"):
        parser.add_argument("--" + key, required=True, type=Path)
    parser.add_argument("--agree-disposable-prefix", action="store_true", required=True)
    a = parser.parse_args(argv)
    result = inspect(a.wine, a.prefix, a.installer, a.sha256_file,
                     a.loader, a.managed,
                     json.loads(a.native40_report.read_text(encoding="utf-8")))
    if a.output.is_symlink():
        raise ValueError("Linked experiment report")
    a.output.parent.mkdir(parents=True, exist_ok=True)
    a.output.write_text(json.dumps(result, sort_keys=True), encoding="ascii")
    for key, value in result.items():
        print("Original .NET 4.8 signed MSI experiment", key, value)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
