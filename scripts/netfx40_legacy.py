"""Run original Microsoft .NET Framework 4.0 through the legacy Winetricks path.

The setup media is hash-pinned and Authenticode-checked on a Windows CI runner,
then used only in a newly initialized marked Wine prefix. Unlike Winetricks,
this experiment never adds fictitious CLR installation registry values. No
vendor executable, setup text, path or Wine output enters the public report.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

from scripts.netfx481_trial import (
    NETFX_FULL_KEY, NETFX_WOW6432_FULL_KEY, probe, validate_prefix,
    wineboot_restart,
)
from scripts.netfx48_baseline import clear_unbacked_release
from scripts.netfx481_payload_audit import snapshot, STATES
from scripts.netfx481_clr_load import run as clr_load, STATUSES as LOAD_STATES
from scripts.netfx481_win32_exit import (
    parse as parse_win32, CATEGORIES, CHILD_VALUES, LIFECYCLE_VALUES, EXIT_VALUES,
)
from scripts.wine_mono_removal import inventory, remove_mono
from swcompat.wine_paths import windows_media_path

INSTALLER_NAME = "dotnetfx40_full_x86_x64.exe"
LAUNCHER_NAME = "netfx40_win32_launch.exe"
# SHA256 of the original Microsoft standalone EXE, independently pinned
# by Winetricks. Also checked for valid Microsoft Authenticode on Windows.
OFFICIAL_SHA256 = "65e064258f2e418816b304f646ff9e87af101e4c9552ab064bb74d281c38659f"
STAGES = {"MEASURED", "ALREADY_NATIVE", "BLOCKED_WINVER", "BLOCKED_REGISTRY",
          "BLOCKED_MONO_REMOVAL", "BLOCKED_WIN32_SELFTEST", "BLOCKED_MEDIA"}
STATES_START = {"NOT_RUN", "EXIT_CAPTURED", "START_FAILED", "TIMEOUT", "BAD_REPORT",
                "INVALID_ARGUMENT", "WAIT_FAILED", "PROCESS_FAILED"}
MONO_STATES = {"NOT_RUN", "REMOVED", "MONO_NOT_REGISTERED", "INVENTORY_FAILED",
               "REMOVE_FAILED", "VERIFY_FAILED"}
SELF_STATES = {"NOT_RUN", "PASS", "NO_OUTPUT", "BAD_REPORT", "PROCESS_FAILED", "TIMEOUT"}
REG_STATES = {"NOT_RUN", "NOT_NEEDED", "CLEARED", "QUERY_FAILED", "DELETE_FAILED", "VERIFY_FAILED"}


def verify_media(installer: Path) -> None:
    if (installer.is_symlink() or not installer.is_file()
            or installer.name.casefold() != INSTALLER_NAME
            or not 35 * 1024 * 1024 <= installer.stat().st_size <= 70 * 1024 * 1024):
        raise ValueError("Unexpected original .NET 4.0 media")
    digest = hashlib.sha256()
    with installer.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    if digest.hexdigest() != OFFICIAL_SHA256:
        raise ValueError("Original Microsoft .NET 4.0 SHA256 mismatch")


def _env(prefix: Path, *, installation: bool = False) -> dict[str, str]:
    env = os.environ.copy()
    env.pop("WINEDLLOVERRIDES", None)
    env.update({"WINEPREFIX": str(prefix), "WINEARCH": "win64", "WINEDEBUG": "-all"})
    if installation:
        # Upstream Winetricks load_dotnet40 uses this override only for setup.
        env["WINEDLLOVERRIDES"] = "fusion=b"
    return env


def set_legacy_winver(wine: Path, prefix: Path) -> str:
    validate_prefix(prefix)
    try:
        done = subprocess.run(
            [str(wine), "winecfg.exe", "-v", "winxp"],
            env=_env(prefix), cwd=prefix,
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, timeout=45, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return "FAILED"
    return "APPLIED" if done.returncode == 0 else "FAILED"


def _run(wine: Path, prefix: Path, fixture: Path, arguments: list[str],
         *, setup: bool = False, timeout: int = 75) -> dict:
    validate_prefix(prefix)
    if fixture.is_symlink() or not fixture.is_file() or fixture.name.casefold() != LAUNCHER_NAME:
        raise ValueError("Expected self-authored .NET 4.0 Win32 launcher")
    env = _env(prefix, installation=setup)
    with tempfile.TemporaryFile() as output:
        try:
            result = subprocess.run(
                [str(wine), str(fixture), *arguments], cwd=fixture.parent,
                env=env, stdin=subprocess.DEVNULL, stdout=output,
                stderr=subprocess.DEVNULL, check=False, timeout=timeout,
            )
            code = result.returncode
            failed = None
        except subprocess.TimeoutExpired:
            code, failed = 124, "TIMEOUT"
        except OSError:
            code, failed = 124, "PROCESS_FAILED"
        output.seek(0)
        raw = output.read(4097)
    if failed:
        return {"status": failed, "category": "NOT_AVAILABLE",
                "exit_hex": "NOT_VERIFIED", "child_seen": "NOT_VERIFIED",
                "child_lifecycle": "NOT_VERIFIED", "child_exit": "NOT_VERIFIED"}
    return parse_win32(raw, code)


def inspect(wine: Path, prefix: Path, installer: Path, launcher: Path,
            loader: Path, managed: Path, timeout: int = 210) -> dict:
    if os.name == "nt":
        raise ValueError("Wine experiment cannot modify native Windows")
    if any(p.is_symlink() for p in (wine, prefix, installer, launcher, loader, managed)):
        raise ValueError("Refuse linked experiment media")
    # Prevent relative "build/build/foo.exe" errors from changing cwd.
    wine, prefix, installer, launcher, loader, managed = (
        p.resolve(strict=True) for p in (wine, prefix, installer, launcher, loader, managed)
    )
    validate_prefix(prefix)
    if not wine.is_file() or not os.access(wine, os.X_OK):
        raise ValueError("Wine not executable")
    if launcher.name.casefold() != LAUNCHER_NAME or loader.name.casefold() != "netfx481_clr_load.exe" or managed.name.casefold() != "netfx481_runtime_probe.exe":
        raise ValueError("Unexpected self-authored probes")
    verify_media(installer)
    disk_before = snapshot(prefix)
    report = {
        "schema": 1, "scope": "ORIGINAL_NETFX40_LEGACY_WINE",
        "status": "MEASURED", "winver": "NOT_RUN",
        "registry64": "NOT_RUN", "registry32": "NOT_RUN",
        "mono": "NOT_RUN", "selftest": "NOT_RUN",
        "installer_status": "NOT_RUN", "installer_exit": "NOT_AVAILABLE",
        "installer_exit_hex": "NOT_VERIFIED",
        "installer_child_seen": "NOT_VERIFIED",
        "installer_child_lifecycle": "NOT_VERIFIED",
        "installer_child_exit": "NOT_VERIFIED",
        "reboot": "NOT_RUN",
        "clr64_before": disk_before["CLR64"][0],
        "clr64_after": disk_before["CLR64"][0],
        "clr32_before": disk_before["CLR32"][0],
        "clr32_after": disk_before["CLR32"][0],
        "mscorlib64_after": disk_before["MSCORLIB64"][0],
        "native_loader": "NOT_REQUESTED",
        "runtime_family": "NOT_VERIFIED", "managed_functionality": "NOT_VERIFIED",
        "candidate_native40": False, "netfx481_ready": False,
        "solidworks_compatibility": "NOT_DEMONSTRATED",
    }
    if disk_before["CLR64"][0] != "ABSENT":
        report["status"] = "ALREADY_NATIVE"
        return report
    report["winver"] = set_legacy_winver(wine, prefix)
    if report["winver"] != "APPLIED":
        report["status"] = "BLOCKED_WINVER"
        return report
    for key, field in ((NETFX_FULL_KEY, "registry64"),
                       (NETFX_WOW6432_FULL_KEY, "registry32")):
        state = clear_unbacked_release(wine, prefix, key)
        report[field] = state
        if state not in {"CLEARED", "NOT_NEEDED"}:
            report["status"] = "BLOCKED_REGISTRY"
            return report
    try:
        products = inventory(wine, prefix)
    except ValueError:
        report["mono"] = "INVENTORY_FAILED"
        report["status"] = "BLOCKED_MONO_REMOVAL"
        return report
    if products:
        cleanup = remove_mono(wine, prefix, {"clr_family": "MONO"})
        report["mono"] = cleanup["action"]
        if report["mono"] != "REMOVED":
            report["status"] = "BLOCKED_MONO_REMOVAL"
            return report
    else:
        report["mono"] = "MONO_NOT_REGISTERED"
    pre = _run(wine, prefix, launcher, ["--selftest-3010"], timeout=65)
    report["selftest"] = ("PASS" if pre["status"] == "EXIT_CAPTURED"
                          and pre["exit_hex"] == "00000BC2" else
                          "NO_OUTPUT" if pre["status"] == "BAD_REPORT" else
                          pre["status"] if pre["status"] in SELF_STATES else "BAD_REPORT")
    if report["selftest"] != "PASS":
        report["status"] = "BLOCKED_WIN32_SELFTEST"
        return report
    windows_path = windows_media_path(wine, prefix, installer)
    installed = _run(wine, prefix, launcher, [windows_path],
                     setup=True, timeout=min(timeout + 40, 390))
    report["installer_status"] = installed["status"]
    report["installer_exit"] = installed["category"]
    report["installer_exit_hex"] = installed["exit_hex"]
    report["installer_child_seen"] = installed.get("child_seen", "NOT_VERIFIED")
    report["installer_child_lifecycle"] = installed.get("child_lifecycle", "NOT_VERIFIED")
    report["installer_child_exit"] = installed.get("child_exit", "NOT_VERIFIED")
    if installed["status"] == "EXIT_CAPTURED" and installed["category"] == "REBOOT_REQUIRED":
        report["reboot"] = wineboot_restart(wine, prefix)
    else:
        report["reboot"] = "NOT_NEEDED"

    disk_after = snapshot(prefix)
    after = probe(wine, prefix, managed)
    report.update({
        "clr64_after": disk_after["CLR64"][0],
        "clr32_after": disk_after["CLR32"][0],
        "mscorlib64_after": disk_after["MSCORLIB64"][0],
        "native_loader": clr_load(wine, prefix, loader),
        "runtime_family": after["clr_family"],
        "managed_functionality": after["managed"],
    })
    report["candidate_native40"] = (
        disk_before["CLR64"][0] == "ABSENT"
        and disk_after["CLR64"][0] == "PE_AMD64"
        and disk_after["MSCORLIB64"][0] == "PE_AMD64"
        and report["native_loader"] == "LOADED"
        and report["runtime_family"] == "MICROSOFT_CLR_CANDIDATE"
        and report["managed_functionality"] == "PASS"
        and installed["status"] == "EXIT_CAPTURED"
        and installed["category"] in {"SUCCESS", "REBOOT_REQUIRED"}
        and report["reboot"] in {"NOT_NEEDED", "COMPLETED"}
    )
    return report


def validate(r: dict) -> bool:
    return (
        type(r) is dict
        and set(r) == {"schema", "scope", "status", "winver", "registry64", "registry32",
                       "mono", "selftest", "installer_status", "installer_exit",
                       "installer_exit_hex", "installer_child_seen",
                       "installer_child_lifecycle", "installer_child_exit",
                       "reboot", "clr64_before", "clr64_after",
                       "clr32_before", "clr32_after", "mscorlib64_after",
                       "native_loader", "runtime_family", "managed_functionality",
                       "candidate_native40", "netfx481_ready", "solidworks_compatibility"}
        and r["schema"] == 1 and r["scope"] == "ORIGINAL_NETFX40_LEGACY_WINE"
        and r["status"] in STAGES
        and r["winver"] in {"NOT_RUN", "APPLIED", "FAILED"}
        and r["registry64"] in REG_STATES and r["registry32"] in REG_STATES
        and r["mono"] in MONO_STATES and r["selftest"] in SELF_STATES
        and r["installer_status"] in STATES_START
        and r["installer_exit"] in (CATEGORIES | {"NOT_AVAILABLE"})
        and r["installer_child_seen"] in CHILD_VALUES
        and r["installer_child_lifecycle"] in LIFECYCLE_VALUES
        and r["installer_child_exit"] in EXIT_VALUES
        and (r["installer_status"] != "EXIT_CAPTURED" or
             ((r["installer_child_seen"] == "OBSERVED" and
               r["installer_child_lifecycle"] in {"ALL_EXITED", "PARTIAL", "STILL_ACTIVE"})
              or (r["installer_child_seen"] == "NOT_OBSERVED" and
                  r["installer_child_lifecycle"] == "NOT_OBSERVED")
              or (r["installer_child_seen"] == "UNKNOWN" and
                  r["installer_child_lifecycle"] == "UNKNOWN")))
        and (r["installer_child_lifecycle"] != "ALL_EXITED" or
             r["installer_child_exit"] in {"ALL_ZERO", "NONZERO", "REBOOT_REQUIRED"})
        and (r["installer_child_lifecycle"] == "ALL_EXITED" or
             r["installer_child_exit"] == "NOT_VERIFIED")
        and type(r["installer_exit_hex"]) is str
        and (r["installer_exit_hex"] == "NOT_VERIFIED" or
             (len(r["installer_exit_hex"]) == 8 and all(c in "0123456789ABCDEF"
                                                      for c in r["installer_exit_hex"])))
        and r["reboot"] in {"NOT_RUN", "NOT_NEEDED", "COMPLETED", "TIMED_OUT", "START_FAILED", "EXIT_NONZERO"}
        and all(r[k] in STATES for k in ("clr64_before", "clr64_after", "clr32_before",
                                         "clr32_after", "mscorlib64_after"))
        and r["native_loader"] in LOAD_STATES
        and r["runtime_family"] in {"NOT_VERIFIED", "MONO", "MICROSOFT_CLR_CANDIDATE", "UNKNOWN"}
        and r["managed_functionality"] in {"NOT_VERIFIED", "PASS", "FAIL"}
        and type(r["candidate_native40"]) is bool
        and r["netfx481_ready"] is False
        and r["solidworks_compatibility"] == "NOT_DEMONSTRATED"
    )


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Original Microsoft .NET 4.0 legacy Winetricks-style native CLR test")
    for key in ("wine", "prefix", "installer", "launcher", "loader", "managed", "output"):
        p.add_argument("--" + key, required=True, type=Path)
    p.add_argument("--timeout", type=int, default=210)
    p.add_argument("--agree-disposable-prefix", action="store_true", required=True)
    args = p.parse_args(argv)
    if not 60 <= args.timeout <= 360:
        p.error("Invalid bounded runtime")
    try:
        if args.output.is_symlink() or args.output.resolve() in {
            x.resolve() for x in (args.wine, args.prefix, args.installer, args.launcher,
                                  args.loader, args.managed)
        }:
            raise ValueError("Output cannot overwrite experiment")
        report = inspect(args.wine, args.prefix, args.installer, args.launcher,
                         args.loader, args.managed, args.timeout)
        if not validate(report):
            raise ValueError("Privacy-safe report invalid")
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="ascii")
    except (ValueError, OSError):
        p.error("Original signed Microsoft .NET 4.0 disposable-prefix experiment refused")
    for key in ("status", "winver", "mono", "selftest", "installer_status",
                "installer_exit", "installer_child_seen",
                "installer_child_lifecycle", "installer_child_exit",
                "reboot", "clr64_before", "clr64_after",
                "clr32_after", "mscorlib64_after", "native_loader",
                "runtime_family", "managed_functionality", "candidate_native40"):
        print("Native .NET 4.0", key, report[key])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
