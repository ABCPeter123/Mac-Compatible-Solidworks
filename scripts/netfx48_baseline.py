"""Isolate a genuine Microsoft .NET Framework 4.8 CLR baseline on Apple Silicon Wine.

The native 4.8 experiment does not claim .NET 4.8.1 compatibility. The
Microsoft redistributable is downloaded and Authenticode checked separately
on a disposable Windows CI worker; only the original signed installer and
its SHA256 manifest reach this disposable macOS Wine prefix.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path

from scripts.netfx481_trial import (
    NETFX_FULL_KEY, NETFX_WOW6432_FULL_KEY, probe, reg_code,
    run_installer, validate_prefix, wineboot_restart,
)
from scripts.netfx481_clr_load import run as load_clr
from scripts.netfx481_payload_audit import snapshot
from scripts.wine_mono_removal import inventory, remove_mono
from scripts.netfx481_win32_exit import VALID_STATUSES as WIN32_STATUSES, CATEGORIES as WIN32_CATEGORIES
from scripts.netfx481_setup_evidence import KNOWN_RESULTS, KNOWN_PHASES, KNOWN_CODES
from scripts.netfx48_win32_exit import SELFTEST_STATES

INSTALLER_NAME = "ndp48-x86-x64-allos-enu.exe"
PROBE_NAME = "netfx481_runtime_probe.exe"
LOADER_NAME = "netfx481_clr_load.exe"
SHA_LENGTH = 64
STATUSES = {"MEASURED", "BLOCKED_MONO_REMOVAL", "BLOCKED_REGISTRY", "ALREADY_NATIVE", "BLOCKED_LAUNCHER"}
UNIX_OUTCOMES = {"ZERO", "POSSIBLE_3010_UNIX_194", "CONFIRMED_3010", "OTHER", "NOT_RUN"}
REBOOT_OUTCOMES = {"NOT_NEEDED", "COMPLETED", "TIMED_OUT", "START_FAILED", "EXIT_NONZERO", "NOT_RUN"}


def verify_official_media(installer: Path, manifest: Path) -> None:
    if (installer.is_symlink() or manifest.is_symlink()
            or not installer.is_file()
            or installer.name.casefold() != INSTALLER_NAME):
        raise ValueError("Expected original .NET 4.8 offline redistributable")
    if not 15 * 1024 * 1024 <= installer.stat().st_size <= 250 * 1024 * 1024:
        raise ValueError("Microsoft redistributable size out of allowed range")
    expected = manifest.read_text(encoding="ascii").strip().lower()
    if len(expected) != SHA_LENGTH or any(x not in "0123456789abcdef" for x in expected):
        raise ValueError("Invalid digest manifest")
    digest = hashlib.sha256()
    with installer.open("rb") as src:
        for block in iter(lambda: src.read(1024 * 1024), b""):
            digest.update(block)
    if digest.hexdigest() != expected:
        raise ValueError("Original installer digest mismatch")


def clear_unbacked_release(wine: Path, prefix: Path, key: str) -> str:
    """Clear only a Release value lacking a native CLR in the marked fresh prefix.

    Caller must first establish Framework64 clr.dll is absent. A fabricated
    Wine Mono Release entry otherwise causes the official setup to short-circuit.
    Do not delete parent registry keys or touch established user prefixes.
    """
    validate_prefix(prefix)
    if key not in {NETFX_FULL_KEY, NETFX_WOW6432_FULL_KEY}:
        raise ValueError("Unexpected registry key")
    state = reg_code(wine, prefix, "query", key, "/v", "Release")
    if state == 1:
        return "NOT_NEEDED"
    if state != 0:
        return "QUERY_FAILED"
    if reg_code(wine, prefix, "delete", key, "/v", "Release", "/f") != 0:
        return "DELETE_FAILED"
    return ("CLEARED" if reg_code(wine, prefix, "query", key, "/v", "Release") == 1
            else "VERIFY_FAILED")


def native_48_candidate(before: dict, after: dict, first: str, last: str,
                        loader: str, outcome: str, reboot: str) -> bool:
    """A candidate requires all independent CLR signals, not just a registry key."""
    return (
        before.get("CLR64") == "ABSENT"
        and first == "CREATED"
        and last == "PE_AMD64"
        and loader == "LOADED"
        and after.get("clr_family") == "MICROSOFT_CLR_CANDIDATE"
        and after.get("managed") == "PASS"
        and after.get("registry") == "BELOW_481"
        and (outcome == "ZERO" or
             (outcome in {"POSSIBLE_3010_UNIX_194", "CONFIRMED_3010"} and reboot == "COMPLETED"))
    )


def inspect(wine: Path, prefix: Path, installer: Path, manifest: Path,
            fixture: Path, loader: Path, timeout: int = 210,
            win32_launcher: Path | None = None) -> dict:
    if os.name == "nt":
        raise ValueError("Wine experiment may not modify native Windows")
    for path in (wine, prefix, installer, manifest, fixture, loader,
                 *([win32_launcher] if win32_launcher is not None else [])):
        if path.is_symlink():
            raise ValueError("Symlinked experiment input")
    validate_prefix(prefix)
    if not wine.is_file() or not os.access(wine, os.X_OK):
        raise ValueError("Wine executable unavailable")
    if not fixture.is_file() or fixture.name.casefold() != PROBE_NAME:
        raise ValueError("Unexpected managed fixture")
    if not loader.is_file() or loader.name.casefold() != LOADER_NAME:
        raise ValueError("Unexpected Win32 loader fixture")
    if win32_launcher is not None and (not win32_launcher.is_file()
                                      or win32_launcher.name.casefold() != "netfx48_win32_launch.exe"):
        raise ValueError("Unexpected netfx48 Win32 launcher")
    verify_official_media(installer, manifest)
    before = probe(wine, prefix, fixture)
    before_disk = snapshot(prefix)
    report = {
        "schema": 1, "scope": "ORIGINAL_NETFX48_DISPOSABLE_WINE_BASELINE",
        "status": "MEASURED",
        "before_family": before["clr_family"],
        "registry64_adjustment": "NOT_APPLICABLE",
        "registry32_adjustment": "NOT_APPLICABLE",
        "mono_removal": "NOT_APPLICABLE",
        "installer_execution": "NOT_RUN",
        "unix_exit_category": "NOT_RUN",
        "win32_selftest_before": "NOT_REQUESTED",
        "win32_selftest_after": "NOT_REQUESTED",
        "win32_original_status": "NOT_REQUESTED",
        "win32_original_exit": "NOT_AVAILABLE",
        "setup_log_status": "NOT_REQUESTED",
        "setup_log_phase": "UNKNOWN",
        "setup_error_categories": [],
        "wine_restart": "NOT_RUN",
        "clr64_before": before_disk["CLR64"][0],
        "clr64_after": before_disk["CLR64"][0],
        "clr64_change": "UNVERIFIED",
        "clr_loader": "NOT_REQUESTED",
        "managed_identity": "NOT_VERIFIED",
        "managed_functionality": "NOT_VERIFIED",
        "registry_indicator": "NOT_VERIFIED",
        "native_48_candidate": False,
        "netfx481_ready": False,
        "solidworks_compatibility": "NOT_DEMONSTRATED",
    }
    if win32_launcher is not None:
        from scripts.netfx48_win32_exit import selftest as launcher_selftest
        report["win32_selftest_before"] = launcher_selftest(wine, prefix, win32_launcher)
    # The managed fixture can be NOT_VERIFIED before .NET exists. That is
    # exactly when a clean CLR install is needed, not a reason to skip setup.
    # Refuse changes when an installed native CLR file already exists.
    if before_disk["CLR64"][0] != "ABSENT":
        report["status"] = "ALREADY_NATIVE"
        return report
    # Only a newly initialized, marked prefix with no CLR file can have these
    # two unsupported Wine Mono Release indicators removed.
    adjust64 = clear_unbacked_release(wine, prefix, NETFX_FULL_KEY)
    report["registry64_adjustment"] = adjust64
    if adjust64 in {"QUERY_FAILED", "DELETE_FAILED", "VERIFY_FAILED"}:
        report["status"] = "BLOCKED_REGISTRY"
        return report
    adjust32 = clear_unbacked_release(wine, prefix, NETFX_WOW6432_FULL_KEY)
    report["registry32_adjustment"] = adjust32
    if adjust32 in {"QUERY_FAILED", "DELETE_FAILED", "VERIFY_FAILED"}:
        report["status"] = "BLOCKED_REGISTRY"
        return report
    # Wine Mono may be MSI-registered even when no managed fixture can run.
    # Trust its exact registered MSI product inventory instead of assuming a
    # failed managed probe implies no Mono installation.
    try:
        mono_products = inventory(wine, prefix)
    except ValueError:
        report["mono_removal"] = "INVENTORY_FAILED"
        report["status"] = "BLOCKED_MONO_REMOVAL"
        return report
    if mono_products:
        removal = remove_mono(wine, prefix, {"clr_family": "MONO"})
        report["mono_removal"] = removal["action"]
        if removal["action"] != "REMOVED":
            report["status"] = "BLOCKED_MONO_REMOVAL"
            return report
    else:
        report["mono_removal"] = "MONO_NOT_REGISTERED"

    if win32_launcher is not None:
        from scripts.netfx48_win32_exit import (
            launch as launch_native, selftest as launcher_selftest,
        )
        report["win32_selftest_after"] = launcher_selftest(wine, prefix, win32_launcher)
        if report["win32_selftest_after"] != "PASS":
            report["status"] = "BLOCKED_LAUNCHER"
            return report
        from scripts.netfx481_win32_exit import termination as native_termination
        from scripts.netfx481_setup_evidence import classify_log, discard_log
        private_dir = prefix / "drive_c" / "swcompat-netfx48-private"
        private_log = private_dir / "framework-setup.txt"
        if private_dir.is_symlink() or private_log.is_symlink() or private_log.exists():
            raise ValueError("Private .NET 4.8 setup log path already occupied")
        private_dir.mkdir(mode=0o700, exist_ok=True)
        try:
            original = launch_native(wine, prefix, installer, win32_launcher,
                                     timeout=min(timeout + 30, 390))
            status, code = native_termination(original)
            setup_log = classify_log(private_log)
        finally:
            discard_log(private_log)
        report["win32_original_status"] = original["status"]
        report["win32_original_exit"] = original["category"]
        report["setup_log_status"] = setup_log["status"]
        report["setup_log_phase"] = setup_log["phase"]
        report["setup_error_categories"] = setup_log["codes"]
        outcome = ("ZERO" if code == 0 and status == "EXIT_ZERO" else
                   "CONFIRMED_3010" if code == 3010 else "OTHER")
    else:
        status, code = run_installer(wine, prefix, installer, timeout)
        outcome = ("ZERO" if status == "EXIT_ZERO" else
                   "POSSIBLE_3010_UNIX_194" if status == "EXIT_NONZERO" and code == 194
                   else "OTHER")
    report["installer_execution"] = status
    report["unix_exit_category"] = outcome
    reboot = (wineboot_restart(wine, prefix) if outcome in {
        "POSSIBLE_3010_UNIX_194", "CONFIRMED_3010"
    } else "NOT_NEEDED")
    report["wine_restart"] = reboot

    after_disk = snapshot(prefix)
    from scripts.netfx481_payload_audit import compare
    comparison = compare(before_disk, after_disk)
    after = probe(wine, prefix, fixture)
    report.update({
        "clr64_after": comparison["after"]["CLR64"],
        "clr64_change": comparison["changes"]["CLR64"],
        "clr_loader": load_clr(wine, prefix, loader),
        "managed_identity": after["clr_family"],
        "managed_functionality": after["managed"],
        "registry_indicator": after["registry"],
    })
    report["native_48_candidate"] = native_48_candidate(
        comparison["before"], after, comparison["changes"]["CLR64"],
        comparison["after"]["CLR64"], report["clr_loader"], outcome, reboot)
    # .NET 4.8 cannot satisfy the .NET 4.8.1 SOLIDWORKS prerequisite.
    return report


def validate(report: dict) -> bool:
    from scripts.netfx481_payload_audit import STATES, CHANGES
    from scripts.netfx481_clr_load import STATUSES as LOAD_STATES
    return (
        type(report) is dict
        and set(report) == {
            "schema", "scope", "status", "before_family",
            "registry64_adjustment", "registry32_adjustment", "mono_removal",
            "installer_execution", "unix_exit_category",
            "win32_selftest_before", "win32_selftest_after",
            "win32_original_status", "win32_original_exit",
            "setup_log_status", "setup_log_phase", "setup_error_categories",
            "wine_restart",
            "clr64_before", "clr64_after", "clr64_change", "clr_loader",
            "managed_identity", "managed_functionality", "registry_indicator",
            "native_48_candidate", "netfx481_ready", "solidworks_compatibility",
        }
        and report["schema"] == 1
        and report["scope"] == "ORIGINAL_NETFX48_DISPOSABLE_WINE_BASELINE"
        and report["status"] in STATUSES
        and report["before_family"] in {"MONO", "MICROSOFT_CLR_CANDIDATE", "UNKNOWN", "NOT_VERIFIED"}
        and report["registry64_adjustment"] in {"NOT_APPLICABLE", "NOT_NEEDED", "CLEARED", "QUERY_FAILED", "DELETE_FAILED", "VERIFY_FAILED"}
        and report["registry32_adjustment"] in {"NOT_APPLICABLE", "NOT_NEEDED", "CLEARED", "QUERY_FAILED", "DELETE_FAILED", "VERIFY_FAILED"}
        and report["mono_removal"] in {"NOT_APPLICABLE", "REMOVED", "MONO_NOT_REGISTERED", "INVENTORY_FAILED", "REMOVE_FAILED", "VERIFY_FAILED"}
        and report["installer_execution"] in {"NOT_RUN", "EXIT_ZERO", "EXIT_NONZERO", "START_FAILED", "TIMEOUT"}
        and report["unix_exit_category"] in UNIX_OUTCOMES
        and report["win32_selftest_before"] in (SELFTEST_STATES | {"NOT_REQUESTED"})
        and report["win32_selftest_after"] in (SELFTEST_STATES | {"NOT_REQUESTED"})
        and report["win32_original_status"] in WIN32_STATUSES
        and report["win32_original_exit"] in WIN32_CATEGORIES
        and report["setup_log_status"] in KNOWN_RESULTS
        and report["setup_log_phase"] in KNOWN_PHASES
        and type(report["setup_error_categories"]) is list
        and report["setup_error_categories"] == sorted(set(report["setup_error_categories"]))
        and all(x in KNOWN_CODES.values()
                for x in report["setup_error_categories"])
        and report["wine_restart"] in REBOOT_OUTCOMES
        and report["clr64_before"] in STATES and report["clr64_after"] in STATES
        and report["clr64_change"] in CHANGES
        and report["clr_loader"] in LOAD_STATES
        and report["managed_identity"] in {"NOT_VERIFIED", "MONO", "MICROSOFT_CLR_CANDIDATE", "UNKNOWN"}
        and report["managed_functionality"] in {"NOT_VERIFIED", "PASS", "FAIL"}
        and report["registry_indicator"] in {"NOT_VERIFIED", "AT_LEAST_481", "BELOW_481", "NOT_FOUND", "UNAVAILABLE"}
        and type(report["native_48_candidate"]) is bool
        and report["netfx481_ready"] is False
        and report["solidworks_compatibility"] == "NOT_DEMONSTRATED"
    )


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Isolated genuine Microsoft .NET 4.8 CLR baseline")
    for name in ("wine", "prefix", "installer", "sha256-file", "probe", "clr-loader", "output"):
        ap.add_argument("--" + name, required=True, type=Path)
    ap.add_argument("--timeout", type=int, default=210)
    ap.add_argument("--win32-launcher", type=Path,
                    help="Capture full original Microsoft .NET 4.8 Win32 exit and private setup error categories")
    ap.add_argument("--agree-disposable-prefix", action="store_true", required=True)
    args = ap.parse_args(argv)
    if not 60 <= args.timeout <= 360:
        ap.error("Invalid installer timeout")
    try:
        source_paths = (args.installer, args.sha256_file, args.probe, args.clr_loader,
                        *([args.win32_launcher] if args.win32_launcher is not None else []))
        if args.output.is_symlink() or args.output.resolve() in {p.resolve() for p in source_paths}:
            raise ValueError("Output must be an independent report")
        report = inspect(args.wine, args.prefix, args.installer, args.sha256_file,
                         args.probe, args.clr_loader, args.timeout,
                         win32_launcher=args.win32_launcher)
        if not validate(report):
            raise ValueError("Invalid sanitization schema")
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    except (OSError, ValueError):
        ap.error("Verified .NET 4.8 disposable-prefix experiment refused")
    print("Original Microsoft .NET 4.8 outcome:", report["installer_execution"])
    print("Original setup process exit category:", report["unix_exit_category"])
    print("Original Win32 monitor selftest before cleanup:", report["win32_selftest_before"])
    print("Original Win32 monitor selftest after cleanup:", report["win32_selftest_after"])
    print("Exact Windows installer status:", report["win32_original_status"])
    print("Exact Windows installer exit classification:", report["win32_original_exit"])
    print("Private installer setup failure stage:", report["setup_log_phase"])
    print("Known original installer error categories:",
          ",".join(report["setup_error_categories"]) or "NONE")
    print("Wine Mono MSI removal:", report["mono_removal"])
    print("Actual Framework64 CLR on disk:", report["clr64_after"])
    print("Independent CLR loader:", report["clr_loader"])
    print("Microsoft native 4.8 candidate:", report["native_48_candidate"])
    print("Microsoft .NET Framework 4.8.1 ready: NO")
    print("SOLIDWORKS: NOT DEMONSTRATED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
