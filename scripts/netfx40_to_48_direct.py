"""Opt-in original signed .NET Framework 4.8 on a verified native 4.0 prefix.

This is an intermediate prerequisite experiment, never proof of 4.8.1
or SOLIDWORKS support. No raw Microsoft setup files, paths, hashes, or logs
are included in the published report. Authentication happens on Windows CI.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path

from scripts.netfx40_msxml3_restart import validate as validate_native40
from scripts.netfx40_to_48_intermediate import _env, _release, _set_winver, RELEASE
from scripts.netfx481_clr_load import run as load_clr, STATUSES as LOAD_STATES
from scripts.netfx481_payload_audit import snapshot, compare
from scripts.netfx481_setup_evidence import (
    classify_log, discard_log, KNOWN_RESULTS, KNOWN_PHASES, KNOWN_CODES,
    snapshot_secondary_logs, scan_secondary_logs, validate_secondary_report,
)
from scripts.netfx481_prereq_diagnostic import (
    classify_file as classify_primary_prerequisite,
    empty as empty_prerequisite, validate as validate_prerequisite,
)
from scripts.netfx481_trial import validate_prefix, probe, wineboot_restart
from scripts.netfx481_win32_exit import (
    launch, blank as blank_launch, validate as validate_launch,
)

STATUSES = {"NOT_ELIGIBLE", "MEASURED"}
PROFILES = {"NOT_RUN", "APPLIED", "FAILED"}
RESTARTS = {"NOT_RUN", "COMPLETED", "TIMED_OUT", "START_FAILED",
            "EXIT_NONZERO", "SKIPPED_CHILD_UNVERIFIED"}
SETUP_EVIDENCE = {"status": "NOT_REQUESTED", "phase": "UNKNOWN", "codes": []}
LOG_FOLDER = "swcompat-netfx48-private"
LOG_FILE = "framework-setup.txt"
MIN_BYTES = 15 * 1024 * 1024
MAX_BYTES = 250 * 1024 * 1024
# Read-only Wine Service Control Manager differential. An absent service is
# evidence of an unsupported installer prerequisite, not permission to forge
# its registration or claim genuine Windows component servicing.
SERVICE_NAMES = ("TrustedInstaller", "msiserver", "wuauserv", "BITS")
SERVICE_VALUES = {"NOT_RUN", "PRESENT", "ABSENT", "UNKNOWN"}
SERVICE_MAX_BYTES = 4096


def blank_services() -> dict:
    return {key: "NOT_RUN" for key in SERVICE_NAMES}


def valid_services(value: object) -> bool:
    return (type(value) is dict and set(value) == set(SERVICE_NAMES)
            and all(type(v) is str and v in SERVICE_VALUES
                    for v in value.values()))


def inventory_services(wine: Path, prefix: Path) -> dict:
    """Read only SCM names, never expose raw Wine stdout or registry paths."""
    validate_prefix(prefix)
    if wine.is_symlink() or not wine.is_file():
        raise ValueError("Invalid signed Wine service probe runtime")
    env = os.environ.copy()
    env.update({"WINEPREFIX": str(prefix), "WINEARCH": "win64",
                "WINEDEBUG": "-all"})
    env.pop("WINEDLLOVERRIDES", None)
    result = blank_services()
    for name in SERVICE_NAMES:
        with tempfile.TemporaryFile() as output:
            try:
                process = subprocess.run(
                    [str(wine), "sc", "query", name], env=env,
                    stdin=subprocess.DEVNULL, stdout=output,
                    stderr=subprocess.DEVNULL, timeout=15, check=False)
            except (OSError, subprocess.TimeoutExpired):
                result[name] = "UNKNOWN"
                continue
            output.seek(0)
            raw = output.read(SERVICE_MAX_BYTES + 1)
            if len(raw) > SERVICE_MAX_BYTES:
                result[name] = "UNKNOWN"
            elif (process.returncode == 0 and
                  re.search(rb"(?i)\\bSERVICE_NAME\\s*:\\s*" +
                            re.escape(name.encode("ascii")) + rb"\\b", raw)):
                result[name] = "PRESENT"
            elif process.returncode != 0 and re.search(
                    rb"(?i)(?:\\b1060\\b|service.{0,80}does not exist)", raw):
                result[name] = "ABSENT"
            else:
                result[name] = "UNKNOWN"
    assert valid_services(result)
    return result



def blank() -> dict:
    return {
        "status": "NOT_ELIGIBLE", "native40_persistent": False,
        "service_prerequisites": blank_services(),
        "win7": "NOT_RUN", "win10": "NOT_RUN",
        "setup": blank_launch(), "setup_evidence": dict(SETUP_EVIDENCE),
        "secondary_evidence": None,
        "primary_prerequisite": empty_prerequisite(),
        "restart": "NOT_RUN", "clr64_changed": False,
        "release": "UNAVAILABLE", "loader": "NOT_VERIFIED",
        "runtime_family": "NOT_VERIFIED", "native_only_managed": "NOT_VERIFIED",
        "native48_candidate": False, "framework481_confirmed": False,
        "solidworks_compatibility": "NOT_DEMONSTRATED",
    }


def validate(report: object) -> bool:
    if type(report) is not dict or set(report) != set(blank()):
        return False
    e = report["setup_evidence"]
    if (type(e) is not dict or set(e) != set(SETUP_EVIDENCE)
            or e["status"] not in KNOWN_RESULTS
            or e["phase"] not in KNOWN_PHASES
            or type(e["codes"]) is not list
            or e["codes"] != sorted(set(e["codes"]))
            or any(code not in KNOWN_CODES.values() for code in e["codes"])):
        return False
    if (report["status"] not in STATUSES
            or not validate_launch(report["setup"])
            or report["win7"] not in PROFILES or report["win10"] not in PROFILES
            or report["restart"] not in RESTARTS
            or report["release"] not in RELEASE
            or report["loader"] not in LOAD_STATES | {"NOT_VERIFIED"}
            or report["runtime_family"] not in {
                "NOT_VERIFIED", "UNKNOWN", "MONO", "MICROSOFT_CLR_CANDIDATE"}
            or report["native_only_managed"] not in {"NOT_VERIFIED", "FAIL", "PASS"}
            or any(type(report[key]) is not bool for key in (
                "native40_persistent", "clr64_changed", "native48_candidate"))
            or report["framework481_confirmed"] is not False
            or report["solidworks_compatibility"] != "NOT_DEMONSTRATED"
            or not validate_prerequisite(report["primary_prerequisite"])
            or not valid_services(report["service_prerequisites"])
            or (report["status"] == "MEASURED"
                and not validate_secondary_report(report["secondary_evidence"]))
            or (report["status"] == "NOT_ELIGIBLE"
                and report["secondary_evidence"] is not None)):
        return False
    if report["status"] == "NOT_ELIGIBLE":
        return report == blank()
    exit_ok = (report["setup"]["status"] == "EXIT_CAPTURED"
               and report["setup"]["category"] in {"SUCCESS", "REBOOT_REQUIRED"}
               and report["setup"]["child_lifecycle"] in {"ALL_EXITED", "NOT_OBSERVED"}
               and (report["setup"]["category"] == "SUCCESS"
                    or report["restart"] == "COMPLETED")
               and report["setup"]["child_exit"] != "NONZERO")
    ready = (report["native40_persistent"]
             and report["win7"] == "APPLIED" and report["win10"] == "APPLIED"
             and exit_ok and report["clr64_changed"]
             and report["release"] == "NETFX48_RANGE"
             and report["loader"] == "LOADED"
             and report["runtime_family"] == "MICROSOFT_CLR_CANDIDATE"
             and report["native_only_managed"] == "PASS")
    return report["native48_candidate"] == ready


def verify_original_media(installer: Path, digest_file: Path) -> None:
    if (installer.is_symlink() or digest_file.is_symlink()
            or installer.name.casefold() != "ndp48-x86-x64-allos-enu.exe"
            or not installer.is_file() or not digest_file.is_file()
            or not MIN_BYTES <= installer.stat().st_size <= MAX_BYTES):
        raise ValueError("Only independently authenticated original 4.8 media permitted")
    expected = digest_file.read_text(encoding="ascii").strip()
    if len(expected) != 64 or any(c not in "0123456789abcdefABCDEF" for c in expected):
        raise ValueError("Invalid original media digest manifest")
    digest = hashlib.sha256()
    with installer.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    if digest.hexdigest().lower() != expected.lower():
        raise ValueError("Original Microsoft .NET 4.8 installer hash differs")


def private_setup_log(prefix: Path) -> Path:
    validate_prefix(prefix)
    folder = prefix / "drive_c" / LOG_FOLDER
    if folder.is_symlink():
        raise ValueError("Linked original installer diagnostic folder")
    folder.mkdir(mode=0o700, exist_ok=True)
    if not folder.is_dir():
        raise ValueError("Private diagnostic folder unavailable")
    target = folder / LOG_FILE
    if target.is_symlink() or target.exists():
        raise ValueError("Original diagnostic output must start absent")
    return target


def inspect(wine: Path, prefix: Path, installer: Path, digest_file: Path,
            launcher: Path, loader: Path, managed: Path, native40: dict) -> dict:
    if os.name == "nt" or any(p.is_symlink() for p in (
            wine, prefix, installer, digest_file, launcher, loader, managed)):
        raise ValueError("Only explicit disposable Wine experiments allowed")
    wine, prefix, installer, digest_file, launcher, loader, managed = (
        p.resolve(strict=True) for p in (
            wine, prefix, installer, digest_file, launcher, loader, managed))
    validate_prefix(prefix)
    verify_original_media(installer, digest_file)
    if (launcher.name.casefold() != "netfx48_win32_launch.exe"
            or loader.name.casefold() != "netfx481_clr_load.exe"
            or managed.name.casefold() != "netfx481_runtime_probe.exe"):
        raise ValueError("Expected independently compiled Windows probes")
    if not validate_native40(native40) or not native40["persistent_native_managed"]:
        return blank()
    before = snapshot(prefix)
    initial = probe(wine, prefix, managed, override="native_only")
    if (before["CLR64"][0] != "PE_AMD64"
            or load_clr(wine, prefix, loader) != "LOADED"
            or initial["clr_family"] != "MICROSOFT_CLR_CANDIDATE"
            or initial["managed"] != "PASS"):
        return blank()

    services = inventory_services(wine, prefix)
    env = _env(wine, prefix)
    win7 = _set_winver(wine, prefix, env, "win7")
    setup = blank_launch()
    evidence = dict(SETUP_EVIDENCE)
    secondary = None
    primary = empty_prerequisite()
    restart = "NOT_RUN"
    try:
        if win7 == "APPLIED":
            log = private_setup_log(prefix)
            # Snapshot before setup. Previous .NET 4.0 / msxml3 logs cannot
            # be attributed to the signed .NET 4.8 installer.
            secondary_before = snapshot_secondary_logs(prefix)
            try:
                setup = launch(wine, prefix, installer, launcher,
                               timeout=465, fusion_builtin=True,
                               setup_family="NETFX48")
            finally:
                # Both classifiers read the short-lived original /log inside
                # the marked Wine prefix. Never print or retain raw text.
                evidence = classify_log(log)
                primary = classify_primary_prerequisite(log, family="NETFX48")
                discard_log(log)
                secondary = scan_secondary_logs(
                    prefix, baseline=secondary_before, family="NETFX48")
            if (setup["status"] == "EXIT_CAPTURED"
                    and setup["category"] == "REBOOT_REQUIRED"):
                if setup["child_lifecycle"] in {"PARTIAL", "STILL_ACTIVE", "UNKNOWN"}:
                    restart = "SKIPPED_CHILD_UNVERIFIED"
                else:
                    restart = wineboot_restart(wine, prefix, timeout=90)
    finally:
        # Restore Win10 even when setup fails or times out. No persistent
        # installer-only Fusion preference is applied to the prefix.
        win10 = _set_winver(wine, prefix, env, "win10")

    if secondary is None:
        # Unavailable media/OS profile cannot result in a measured upgrade.
        # This is not a native 4.8 success.
        return blank()
    after = snapshot(prefix)
    delta = compare(before, after)
    current = probe(wine, prefix, managed, override="native_only")
    result = {
        "status": "MEASURED", "native40_persistent": True,
        "service_prerequisites": services,
        "win7": win7, "win10": win10, "setup": setup,
        "setup_evidence": evidence, "secondary_evidence": secondary,
        "primary_prerequisite": primary, "restart": restart,
        "clr64_changed": delta["changes"]["CLR64"] == "CHANGED",
        "release": _release(wine, prefix, env),
        "loader": load_clr(wine, prefix, loader),
        "runtime_family": current["clr_family"],
        "native_only_managed": current["managed"],
        "native48_candidate": False, "framework481_confirmed": False,
        "solidworks_compatibility": "NOT_DEMONSTRATED",
    }
    result["native48_candidate"] = (
        result["win7"] == "APPLIED" and result["win10"] == "APPLIED"
        and result["setup"]["status"] == "EXIT_CAPTURED"
        and result["setup"]["category"] in {"SUCCESS", "REBOOT_REQUIRED"}
        and result["setup"]["child_lifecycle"] in {"ALL_EXITED", "NOT_OBSERVED"}
        and result["setup"]["child_exit"] != "NONZERO"
        and (result["setup"]["category"] == "SUCCESS"
             or result["restart"] == "COMPLETED")
        and result["clr64_changed"] and result["release"] == "NETFX48_RANGE"
        and result["loader"] == "LOADED"
        and result["runtime_family"] == "MICROSOFT_CLR_CANDIDATE"
        and result["native_only_managed"] == "PASS")
    if not validate(result):
        raise ValueError("Invalid bounded original Microsoft .NET 4.8 report")
    return result


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Opt-in authentic native 4.0 to 4.8 upgrade")
    for key in ("wine", "prefix", "installer", "sha256-file", "launcher", "loader",
                "managed", "native40-report", "output"):
        ap.add_argument("--" + key, type=Path, required=True)
    ap.add_argument("--agree-disposable-prefix", action="store_true", required=True)
    args = ap.parse_args(argv)
    prior = json.loads(args.native40_report.read_text(encoding="ascii"))
    result = inspect(args.wine, args.prefix, args.installer, args.sha256_file,
                     args.launcher, args.loader, args.managed, prior)
    if not validate(result) or args.output.is_symlink():
        raise ValueError("Unverified original Microsoft .NET 4.8 outcome")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, sort_keys=True), encoding="ascii")
    for field, value in result.items():
        if field == "setup":
            for name in ("status", "category", "child_lifecycle", "child_exit"):
                print("Original .NET 4.8 setup", name, value[name])
        elif field == "setup_evidence":
            for name in ("status", "phase"):
                print("Original .NET 4.8 private log", name, value[name])
            print("Original .NET 4.8 private log error classes", ",".join(value["codes"]))
        elif field == "primary_prerequisite":
            for name in ("status", "os_versions", "blockers", "5100_in_log"):
                print("Original .NET 4.8 primary_prerequisite", name, value[name])
        elif field == "secondary_evidence":
            if value is not None:
                print("Original .NET 4.8 secondary status", value["status"])
                print("Original .NET 4.8 secondary files_scanned", value["files_scanned"])
                print("Original .NET 4.8 secondary fresh_files", value["stage_files"])
                print("Original .NET 4.8 secondary named_files", value["prerequisite_files"])
                for scope in ("prerequisite", "stage_prerequisite"):
                    for name in ("status", "os_versions", "blockers", "5100_in_log"):
                        print("Original .NET 4.8", scope, name, value[scope][name])
        else:
            print("Original .NET 4.8 intermediate", field, value)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
