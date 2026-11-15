"""Authentic .NET 4.0 -> 4.8.1 in-place upgrade on Apple Silicon Wine.

Run only after the real 4.0 CLR survived Wine restart with native-only
managed execution. Do not uninstall or spoof the existing Microsoft CLR.
Never publish installer text, file names/paths, hashes or proprietary media.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from scripts.netfx40_msxml3_restart import validate as validate_native40
from scripts.netfx481_clr_load import run as load_clr, STATUSES as LOAD_STATES
from scripts.netfx481_payload_audit import compare, snapshot, STATES, CHANGES
from scripts.netfx481_trial import (
    validate_prefix, probe, verify_media, wineboot_restart,
)
from scripts.netfx481_win32_exit import (
    blank as blank_launch, launch, validate as validate_launch,
)
from scripts.netfx481_setup_evidence import (
    private_log_path, classify_log, discard_log, scan_secondary_logs,
    validate_secondary_report, KNOWN_RESULTS, KNOWN_PHASES, KNOWN_CODES,
)

STATES_UPGRADE = {"PREREQUISITE_MISSING", "MEASURED"}
RESTARTS = {"NOT_RUN", "COMPLETED", "TIMED_OUT", "START_FAILED",
            "EXIT_NONZERO", "WINEBOOT_MISSING", "SKIPPED_CHILD_UNVERIFIED"}
REGISTRY = {"NOT_VERIFIED", "NOT_FOUND", "AT_LEAST_481", "BELOW_481", "UNAVAILABLE"}
FAMILIES = {"NOT_VERIFIED", "UNKNOWN", "MONO", "MICROSOFT_CLR_CANDIDATE"}
MANAGED = {"NOT_VERIFIED", "PASS", "FAIL"}


def blank() -> dict:
    return {
        "status": "PREREQUISITE_MISSING",
        "original_native40_persistent": False,
        "setup": blank_launch(),
        "setup_evidence": {"status": "NOT_REQUESTED", "phase": "UNKNOWN", "codes": []},
        "secondary_evidence": None,
        "restart": "NOT_RUN",
        "clr64_before": "NOT_VERIFIED",
        "clr64_after": "NOT_VERIFIED",
        "clr64_change": "UNVERIFIED",
        "mscorlib64_after": "NOT_VERIFIED",
        "native_clr_load": "NOT_VERIFIED",
        "native_only_managed": "NOT_VERIFIED",
        "runtime_family": "NOT_VERIFIED",
        "registry": "NOT_VERIFIED",
        "native_upgrade_candidate": False,
        "framework481_confirmed": False,
        "solidworks_compatibility": "NOT_DEMONSTRATED",
    }


def validate(result: dict) -> bool:
    if type(result) is not dict or set(result) != set(blank()):
        return False
    evidence = result["setup_evidence"]
    if (type(evidence) is not dict or set(evidence) != {"status", "phase", "codes"}
            or evidence["status"] not in KNOWN_RESULTS
            or evidence["phase"] not in KNOWN_PHASES
            or type(evidence["codes"]) is not list
            or len(evidence["codes"]) > len(KNOWN_CODES)
            or any(x not in KNOWN_CODES.values() for x in evidence["codes"])):
        return False
    secondary = result["secondary_evidence"]
    if secondary is not None and not validate_secondary_report(secondary):
        return False
    if (result["status"] not in STATES_UPGRADE
            or type(result["original_native40_persistent"]) is not bool
            or not validate_launch(result["setup"])
            or result["restart"] not in RESTARTS
            or result["clr64_before"] not in (STATES | {"NOT_VERIFIED"})
            or result["clr64_after"] not in (STATES | {"NOT_VERIFIED"})
            or result["clr64_change"] not in CHANGES
            or result["mscorlib64_after"] not in (STATES | {"NOT_VERIFIED"})
            or result["native_clr_load"] not in (LOAD_STATES | {"NOT_VERIFIED"})
            or result["native_only_managed"] not in MANAGED
            or result["runtime_family"] not in FAMILIES
            or result["registry"] not in REGISTRY
            or type(result["native_upgrade_candidate"]) is not bool
            or type(result["framework481_confirmed"]) is not bool
            or result["solidworks_compatibility"] != "NOT_DEMONSTRATED"):
        return False
    if result["status"] == "PREREQUISITE_MISSING":
        return result == blank()
    if (not result["original_native40_persistent"]
            or result["clr64_before"] != "PE_AMD64"):
        return False
    candidate = (result["clr64_after"] == "PE_AMD64"
                 and result["mscorlib64_after"] == "PE_AMD64"
                 and result["clr64_change"] == "CHANGED"
                 and result["native_clr_load"] == "LOADED"
                 and result["runtime_family"] == "MICROSOFT_CLR_CANDIDATE"
                 and result["native_only_managed"] == "PASS")
    if result["native_upgrade_candidate"] != candidate:
        return False
    successfully_exited = (
        result["setup"]["status"] == "EXIT_CAPTURED"
        and result["setup"]["category"] in {"SUCCESS", "REBOOT_REQUIRED"}
        and (result["setup"]["category"] == "SUCCESS"
             or result["restart"] == "COMPLETED")
    )
    confirmed = (candidate and successfully_exited
                 and result["registry"] == "AT_LEAST_481")
    return result["framework481_confirmed"] == confirmed


def _wine_host() -> bool:
    return os.name != "nt"


def inspect(wine: Path, prefix: Path, installer: Path, manifest: Path,
            launcher: Path, loader: Path, managed: Path,
            native40: dict, *, capture_setup_evidence: bool = False) -> dict:
    if not _wine_host() or any(p.is_symlink() for p in (
            wine, prefix, installer, manifest, launcher, loader, managed)):
        raise ValueError("Only a real disposable Wine upgrade is permitted")
    wine, prefix, installer, manifest, launcher, loader, managed = (
        p.resolve(strict=True) for p in
        (wine, prefix, installer, manifest, launcher, loader, managed)
    )
    validate_prefix(prefix)
    verify_media(installer, manifest)
    if (launcher.name.casefold() != "netfx481_win32_launch.exe"
            or loader.name.casefold() != "netfx481_clr_load.exe"
            or managed.name.casefold() != "netfx481_runtime_probe.exe"):
        raise ValueError("Only self-authored Windows x64 probes are permitted")
    if not validate_native40(native40):
        raise ValueError("Prior native .NET 4.0 restart proof invalid")
    if not native40["persistent_native_managed"]:
        return blank()

    before = snapshot(prefix)
    first = probe(wine, prefix, managed, override="native_only")
    if (before["CLR64"][0] != "PE_AMD64"
            or before["MSCORLIB64"][0] != "PE_AMD64"
            or load_clr(wine, prefix, loader) != "LOADED"
            or first["clr_family"] != "MICROSOFT_CLR_CANDIDATE"
            or first["managed"] != "PASS"):
        return blank()

    # Same official .NET 4.8.1 bootstrapper and scoped Fusion option
    # used in the separate fresh-prefix baseline.
    if capture_setup_evidence:
        log_file = private_log_path(prefix)
        try:
            setup = launch(wine, prefix, installer, launcher,
                           timeout=245, fusion_builtin=True)
        finally:
            setup_evidence = classify_log(log_file)
            discard_log(log_file)
        secondary_evidence = scan_secondary_logs(prefix)
    else:
        setup = launch(wine, prefix, installer, launcher,
                       timeout=245, fusion_builtin=True)
        setup_evidence = {"status": "NOT_REQUESTED", "phase": "UNKNOWN", "codes": []}
        secondary_evidence = None
    if not validate_launch(setup):
        raise ValueError("Unverified original Microsoft installer exit")
    restart = "NOT_RUN"
    if (setup["status"] == "EXIT_CAPTURED"
            and setup["category"] == "REBOOT_REQUIRED"):
        if setup["child_lifecycle"] in {"STILL_ACTIVE", "PARTIAL", "UNKNOWN"}:
            restart = "SKIPPED_CHILD_UNVERIFIED"
        else:
            restart = wineboot_restart(wine, prefix, timeout=120)

    after = snapshot(prefix)
    comparison = compare(before, after)
    current = probe(wine, prefix, managed, override="native_only")
    loader_state = load_clr(wine, prefix, loader)
    result = {
        "status": "MEASURED",
        "original_native40_persistent": True,
        "setup": setup, "restart": restart,
        "setup_evidence": setup_evidence,
        "secondary_evidence": secondary_evidence,
        "clr64_before": comparison["before"]["CLR64"],
        "clr64_after": comparison["after"]["CLR64"],
        "clr64_change": comparison["changes"]["CLR64"],
        "mscorlib64_after": comparison["after"]["MSCORLIB64"],
        "native_clr_load": loader_state,
        "native_only_managed": current["managed"],
        "runtime_family": current["clr_family"],
        "registry": current["registry"],
        "native_upgrade_candidate": False,
        "framework481_confirmed": False,
        "solidworks_compatibility": "NOT_DEMONSTRATED",
    }
    result["native_upgrade_candidate"] = (
        result["clr64_after"] == "PE_AMD64"
        and result["mscorlib64_after"] == "PE_AMD64"
        and result["clr64_change"] == "CHANGED"
        and result["native_clr_load"] == "LOADED"
        and result["runtime_family"] == "MICROSOFT_CLR_CANDIDATE"
        and result["native_only_managed"] == "PASS"
    )
    result["framework481_confirmed"] = (
        result["native_upgrade_candidate"]
        and result["setup"]["status"] == "EXIT_CAPTURED"
        and result["setup"]["category"] in {"SUCCESS", "REBOOT_REQUIRED"}
        and (result["setup"]["category"] == "SUCCESS"
             or result["restart"] == "COMPLETED")
        and result["registry"] == "AT_LEAST_481"
    )
    if not validate(result):
        raise ValueError("Invalid bounded Microsoft 4.0-to-4.8.1 upgrade report")
    return result


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Genuine .NET 4.0 to 4.8.1 upgrade")
    for key in ("wine", "prefix", "installer", "sha256-file", "launcher",
                "loader", "managed", "native40-report", "output"):
        ap.add_argument("--" + key, type=Path, required=True)
    ap.add_argument("--agree-disposable-prefix", action="store_true", required=True)
    ap.add_argument("--experiment-private-setup-evidence", action="store_true")
    args = ap.parse_args(argv)
    native40 = json.loads(args.native40_report.read_text(encoding="utf-8"))
    outcome = inspect(args.wine, args.prefix, args.installer, args.sha256_file,
                      args.launcher, args.loader, args.managed, native40,
                      capture_setup_evidence=args.experiment_private_setup_evidence)
    if not validate(outcome):
        raise ValueError("Unsafe original Microsoft upgrade outcome")
    if args.output.is_symlink():
        raise ValueError("Linked report output")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(outcome, sort_keys=True), encoding="ascii")
    for key in ("status", "original_native40_persistent", "restart",
                "clr64_before", "clr64_after", "clr64_change",
                "mscorlib64_after", "native_clr_load", "native_only_managed",
                "runtime_family", "registry", "native_upgrade_candidate",
                "framework481_confirmed", "solidworks_compatibility"):
        print("Genuine Microsoft .NET in-place upgrade", key, outcome[key])
    for key in ("status", "category", "child_lifecycle"):
        print("Genuine Microsoft .NET in-place setup", key, outcome["setup"][key])
    for key in ("status", "phase"):
        print("Genuine Microsoft .NET private setup", key, outcome["setup_evidence"][key])
    print("Genuine Microsoft .NET private setup error classes", ",".join(outcome["setup_evidence"]["codes"]))
    if outcome["secondary_evidence"] is not None:
        for key in ("status", "phase"):
            print("Genuine Microsoft .NET secondary setup", key, outcome["secondary_evidence"][key])
        print("Genuine Microsoft .NET secondary setup error classes", ",".join(outcome["secondary_evidence"]["codes"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
