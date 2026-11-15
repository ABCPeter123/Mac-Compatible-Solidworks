"""Try a targeted Wine-only restart after an original MSI service registration.

An original MSI installed the exact Win32 service binary and wrote its
HKLM service key under Wine, yet a new SCM process returned 1060. Determine
whether Wine's supported wineboot.exe --restart refreshes SCM visibility.
No host reboot, no custom Wine patches, no original Microsoft installer.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from scripts.netfx481_trial import validate_prefix, wineboot_restart
from scripts.msi_service_registry_observation import (
    validate as validate_previous, service_registry,
)
from scripts.msi_service_action_trial import query_service, EXE_NAME

SCOPE = "DISPOSABLE_WINE_SCM_RESTART_VISIBILITY_NOT_SOLIDWORKS"
RESTART_STATES = {"NOT_RUN", "COMPLETED", "TIMED_OUT", "START_FAILED", "EXIT_NONZERO"}
QUERY_STATES = {"ABSENT", "RUNNING", "STOPPED", "LOCKED", "START_TIMEOUT", "OTHER", "UNKNOWN"}


def inspect(wine: Path, prefix: Path, executable: Path, prior: Path) -> dict:
    if os.name == "nt" or any(x.is_symlink() for x in (wine, prefix, executable, prior)):
        raise ValueError("Only self-authored disposable Wine service experiment")
    wine, prefix, executable, prior = (
        x.resolve(strict=True) for x in (wine, prefix, executable, prior))
    validate_prefix(prefix)
    if not wine.is_file() or not os.access(wine, os.X_OK):
        raise ValueError("Wine missing")
    if not executable.is_file() or executable.name.casefold() != EXE_NAME:
        raise ValueError("Original self-authored Win32 service fixture missing")
    if not prior.is_file() or prior.stat().st_size > 8192:
        raise ValueError("Only bounded prior result permitted")
    previous = json.loads(prior.read_text(encoding="ascii"))
    if not validate_previous(previous):
        raise ValueError("Invalid previously verified service registry and SCM evidence")
    eligible = (previous["difference"] == "REGISTRY_PRESENT_SCM_ABSENT"
                and previous["installer_status"] == "ZERO"
                and previous["file_status"] == "PRESENT_MATCH")
    report = {
        "schema": 1, "scope": SCOPE,
        "trial": "MEASURED" if eligible else "NOT_APPLICABLE",
        "restart": "NOT_RUN", "registry_before": previous["service_registry"],
        "scm_before": previous["independent_scm"],
        "registry_after": "UNAVAILABLE", "scm_after": "UNKNOWN",
        "service_visibility_recovered": False,
        "native_microsoft_clr": False,
        "solidworks_compatibility": "NOT_DEMONSTRATED",
    }
    if eligible:
        report["restart"] = wineboot_restart(wine, prefix, timeout=100)
        # Even if restart returns nonzero, measure but do not claim recovery.
        report["registry_after"] = service_registry(wine, prefix)
        report["scm_after"] = query_service(wine, prefix, executable, "status")
        report["service_visibility_recovered"] = (
            report["restart"] == "COMPLETED"
            and report["registry_after"] == "PRESENT"
            and report["scm_after"] in {"RUNNING", "STOPPED"}
        )
    return report


def validate(r: dict) -> bool:
    if type(r) is not dict or set(r) != {
        "schema", "scope", "trial", "restart", "registry_before", "scm_before",
        "registry_after", "scm_after", "service_visibility_recovered",
        "native_microsoft_clr", "solidworks_compatibility"
    }:
        return False
    if (type(r["schema"]) is not int or r["schema"] != 1 or r["scope"] != SCOPE
            or r["trial"] not in {"MEASURED", "NOT_APPLICABLE"}
            or r["restart"] not in RESTART_STATES
            or r["registry_before"] not in {"PRESENT", "ABSENT", "UNAVAILABLE"}
            or r["registry_after"] not in {"PRESENT", "ABSENT", "UNAVAILABLE"}
            or r["scm_before"] not in QUERY_STATES or r["scm_after"] not in QUERY_STATES
            or type(r["service_visibility_recovered"]) is not bool
            or r["native_microsoft_clr"] is not False
            or r["solidworks_compatibility"] != "NOT_DEMONSTRATED"):
        return False
    if r["trial"] == "NOT_APPLICABLE":
        return (r["restart"] == "NOT_RUN" and r["scm_after"] == "UNKNOWN"
                and r["registry_after"] == "UNAVAILABLE"
                and r["service_visibility_recovered"] is False)
    if r["registry_before"] != "PRESENT" or r["scm_before"] != "ABSENT":
        return False
    return r["service_visibility_recovered"] == (
        r["restart"] == "COMPLETED"
        and r["registry_after"] == "PRESENT"
        and r["scm_after"] in {"RUNNING", "STOPPED"}
    )


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Read-only SCM visibility after bounded disposable Wine restart")
    for name in ("wine", "prefix", "exe", "prior", "output"):
        p.add_argument("--" + name, required=True, type=Path)
    p.add_argument("--agree-disposable-prefix", action="store_true", required=True)
    args = p.parse_args(argv)
    try:
        if args.output.is_symlink() or args.output.resolve() in {
            x.resolve() for x in (args.wine, args.prefix, args.exe, args.prior)
        }:
            raise ValueError("Invalid report target")
        report = inspect(args.wine, args.prefix, args.exe, args.prior)
        if not validate(report):
            raise ValueError("Invalid isolated Wine restart status")
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="ascii")
    except (OSError, ValueError, json.JSONDecodeError):
        p.error("Unsafe or incomplete original service Wine restart experiment")
    for key in ("trial", "restart", "registry_before", "scm_before",
                "registry_after", "scm_after", "service_visibility_recovered"):
        print("Wine isolated service refresh", key, report[key])
    print("Microsoft native CLR and SOLIDWORKS compatibility: NOT DEMONSTRATED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
