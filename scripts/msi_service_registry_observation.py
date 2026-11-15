"""Read-only HKLM service registration check after original MSI install-only trial.

The previously verified source-backed MSI successfully installed its service
binary under Wine, but a separate Win32 SCM client could not open that service.
Determine whether the registration exists in the registry, or was never
persisted. Never export raw Registry values, user paths or vendor content.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess

from scripts.netfx481_trial import validate_prefix
from scripts.msi_service_action_trial import validate as validate_msi

FIXED_KEY = r"HKLM\SYSTEM\CurrentControlSet\Services\SWCompatOriginalServiceTest"
STATES = {"PRESENT", "ABSENT", "UNAVAILABLE"}
DISTINCTIONS = {"SCM_AND_REGISTRY_PRESENT", "REGISTRY_PRESENT_SCM_ABSENT",
                "REGISTRY_ABSENT", "UNKNOWN"}
SCOPE = "MSI_ORIGINAL_SERVICE_REGISTRY_VS_SCM_NOT_SOLIDWORKS"


def service_registry(wine: Path, prefix: Path) -> str:
    validate_prefix(prefix)
    if wine.is_symlink() or not wine.is_file() or not os.access(wine, os.X_OK):
        raise ValueError("Fixed Wine executable missing")
    env = os.environ.copy()
    env.pop("WINEDLLOVERRIDES", None)
    env.update({"WINEPREFIX": str(prefix), "WINEARCH": "win64",
                "WINEDEBUG": "-all"})
    try:
        result = subprocess.run(
            [str(wine), "reg.exe", "query", FIXED_KEY],
            cwd=prefix, env=env, stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=35, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return "UNAVAILABLE"
    return {0: "PRESENT", 1: "ABSENT"}.get(result.returncode, "UNAVAILABLE")


def inspect(wine: Path, prefix: Path, prior: Path) -> dict:
    if os.name == "nt" or any(x.is_symlink() for x in (wine, prefix, prior)):
        raise ValueError("Read-only registry check only within marked Wine prefix")
    wine, prefix, prior = (x.resolve(strict=True) for x in (wine, prefix, prior))
    validate_prefix(prefix)
    if prior.stat().st_size > 8192:
        raise ValueError("Expected bounded self-authored MSI result")
    previous = json.loads(prior.read_text(encoding="ascii"))
    if not validate_msi(previous):
        raise ValueError("Invalid original service MSI evidence")
    registry = service_registry(wine, prefix)
    scm = previous["service_after"]
    if registry == "PRESENT" and scm in {"RUNNING", "STOPPED"}:
        difference = "SCM_AND_REGISTRY_PRESENT"
    elif registry == "PRESENT" and scm == "ABSENT":
        difference = "REGISTRY_PRESENT_SCM_ABSENT"
    elif registry == "ABSENT":
        difference = "REGISTRY_ABSENT"
    else:
        difference = "UNKNOWN"
    return {
        "schema": 1, "scope": SCOPE, "service_registry": registry,
        "independent_scm": scm, "difference": difference,
        "installer_status": previous["msi_process"],
        "file_status": previous["binary_after"],
        "native_dotnet_compatibility": False,
        "solidworks_compatibility": "NOT_DEMONSTRATED",
    }


def validate(r: dict) -> bool:
    if type(r) is not dict or set(r) != {
        "schema", "scope", "service_registry", "independent_scm",
        "difference", "installer_status", "file_status",
        "native_dotnet_compatibility", "solidworks_compatibility"
    }:
        return False
    if (type(r["schema"]) is not int or r["schema"] != 1 or r["scope"] != SCOPE
            or r["service_registry"] not in STATES
            or r["independent_scm"] not in {
                "ABSENT", "RUNNING", "STOPPED", "LOCKED",
                "START_TIMEOUT", "OTHER", "UNKNOWN"}
            or r["difference"] not in DISTINCTIONS
            or r["installer_status"] not in {
                "NOT_RUN", "ZERO", "NONZERO", "TIMEOUT", "START_FAILED"}
            or r["file_status"] not in {
                "ABSENT", "PRESENT_MATCH", "CHANGED", "LINKED", "IO_ERROR"}
            or r["native_dotnet_compatibility"] is not False
            or r["solidworks_compatibility"] != "NOT_DEMONSTRATED"):
        return False
    correct = (
        "SCM_AND_REGISTRY_PRESENT"
        if r["service_registry"] == "PRESENT" and r["independent_scm"] in {"RUNNING", "STOPPED"}
        else "REGISTRY_PRESENT_SCM_ABSENT"
        if r["service_registry"] == "PRESENT" and r["independent_scm"] == "ABSENT"
        else "REGISTRY_ABSENT" if r["service_registry"] == "ABSENT"
        else "UNKNOWN"
    )
    return r["difference"] == correct


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Compare Wine registry vs independent SCM for harmless MSI service")
    for key in ("wine", "prefix", "prior", "output"):
        p.add_argument("--" + key, required=True, type=Path)
    p.add_argument("--agree-disposable-prefix", action="store_true", required=True)
    args = p.parse_args(argv)
    try:
        if args.output.is_symlink() or args.output.resolve() in {
            x.resolve() for x in (args.wine, args.prefix, args.prior)
        }:
            raise ValueError("Unsafe report path")
        report = inspect(args.wine, args.prefix, args.prior)
        if not validate(report):
            raise ValueError("Unsafe service registration comparison")
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="ascii")
    except (ValueError, OSError, json.JSONDecodeError):
        p.error("Read-only original MSI registry diagnostic failed")
    for field in ("service_registry", "independent_scm", "difference",
                  "installer_status", "file_status"):
        print("Original service registration", field, report[field])
    print("Native Microsoft CLR and SOLIDWORKS: NOT DEMONSTRATED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
