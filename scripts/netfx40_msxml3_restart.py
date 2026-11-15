"""Verify real Microsoft CLR after restarting a timed-out .NET 4.0 installer.

This may demonstrate persistent managed-code execution. It never calls an
incomplete Microsoft installation successful or claims SOLIDWORKS readiness.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from scripts.netfx40_legacy import validate as validate_original
from scripts.netfx481_payload_audit import snapshot
from scripts.netfx481_trial import validate_prefix, wineboot_restart, probe
from scripts.netfx481_clr_load import run as clr_load, STATUSES as LOAD_STATES

STATUSES = {"NOT_ELIGIBLE", "RESTART_COMPLETED", "RESTART_FAILED"}
RESTARTS = {"NOT_RUN", "COMPLETED", "TIMED_OUT", "START_FAILED", "EXIT_NONZERO"}
STATES = {"NOT_VERIFIED", "ABSENT", "PE_AMD64", "PE_I386", "PE_OTHER",
          "NOT_PE", "LINKED", "IO_ERROR", "INVALID_SIZE"}
def blank() -> dict:
    return {"status": "NOT_ELIGIBLE", "restart": "NOT_RUN",
            "clr64": "NOT_VERIFIED", "mscorlib64": "NOT_VERIFIED",
            "native_loader": "NOT_VERIFIED", "runtime_family": "NOT_VERIFIED",
            "managed": "NOT_VERIFIED", "native_only_managed": "NOT_VERIFIED",
            "persistent_native_managed": False}


def validate(r: dict) -> bool:
    if type(r) is not dict or set(r) != set(blank()):
        return False
    if (r["status"] not in STATUSES or r["restart"] not in RESTARTS
            or r["clr64"] not in STATES or r["mscorlib64"] not in STATES
            or r["native_loader"] not in (LOAD_STATES | {"NOT_VERIFIED"})
            or r["runtime_family"] not in {
                "NOT_VERIFIED", "UNKNOWN", "MONO", "MICROSOFT_CLR_CANDIDATE"}
            or r["managed"] not in {"NOT_VERIFIED", "PASS", "FAIL"}
            or r["native_only_managed"] not in {"NOT_VERIFIED", "PASS", "FAIL"}
            or type(r["persistent_native_managed"]) is not bool):
        return False
    if r["status"] == "NOT_ELIGIBLE":
        return r == blank()
    if r["status"] == "RESTART_FAILED":
        return (r["restart"] in {"TIMED_OUT", "START_FAILED", "EXIT_NONZERO"}
                and all(r[key] == blank()[key] for key in (
                    "clr64", "mscorlib64", "native_loader", "runtime_family",
                    "managed", "native_only_managed", "persistent_native_managed")))
    if r["restart"] != "COMPLETED":
        return False
    should_pass = (r["clr64"] == "PE_AMD64"
                   and r["mscorlib64"] == "PE_AMD64"
                   and r["native_loader"] == "LOADED"
                   and r["runtime_family"] == "MICROSOFT_CLR_CANDIDATE"
                   and r["managed"] == "PASS"
                   and r["native_only_managed"] == "PASS")
    return r["persistent_native_managed"] is should_pass


def _is_wine_host() -> bool:
    return os.name != "nt"


def inspect(wine: Path, prefix: Path, loader: Path, managed: Path,
            original: dict) -> dict:
    if not _is_wine_host() or any(p.is_symlink() for p in
                                  (wine, prefix, loader, managed)):
        raise ValueError("Restart experiment requires isolated Wine")
    wine, prefix, loader, managed = (
        p.resolve(strict=True) for p in (wine, prefix, loader, managed)
    )
    validate_prefix(prefix)
    if not wine.is_file() or not os.access(wine, os.X_OK):
        raise ValueError("Wine executable invalid")
    if (loader.name != "netfx481_clr_load.exe"
            or managed.name != "netfx481_runtime_probe.exe"):
        raise ValueError("Unexpected original self-authored CLR test binaries")
    if not validate_original(original):
        raise ValueError("Unverified original installer measurement")
    if (original["installer_status"] not in {"TIMEOUT", "EXIT_CAPTURED"}
            or original["clr64_after"] != "PE_AMD64"
            or original["mscorlib64_after"] != "PE_AMD64"
            or original["native_loader"] != "LOADED"
            or original["managed_functionality"] != "PASS"):
        return blank()
    restart = wineboot_restart(wine, prefix, timeout=120)
    if restart != "COMPLETED":
        return {**blank(), "status": "RESTART_FAILED", "restart": restart}
    disk = snapshot(prefix)
    load = clr_load(wine, prefix, loader)
    managed_default = probe(wine, prefix, managed)
    managed_native = probe(wine, prefix, managed, override="native_only")
    result = {"status": "RESTART_COMPLETED", "restart": "COMPLETED",
              "clr64": disk["CLR64"][0],
              "mscorlib64": disk["MSCORLIB64"][0],
              "native_loader": load,
              "runtime_family": managed_default["clr_family"],
              "managed": managed_default["managed"],
              "native_only_managed": managed_native["managed"],
              "persistent_native_managed": False}
    result["persistent_native_managed"] = (
        result["clr64"] == "PE_AMD64"
        and result["mscorlib64"] == "PE_AMD64"
        and result["native_loader"] == "LOADED"
        and result["runtime_family"] == "MICROSOFT_CLR_CANDIDATE"
        and result["managed"] == "PASS"
        and result["native_only_managed"] == "PASS"
    )
    assert validate(result)
    return result


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Prove real CLR persistence after .NET timeout")
    for key in ("wine", "prefix", "loader", "managed", "original", "output"):
        p.add_argument("--" + key, required=True, type=Path)
    p.add_argument("--agree-disposable-prefix", action="store_true", required=True)
    args = p.parse_args(argv)
    original = json.loads(args.original.read_text(encoding="utf-8"))
    result = inspect(args.wine, args.prefix, args.loader, args.managed, original)
    if not validate(result):
        raise ValueError("Unsafe native CLR persistence report")
    if args.output.is_symlink():
        raise ValueError("Linked output report refused")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, sort_keys=True), encoding="ascii")
    for key in ("status", "restart", "clr64", "mscorlib64", "native_loader",
                "runtime_family", "managed", "native_only_managed",
                "persistent_native_managed"):
        print("Original .NET 4.0 post-timeout restart", key, result[key])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
