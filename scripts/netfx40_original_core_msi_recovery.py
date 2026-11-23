"""Try unmodified original Microsoft .NET 4.0 x64 Core MSI after setup 1603.

This deliberately tests one narrow alternative to the .NET 4 bootstrapper:
a fully authenticated Microsoft EXE has already been run for setup and /x
offline extraction in the *same disposable Wine prefix*. Only after a
measured 1603 with zero native CLR files may we invoke its original
netfx_Core_x64.msi directly, with its original adjacent netfx_Core.mzz.
It is NOT a full .NET 4 install or proof of SOLIDWORKS compatibility.
No signed original MSI or cabinet is patched, re-signed or uploaded.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from scripts.netfx40_legacy import verify_media, validate as valid_legacy
from scripts.netfx40_msxml3_restart import validate as valid_restart
from scripts.netfx40_msi_evidence import (
    classify_msi_log, ACTION_CLASSES, ERROR_CLASSES, MAX_FILE_BYTES,
)
from scripts.netfx40_offline_extract import (
    EXTRACT_FOLDER, OLE_SIGNATURE, validate as valid_extract,
)
from scripts.netfx40_to_48_signed_msi import private_run
from scripts.netfx481_payload_audit import snapshot
from scripts.netfx481_trial import probe, wineboot_restart, validate_prefix
from scripts.netfx481_clr_load import run as load_clr
from swcompat.wine_paths import windows_media_path

STATES = {"NOT_RUN", "MEASURED", "SKIPPED_ALREADY_NATIVE",
          "SKIPPED_NOT_1603", "BLOCKED_MEDIA"}
MEDIA = {"NOT_RUN", "VERIFIED_EXTRACTED_CORE", "NOT_FOUND", "MULTIPLE",
         "BAD_OLE", "COMPANION_MISSING", "UNSAFE", "SCAN_LIMIT",
         "SCAN_DEPTH_LIMIT", "SCAN_DIR_LIMIT", "SCAN_FILE_LIMIT",
         "SCAN_BRANCH_LIMIT"}
INSTALL = {"NOT_RUN", "SUCCESS", "EXIT_NONZERO", "START_FAILED",
           "TIMED_OUT", "TIMED_OUT_CLEANUP_DENIED"}
RESTART = {"NOT_RUN", "COMPLETED", "TIMED_OUT", "EXIT_NONZERO", "START_FAILED"}
LOADER = {"NOT_RUN", "NOT_REQUESTED", "NOT_FOUND", "LINKED",
          "LOAD_FAILED", "LOADED", "NOT_VERIFIED"}
MANAGED = {"NOT_RUN", "PASS", "FAIL", "NOT_VERIFIED"}
TIMEOUT = 420
# The authentic /x result has already reported 17 directories, 74 files,
# and a partial scan with the older 4-level census. A recovery probe must
# search that genuine tree rather than reject it because its diagnostic
# limits were tighter than the Microsoft extractor's layout.
# Keep finite, explicit caps with no symlink traversal or original filenames
# in public reports. This does not lower any original media validation.
MAX_DIRS = 128
MAX_FILES = 1024
MAX_DEPTH = 12
MAX_BRANCH = 48
MAX_MSI = 200 * 1024 * 1024
LOG_NAME = "msi0c0e.log"
LOG_WINDOWS = r"C:\swcompat-netfx40-original-extract\msi0c0e.log"
LOG_STATES = {"NOT_RUN", "NO_LOG", "SCANNED", "TRUNCATED", "UNREADABLE", "UNSAFE"}


def blank_log() -> dict:
    return {"status": "NOT_RUN", "action": "UNKNOWN", "errors": []}


def valid_log(value: object) -> bool:
    return (
        type(value) is dict and set(value) == {"status", "action", "errors"}
        and value["status"] in LOG_STATES and value["action"] in ACTION_CLASSES
        and type(value["errors"]) is list
        and value["errors"] == sorted(set(value["errors"]))
        and all(type(x) is str and x in ERROR_CLASSES for x in value["errors"])
        and (value["status"] == "SCANNED"
             or value["action"] == "UNKNOWN" and value["errors"] == [])
    )


def private_log(prefix: Path) -> dict:
    """Original MSI log never appears outside local disposable Wine prefix."""
    root = prefix / "drive_c" / EXTRACT_FOLDER
    path = root / LOG_NAME
    if root.is_symlink() or path.is_symlink():
        return blank_log() | {"status": "UNSAFE"}
    if not path.exists():
        return blank_log() | {"status": "NO_LOG"}
    if not path.is_file():
        return blank_log() | {"status": "UNSAFE"}
    try:
        size = path.stat().st_size
        if size > MAX_FILE_BYTES:
            return blank_log() | {"status": "TRUNCATED"}
        with path.open("rb") as inp:
            raw = inp.read(MAX_FILE_BYTES + 1)
        if len(raw) > MAX_FILE_BYTES:
            return blank_log() | {"status": "TRUNCATED"}
        evidence = classify_msi_log(raw)
    except OSError:
        return blank_log() | {"status": "UNREADABLE"}
    if not evidence["readable"]:
        return blank_log() | {"status": "UNREADABLE"}
    result = {"status": "SCANNED", "action": evidence["action"],
              "errors": evidence["errors"]}
    assert valid_log(result)
    return result



def blank() -> dict:
    return {
        "status": "NOT_RUN", "media": "NOT_RUN", "install": "NOT_RUN",
        "msi_log": blank_log(),
        "restart": "NOT_RUN", "clr64_added": False, "loader": "NOT_RUN",
        "native_only_managed": "NOT_RUN", "core_msi_candidate": False,
        "framework40_installed": False, "framework48_installed": False,
        "solidworks_compatibility": "NOT_DEMONSTRATED",
    }


def valid(r: object) -> bool:
    if type(r) is not dict or set(r) != set(blank()):
        return False
    if (not valid_log(r["msi_log"])
            or r["status"] not in STATES or r["media"] not in MEDIA
            or r["install"] not in INSTALL or r["restart"] not in RESTART
            or r["loader"] not in LOADER
            or r["native_only_managed"] not in MANAGED
            or any(type(r[k]) is not bool for k in (
                "clr64_added", "core_msi_candidate", "framework40_installed",
                "framework48_installed"))
            or r["framework40_installed"] or r["framework48_installed"]
            or r["solidworks_compatibility"] != "NOT_DEMONSTRATED"):
        return False
    if r["status"] == "NOT_RUN":
        return r == blank()
    if r["status"] != "MEASURED":
        return (r["msi_log"] == blank_log()
                and r["install"] == r["restart"] == "NOT_RUN"
                and r["loader"] == r["native_only_managed"] == "NOT_RUN"
                and not r["clr64_added"] and not r["core_msi_candidate"]
                and (r["media"] == "NOT_RUN" if r["status"] in {
                    "SKIPPED_ALREADY_NATIVE", "SKIPPED_NOT_1603"}
                     else r["media"] not in {"NOT_RUN", "VERIFIED_EXTRACTED_CORE"}))
    if r["media"] != "VERIFIED_EXTRACTED_CORE" or r["install"] == "NOT_RUN":
        return False
    if r["install"] == "TIMED_OUT_CLEANUP_DENIED":
        return (r["msi_log"] == blank_log()
                and r["restart"] == r["loader"] == r["native_only_managed"] == "NOT_RUN"
                and not r["clr64_added"] and not r["core_msi_candidate"])
    expected = (
        r["install"] == "SUCCESS" and r["restart"] == "COMPLETED"
        and r["clr64_added"] and r["loader"] == "LOADED"
        and r["native_only_managed"] == "PASS"
    )
    return (r["core_msi_candidate"] is expected
            and (r["restart"] == "NOT_RUN" or r["restart"] in RESTART))


def _bound_prefix(prefix: Path) -> None:
    validate_prefix(prefix)
    root = os.environ.get("RUNNER_TEMP")
    if (not root or Path(root).is_symlink()
            or prefix.is_symlink() or prefix.name != "netfx40-msxml3-prefix"
            or prefix.parent.resolve() != Path(root).resolve()):
        raise ValueError("Authentic core MSI control requires marked ephemeral CI prefix")


def _original_core(prefix: Path) -> tuple[Path | None, str]:
    root = prefix / "drive_c" / EXTRACT_FOLDER
    if root.is_symlink() or not root.is_dir():
        return None, "UNSAFE"
    found: list[Path] = []
    count_dirs = count_files = 0
    for parent, dirs, names in os.walk(root, followlinks=False):
        count_dirs += 1
        if count_dirs > MAX_DIRS:
            return None, "SCAN_DIR_LIMIT"
        here = Path(parent)
        if here.is_symlink():
            return None, "UNSAFE"
        if len(here.relative_to(root).parts) >= MAX_DEPTH:
            if dirs:
                return None, "SCAN_DEPTH_LIMIT"
            dirs.clear()
        else:
            if len(dirs) > MAX_BRANCH:
                return None, "SCAN_BRANCH_LIMIT"
            if any((here / n).is_symlink() for n in dirs):
                return None, "UNSAFE"
            dirs.sort()
        for name in sorted(names):
            count_files += 1
            if count_files > MAX_FILES:
                return None, "SCAN_FILE_LIMIT"
            if name.casefold() != "netfx_core_x64.msi":
                continue
            candidate = here / name
            if candidate.is_symlink() or not candidate.is_file():
                return None, "UNSAFE"
            found.append(candidate)
            if len(found) > 1:
                return None, "MULTIPLE"
    if not found:
        return None, "NOT_FOUND"
    core = found[0]
    try:
        if not 4096 <= core.stat().st_size <= MAX_MSI:
            return None, "BAD_OLE"
        with core.open("rb") as stream:
            if stream.read(8) != OLE_SIGNATURE:
                return None, "BAD_OLE"
    except OSError:
        return None, "UNSAFE"
    # Use the *unmodified* original cabinet, not an MSI copied out of
    # context or a made-up repair package.
    companions = [x for x in core.parent.iterdir()
                  if x.name.casefold() == "netfx_core.mzz"]
    if len(companions) != 1:
        return None, "COMPANION_MISSING"
    companion = companions[0]
    if (companion.is_symlink() or not companion.is_file()
            or not 128 * 1024 <= companion.stat().st_size <= MAX_MSI):
        return None, "UNSAFE"
    return core, "VERIFIED_EXTRACTED_CORE"


def inspect(wine: Path, prefix: Path, original: Path, core_extract: dict,
            original_setup: dict, restart40: dict, managed: Path,
            loader: Path) -> dict:
    if (os.name == "nt" or wine.is_symlink() or original.is_symlink()
            or any(p.is_symlink() for p in (managed, loader, prefix))):
        raise ValueError("Untrusted genuine Microsoft native MSI experiment")
    _bound_prefix(prefix)
    verify_media(original)
    if not (valid_legacy(original_setup) and valid_extract(core_extract)
            and valid_restart(restart40)):
        raise ValueError("Original Microsoft setup and /x evidence must validate")
    if not wine.is_file() or not os.access(wine, os.X_OK):
        raise ValueError("Expected executable Wine binary")
    if (managed.name != "netfx481_runtime_probe.exe"
            or loader.name != "netfx481_clr_load.exe"
            or not managed.is_file() or not loader.is_file()):
        raise ValueError("Only recognized self-authored CLR probes permitted")
    if restart40["persistent_native_managed"]:
        return {**blank(), "status": "SKIPPED_ALREADY_NATIVE"}
    if (original_setup["installer_status"] != "EXIT_CAPTURED"
            or original_setup["installer_exit"] != "MSI_FATAL_ERROR"
            or original_setup["installer_exit_hex"] != "00000643"
            or original_setup["clr64_after"] != "ABSENT"
            or restart40["status"] != "NOT_ELIGIBLE"):
        return {**blank(), "status": "SKIPPED_NOT_1603"}
    if (core_extract["process"] != "ZERO"
            or not core_extract["core_x64_ole_candidate"]):
        return {**blank(), "status": "BLOCKED_MEDIA", "media": "NOT_FOUND"}

    core, media = _original_core(prefix)
    if core is None:
        return {**blank(), "status": "BLOCKED_MEDIA", "media": media}

    # Confirm unmodified Microsoft MSI on the exact disk state observed
    # after setup 1603. Do not override Wine registration or fabricate CLR.
    before = snapshot(prefix)
    if before["CLR64"][0] != "ABSENT":
        return {**blank(), "status": "SKIPPED_ALREADY_NATIVE"}
    windows_core = windows_media_path(wine, prefix, core)
    env = os.environ.copy()
    env.update({
        "WINEPREFIX": str(prefix), "WINEARCH": "win64",
        "WINEDEBUG": "-all", "WINEDLLOVERRIDES": "fusion=b",
    })
    # The original MSI executable and package are untouched; the isolated
    # output file and all original logs stay inside the runner's prefix.
    install = private_run(
        [str(wine), "msiexec.exe", "/i", windows_core,
         "/qn", "/norestart", "EXTUI=1", "/L*v", LOG_WINDOWS],
        env, prefix, TIMEOUT,
    )
    result = {**blank(), "status": "MEASURED",
              "media": "VERIFIED_EXTRACTED_CORE", "install": install}
    if install == "TIMED_OUT_CLEANUP_DENIED":
        assert valid(result)
        return result
    result["msi_log"] = private_log(prefix)
    after = snapshot(prefix)
    result["clr64_added"] = (before["CLR64"][0] == "ABSENT"
                             and after["CLR64"][0] == "PE_AMD64")
    if result["clr64_added"]:
        result["restart"] = wineboot_restart(wine, prefix, timeout=100)
        if result["restart"] == "COMPLETED":
            result["loader"] = load_clr(wine, prefix, loader)
            execution = probe(wine, prefix, managed, override="native_only")
            result["native_only_managed"] = (
                "PASS" if execution["managed"] == "PASS"
                and execution["clr_family"] == "MICROSOFT_CLR_CANDIDATE"
                else "FAIL")
    result["core_msi_candidate"] = (
        result["install"] == "SUCCESS" and result["clr64_added"]
        and result["restart"] == "COMPLETED"
        and result["loader"] == "LOADED"
        and result["native_only_managed"] == "PASS"
    )
    assert valid(result)
    return result


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Unmodified .NET4 original x64 core MSI after 1603")
    for name in ("wine", "prefix", "original", "original-extract",
                 "original-setup", "original-restart", "managed", "loader", "output"):
        p.add_argument("--" + name, required=True, type=Path)
    p.add_argument("--agree-disposable-prefix", action="store_true", required=True)
    args = p.parse_args(argv)
    if args.output.is_symlink() or args.output.resolve().is_relative_to(args.prefix.resolve()):
        p.error("Original MSI recovery report must remain outside Wine prefix")
    result = inspect(
        args.wine, args.prefix, args.original,
        json.loads(args.original_extract.read_text(encoding="ascii")),
        json.loads(args.original_setup.read_text(encoding="ascii")),
        json.loads(args.original_restart.read_text(encoding="ascii")),
        args.managed, args.loader,
    )
    if not valid(result):
        raise ValueError("Unverifiable original Microsoft .NET4 core MSI trial")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, sort_keys=True), encoding="ascii")
    for key, value in result.items():
        print("Authentic original .NET4 x64 core MSI recovery", key, value)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
