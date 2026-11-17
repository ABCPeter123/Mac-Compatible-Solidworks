"""Test original Microsoft .NET 4.8 CLR activation over a proven native 4.0 Wine host.

This is a deliberately reversible, disposable-prefix *runtime payload* test,
NOT a .NET 4.8 installation, Release-key spoof, or replacement for servicing.
Only original Windows Authenticode-bound Microsoft 4.8 media may supply files.
All vendor binaries and backups remain private to the runner. The output has
only fixed status categories; no vendor filenames, paths, hashes or logs.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import tempfile

from scripts.netfx40_host_api_diagnostic import (
    STATUS as HOST_STATUSES, execute as host_execute, valid as valid_host,
)
from scripts.netfx40_msxml3_restart import validate as valid_restart
from scripts.netfx48_isolated_loader_trial import (
    extract_clr, verify_original,
)
from scripts.netfx48_signed_mzz_dependency_staging import stage, valid as valid_stage
from scripts.netfx4x_mzz_import_evidence import parse_pe, family
from scripts.netfx481_payload_audit import pe_type
from scripts.netfx481_trial import validate_prefix

STATES = {"NOT_RUN", "BASELINE_FAILED", "EXTRACTION_FAILED",
          "PARTIAL", "MEASURED", "INTERNAL_ERROR"}
SOURCE = {"NOT_RUN", "PE_AMD64", "NO_MZZ", "NO_CLR", "MZZ_ERROR",
          "EXTRACT_FAILED", "INVALID_CLR_PE"}
MAX_STAGE = 16
NAME = re.compile(r"[a-z0-9_.-]{1,90}\.dll\Z")
FRAMEWORK = Path("drive_c/windows/Microsoft.NET/Framework64/v4.0.30319")
CORE = ("mscoreei.dll", "clrjit.dll", "mscorrc.dll", "fusion.dll")


def blank() -> dict:
    return {
        "schema": 1, "status": "NOT_RUN",
        "native40_before": "NOT_RUN", "native40_after": "NOT_RUN",
        "original48_sha256_verified": False,
        "original48_clr": "NOT_RUN",
        "original48_mscorlib_staged": False,
        "original48_core_staged": 0,
        "original48_imports_staged": 0,
        "clr_only": "NOT_RUN",
        "clr_and_mscorlib": "NOT_RUN",
        "additional_core": "NOT_RUN",
        "original40_restored": False,
        "framework48_installed": False,
        "framework481_installed": False,
        "solidworks_compatibility": "NOT_DEMONSTRATED",
    }


def valid(value: object) -> bool:
    if type(value) is not dict or set(value) != set(blank()):
        return False
    if (type(value["schema"]) is not int or value["schema"] != 1
            or value["status"] not in STATES
            or value["original48_clr"] not in SOURCE
            or any(value[k] not in HOST_STATUSES for k in (
                "native40_before", "native40_after", "clr_only",
                "clr_and_mscorlib", "additional_core"))
            or any(type(value[k]) is not bool for k in (
                "original48_sha256_verified", "original48_mscorlib_staged",
                "original40_restored"))
            or type(value["original48_core_staged"]) is not int
            or not 0 <= value["original48_core_staged"] <= len(CORE)
            or type(value["original48_imports_staged"]) is not int
            or not 0 <= value["original48_imports_staged"] <= MAX_STAGE
            or value["framework48_installed"] is not False
            or value["framework481_installed"] is not False
            or value["solidworks_compatibility"] != "NOT_DEMONSTRATED"):
        return False
    if value["status"] == "NOT_RUN":
        return value == blank()
    if value["status"] == "MEASURED":
        return (value["original48_sha256_verified"]
                and value["original48_clr"] == "PE_AMD64"
                and value["native40_before"] == "MANAGED_ORIGINAL_PASS"
                and value["native40_after"] == "MANAGED_ORIGINAL_PASS"
                and value["original40_restored"]
                and value["clr_only"] != "NOT_RUN"
                and value["original48_mscorlib_staged"]
                and value["clr_and_mscorlib"] != "NOT_RUN")
    if value["original40_restored"]:
        return value["native40_after"] == "MANAGED_ORIGINAL_PASS"
    return True


def sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


class ReversibleFramework:
    """Replace a strict allowlist in a marked, throwaway Wine Framework64 tree."""

    def __init__(self, root: Path, private: Path):
        if (root.is_symlink() or not root.is_dir()
                or private.is_symlink() or not private.is_dir()
                or private.resolve().is_relative_to(root.resolve())
                or root.resolve().is_relative_to(private.resolve())):
            raise ValueError("Unsafe runtime replacement boundary")
        self.root = root
        self.private = private
        self.saved: dict[str, Path | None] = {}

    def replace(self, source: Path, name: str) -> None:
        if (not NAME.fullmatch(name) or source.name != name
                or source.is_symlink() or not source.is_file()
                or source.resolve().is_relative_to(self.root.resolve())
                or not 512 <= source.stat().st_size <= 100 * 1024 * 1024):
            raise ValueError("Untrusted original runtime payload")
        with source.open("rb") as stream:
            if pe_type(stream.read(8192)) != "PE_AMD64":
                raise ValueError("Original x64 runtime payload not PE_AMD64")
        target = self.root / name
        if target.is_symlink() or (target.exists() and not target.is_file()):
            raise ValueError("Unsafe original Wine runtime target")
        if name not in self.saved:
            if target.exists():
                backup = self.private / ("saved-" + name)
                if backup.exists() or backup.is_symlink():
                    raise ValueError("Backup collision")
                shutil.copy2(target, backup)
                self.saved[name] = backup
            else:
                self.saved[name] = None
        temporary = self.root / (name + ".swcompat-temporary")
        if temporary.exists() or temporary.is_symlink():
            raise ValueError("Untrusted temporary runtime target")
        try:
            shutil.copy2(source, temporary)
            if sha256(temporary) != sha256(source):
                raise ValueError("Original runtime payload copy mismatch")
            os.replace(temporary, target)
        finally:
            temporary.unlink(missing_ok=True)

    def restore(self) -> None:
        failures = []
        for name, backup in reversed(list(self.saved.items())):
            target = self.root / name
            try:
                if backup is None:
                    target.unlink(missing_ok=True)
                else:
                    temporary = self.root / (name + ".swcompat-restore")
                    if temporary.exists() or temporary.is_symlink():
                        raise ValueError("Untrusted restoration path")
                    try:
                        shutil.copy2(backup, temporary)
                        if sha256(temporary) != sha256(backup):
                            raise ValueError("Restoration digest mismatch")
                        os.replace(temporary, target)
                    finally:
                        temporary.unlink(missing_ok=True)
            except (OSError, ValueError) as exc:
                failures.append(type(exc).__name__)
        if failures:
            raise RuntimeError("Disposable native 4.0 runtime restoration failed")


def _eligible(wine: Path, prefix: Path, sevenzip: Path, fixture: Path,
              managed: Path, installer: Path, restart: dict, host: dict) -> None:
    validate_prefix(prefix)
    if (not valid_restart(restart) or not restart["persistent_native_managed"]
            or restart["native_only_managed"] != "PASS"
            or not valid_host(host) or host["status"] != "MEASURED"
            or not host["native_managed_pass"]):
        raise ValueError("Requires genuine installed .NET 4.0 native host PASS")
    for path in (wine, sevenzip, fixture, managed, installer):
        if path.is_symlink() or not path.is_file():
            raise ValueError("Unsafe native Wine / original media / fixture")
        if path.resolve().is_relative_to(prefix.resolve()):
            raise ValueError("Original media and fixtures must be outside prefix")
    if (not os.access(wine, os.X_OK) or not os.access(sevenzip, os.X_OK)
            or fixture.name != "netfx48_host_activation.exe"
            or managed.name != "netfx48_managed_host_check.dll"):
        raise ValueError("Native host fixture or archive reader mismatch")
    root = prefix / FRAMEWORK
    if root.is_symlink() or not root.is_dir():
        raise ValueError("Original native 4.0 Framework64 tree missing")
    for name in ("clr.dll", "mscorlib.dll"):
        if (root / name).is_symlink() or not (root / name).is_file():
            raise ValueError("Original native 4.0 runtime file missing")


def trial(installer: Path, signed_sha: str, wine: Path, prefix: Path,
          sevenzip: Path, fixture: Path, managed: Path,
          restart: dict, host: dict) -> dict:
    _eligible(wine, prefix, sevenzip, fixture, managed, installer, restart, host)
    # CLI callers supply build-relative fixtures and media. The Wine child
    # runs with cwd=build, while 7-Zip runs in a private temporary directory.
    # Canonicalize every path BEFORE spawning either process, or both tools
    # silently look under the wrong working directory.
    wine = wine.resolve(strict=True)
    prefix = prefix.resolve(strict=True)
    sevenzip = sevenzip.resolve(strict=True)
    fixture = fixture.resolve(strict=True)
    managed = managed.resolve(strict=True)
    installer = installer.resolve(strict=True)
    verify_original(installer, signed_sha)
    result = blank()
    result["original48_sha256_verified"] = True
    result["native40_before"] = host_execute(wine, prefix, fixture, managed, "n")
    if result["native40_before"] != "MANAGED_ORIGINAL_PASS":
        result["status"] = "BASELINE_FAILED"
        assert valid(result)
        return result
    root = prefix / FRAMEWORK
    with tempfile.TemporaryDirectory(prefix="swcompat-authentic48-core-") as td:
        private = Path(td).resolve()
        if private.is_relative_to(prefix.resolve()):
            raise ValueError("Original Microsoft payload staging inside Wine prefix")
        extraction, clr = extract_clr(installer, sevenzip, private)
        result["original48_clr"] = extraction
        if extraction != "PE_AMD64" or clr is None:
            result["status"] = "EXTRACTION_FAILED"
            assert valid(result)
            return result

        # Inspect original CLR imports locally. Never serialize vendor DLL names.
        names: list[str] = []
        imported = parse_pe(clr.read_bytes(), _private_direct_names=names)
        if imported["pe"] != "PE_AMD64" or imported["import_table"] != "READABLE":
            result["status"] = "PARTIAL"
            assert valid(result)
            return result
        optional = sorted(set(name for name in names
                              if NAME.fullmatch(name)
                              and family(name) in {"VCRUNTIME", "OTHER", "MSVC_RUNTIME"}))
        if len(optional) > MAX_STAGE:
            result["status"] = "PARTIAL"
            assert valid(result)
            return result
        if optional:
            deps = stage(private, sevenzip, optional)
            assert valid_stage(deps)
            result["original48_imports_staged"] = deps["staged"]
        mscorlib = stage(private, sevenzip, ["mscorlib.dll"])
        assert valid_stage(mscorlib)
        result["original48_mscorlib_staged"] = mscorlib["staged"] == 1
        core = stage(private, sevenzip, list(CORE))
        assert valid_stage(core)
        result["original48_core_staged"] = core["staged"]

        replacement = ReversibleFramework(root, private)
        try:
            for name in optional:
                path = private / name
                if path.is_file():
                    replacement.replace(path, name)
            replacement.replace(clr, "clr.dll")
            result["clr_only"] = host_execute(wine, prefix, fixture, managed, "n")
            if result["original48_mscorlib_staged"]:
                replacement.replace(private / "mscorlib.dll", "mscorlib.dll")
                result["clr_and_mscorlib"] = host_execute(
                    wine, prefix, fixture, managed, "n")
                if result["original48_core_staged"]:
                    for name in CORE:
                        path = private / name
                        if path.is_file():
                            replacement.replace(path, name)
                    result["additional_core"] = host_execute(
                        wine, prefix, fixture, managed, "n")
        finally:
            replacement.restore()
        result["native40_after"] = host_execute(
            wine, prefix, fixture, managed, "n")
        result["original40_restored"] = (
            result["native40_after"] == "MANAGED_ORIGINAL_PASS")
        result["status"] = ("MEASURED" if result["original40_restored"]
                            and result["original48_mscorlib_staged"]
                            else "PARTIAL")
    assert valid(result)
    return result


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    for key in ("installer", "wine", "prefix", "sevenzip", "fixture",
                "managed", "restart", "host", "output"):
        ap.add_argument("--" + key, type=Path, required=True)
    ap.add_argument("--signed-sha256", required=True)
    ap.add_argument("--agree-disposable-prefix", action="store_true", required=True)
    a = ap.parse_args(argv)
    if (a.output.is_symlink()
            or a.output.resolve().is_relative_to(a.prefix.resolve())):
        ap.error("Original runtime reports must stay outside disposable prefix")
    try:
        result = trial(
            a.installer, a.signed_sha256, a.wine, a.prefix,
            a.sevenzip, a.fixture, a.managed,
            json.loads(a.restart.read_text(encoding="utf-8")),
            json.loads(a.host.read_text(encoding="utf-8")))
        assert valid(result)
    except Exception:
        # No private Microsoft filenames, original paths or Wine output in CI.
        result = blank()
        result["status"] = "INTERNAL_ERROR"
        a.output.parent.mkdir(parents=True, exist_ok=True)
        a.output.write_text(json.dumps(result, sort_keys=True), encoding="ascii")
        print("AUTHENTIC_NETFX48_CORE_HOST INTERNAL_ERROR")
        return 1
    a.output.parent.mkdir(parents=True, exist_ok=True)
    a.output.write_text(json.dumps(result, sort_keys=True), encoding="ascii")
    print("AUTHENTIC_NETFX48_CORE_HOST", result["status"],
          result["native40_before"], result["original48_clr"],
          result["clr_only"], result["clr_and_mscorlib"],
          result["additional_core"], result["native40_after"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
