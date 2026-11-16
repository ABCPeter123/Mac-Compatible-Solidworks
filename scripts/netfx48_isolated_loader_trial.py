"""Bounded isolated LoadLibraryExW of authentic Microsoft .NET 4.8 x64 CLR.

Windows CI authenticates the original Microsoft's signed offline installer
and passes its SHA256 as a same-workflow job output. On Apple Silicon, this
module verifies an independently downloaded identical installer, extracts
only the selected original x64 CLR into a private temp directory outside the
marked disposable Wine prefix, and runs a self-authored Win32 loader probe.
Original Microsoft bytes never leave the runner or become GitHub artifacts.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

from scripts.netfx481_payload_audit import pe_type
from scripts.netfx481_trial import validate_prefix
from scripts.netfx4x_mzz_pe_evidence import matching_names
from scripts.netfx4x_mzz_import_evidence import FAMILIES, MAX_IMPORTS, family, parse_pe
from scripts.netfx48_signed_mzz_dependency_staging import (
    blank as stage_blank, valid as stage_valid, stage as stage_from_mzz,
)

SHA = re.compile(r"[0-9a-fA-F]{64}\Z")
MAX_INSTALLER = 250 * 1024 * 1024
MAX_MZZ = 24
MAX_CLR = 100 * 1024 * 1024
MAX_LIST = 8 * 1024 * 1024
MAX_PROBE = 1200
STATES = {"NOT_RUN", "NOT_FOUND", "LINKED", "LOADED", "MISSING_DEPENDENCY",
          "MISSING_EXPORT", "BAD_IMAGE", "DLL_INIT_FAILED", "ACCESS_DENIED",
          "OTHER_LOAD_FAILURE", "INVALID_ARGUMENT", "TIMEOUT", "PROBE_ERROR"}
EXTRACTIONS = {"NOT_STARTED", "NO_MZZ", "NO_CLR", "MZZ_ERROR", "EXTRACT_FAILED",
               "INVALID_CLR_PE", "PE_AMD64"}
HOST_STATES = {"NOT_RUN", "INVALID_INPUT", "ORIGINAL_MISSING",
               "ORIGINAL_LOAD_FAILED", "ORIGINAL_PATH_MISMATCH", "NO_MSCOREE",
               "NO_HOST_EXPORT", "META_HOST_FAILED", "RUNTIME_DISCOVERY_FAILED",
               "RUNTIME_DIRECTORY_FAILED", "HOST_INTERFACE_FAILED",
               "OTHER_RUNTIME_SELECTED", "HOST_START_FAILED",
               "ORIGINAL_SHIM_INVALID_INPUT", "ORIGINAL_SHIM_MISSING",
               "ORIGINAL_SHIM_LOAD_FAILED", "ORIGINAL_SHIM_NO_HOST_EXPORT",
               "ORIGINAL_SHIM_MISSING_DEPENDENCY", "ORIGINAL_SHIM_MISSING_EXPORT",
               "ORIGINAL_SHIM_BAD_IMAGE", "ORIGINAL_SHIM_INIT_FAILED",
               "ORIGINAL_SHIM_ACCESS_DENIED", "ORIGINAL_SHIM_ONLY_LOADED",
               "MANAGED_FIXTURE_MISSING", "MANAGED_EXECUTION_FAILED",
               "MANAGED_UNEXPECTED_RESULT", "MANAGED_ORIGINAL_PASS",
               "TIMEOUT", "PROBE_ERROR"}
HOST_LINE = re.compile(r"^SWCOMPAT_NETFX48_HOST_(SCHEMA|STATUS)=([A-Z0-9_]+)$")
PROCESSES = {"NOT_RUN", "EXIT_ZERO", "EXIT_1", "EXIT_2", "EXIT_5",
             "EXIT_126", "EXIT_127", "EXIT_193", "EXIT_NONZERO_OTHER",
             "SIGNALLED", "TIMEOUT", "SPAWN_ERROR", "NO_Z_DRIVE"}


def exit_class(code: int) -> str:
    if code == 0:
        return "EXIT_ZERO"
    if code < 0:
        return "SIGNALLED"
    return "EXIT_" + str(code) if code in {1, 2, 5, 126, 127, 193} else "EXIT_NONZERO_OTHER"

LINES = {
    "SCHEMA": {"1"},
    "LOADER": STATES - {"NOT_RUN", "TIMEOUT", "PROBE_ERROR"},
    "MANAGED": {"NOT_TESTED"},
}
LINE = re.compile(r"^SWCOMPAT_NETFX48_ISOLATED_([A-Z]+)=([A-Z0-9_]+)$")


def empty_dependencies() -> dict:
    return {"status": "NOT_RUN", "checked": 0, "loaded": 0, "missing": 0,
            "other": 0, "families": {
                key: {"loaded": 0, "missing": 0, "other": 0} for key in FAMILIES}}


def valid_dependencies(r: object) -> bool:
    if type(r) is not dict or set(r) != set(empty_dependencies()):
        return False
    if r["status"] not in {"NOT_RUN", "SCANNED", "PARTIAL"}:
        return False
    for key in ("checked", "loaded", "missing", "other"):
        if type(r[key]) is not int or not 0 <= r[key] <= MAX_IMPORTS:
            return False
    if r["loaded"] + r["missing"] + r["other"] != r["checked"]:
        return False
    if type(r["families"]) is not dict or set(r["families"]) != set(FAMILIES):
        return False
    for item in r["families"].values():
        if type(item) is not dict or set(item) != {"loaded", "missing", "other"}:
            return False
        if any(type(v) is not int or v < 0 for v in item.values()):
            return False
    if any(sum(i[k] for i in r["families"].values()) != r[k]
           for k in ("loaded", "missing", "other")):
        return False
    return r["status"] != "NOT_RUN" or r == empty_dependencies()


def blank() -> dict:
    return {
        "status": "NOT_RUN", "installer_authenticode_preverified": False,
        "installer_sha256_verified": False, "extraction": "NOT_STARTED",
        "loader": "NOT_RUN", "selftest": "NOT_RUN",
        "wine_system_process": "NOT_RUN",
        "selftest_process": "NOT_RUN", "original_process": "NOT_RUN",
        "managed_executed": False,
        "runtime_installed": False, "original_payload_artifact": False,
        "direct_imports": empty_dependencies(),
        "signed_mzz_staging": stage_blank(),
        "loader_after_mzz": "NOT_RUN",
        "mzz_process": "NOT_RUN",
        "host_stage": "NOT_RUN", "host_process": "NOT_RUN",
        "original_shim_staging": stage_blank(),
        "original_shim_host": "NOT_RUN", "original_shim_process": "NOT_RUN",
        "original_shim_direct_imports": empty_dependencies(),
        "original_shim_dependency_stage": stage_blank(),
        "original_shim_reused": 0,
        "original_shim_retry": "NOT_RUN", "original_shim_retry_process": "NOT_RUN",
        "original_shim_only": "NOT_RUN", "original_shim_only_process": "NOT_RUN",
    }


def valid(report: object) -> bool:
    if type(report) is not dict or set(report) != set(blank()):
        return False
    if (report["status"] not in {"NOT_RUN", "MEASURED", "PARTIAL"}
            or report["extraction"] not in EXTRACTIONS
            or report["loader"] not in STATES
            or report["selftest"] not in STATES
            or report["wine_system_process"] not in PROCESSES
            or report["selftest_process"] not in PROCESSES
            or report["original_process"] not in PROCESSES
            or not valid_dependencies(report["direct_imports"])
            or not stage_valid(report["signed_mzz_staging"])
            or report["loader_after_mzz"] not in STATES
            or report["mzz_process"] not in PROCESSES
            or report["host_stage"] not in HOST_STATES
            or report["host_process"] not in PROCESSES
            or not stage_valid(report["original_shim_staging"])
            or report["original_shim_host"] not in HOST_STATES
            or report["original_shim_process"] not in PROCESSES
            or not valid_dependencies(report["original_shim_direct_imports"])
            or not stage_valid(report["original_shim_dependency_stage"])
            or type(report["original_shim_reused"]) is not int
            or not 0 <= report["original_shim_reused"] <= MAX_IMPORTS
            or report["original_shim_retry"] not in HOST_STATES
            or report["original_shim_retry_process"] not in PROCESSES
            or report["original_shim_only"] not in HOST_STATES
            or report["original_shim_only_process"] not in PROCESSES):
        return False
    if ((report["original_shim_only"] == "NOT_RUN")
            != (report["original_shim_only_process"] == "NOT_RUN")):
        return False
    if (report["original_shim_only"] != "NOT_RUN" and (
            report["original_shim_staging"]["staged"] != 1
            or report["loader_after_mzz"] != "LOADED")):
        return False
    if report["original_shim_only"] == "MANAGED_ORIGINAL_PASS":
        return False
    if report["original_shim_only"] == "ORIGINAL_SHIM_ONLY_LOADED" and (
            report["original_shim_only_process"] != "EXIT_ZERO"):
        return False
    if ((report["original_shim_retry"] == "NOT_RUN")
            != (report["original_shim_retry_process"] == "NOT_RUN")):
        return False
    if report["original_shim_retry"] != "NOT_RUN" and (
            report["original_shim_host"] != "ORIGINAL_SHIM_MISSING_DEPENDENCY"
            or report["original_shim_dependency_stage"]["staged"] < 1
            or report["loader_after_mzz"] != "LOADED"):
        return False
    if report["original_shim_dependency_stage"]["status"] != "NOT_RUN" and (
            report["original_shim_host"] != "ORIGINAL_SHIM_MISSING_DEPENDENCY"):
        return False
    if report["original_shim_direct_imports"]["status"] != "NOT_RUN" and (
            report["original_shim_staging"]["staged"] != 1
            or report["original_shim_host"] != "ORIGINAL_SHIM_MISSING_DEPENDENCY"):
        return False
    if report["original_shim_reused"] > report["original_shim_direct_imports"]["missing"]:
        return False
    if report["original_shim_retry"] == "MANAGED_ORIGINAL_PASS" and (
            report["original_shim_retry_process"] != "EXIT_ZERO"):
        return False
    if report["original_shim_staging"]["missing_requested"] not in {0, 1}:
        return False
    if report["original_shim_staging"]["staged"] > 1:
        return False
    if ((report["original_shim_host"] == "NOT_RUN")
            != (report["original_shim_process"] == "NOT_RUN")):
        return False
    if report["original_shim_host"] != "NOT_RUN" and (
            report["original_shim_staging"]["staged"] != 1
            or report["loader_after_mzz"] != "LOADED"):
        return False
    if report["original_shim_staging"]["status"] != "NOT_RUN" and (
            report["loader_after_mzz"] != "LOADED"):
        return False
    if report["original_shim_host"] == "MANAGED_ORIGINAL_PASS" and (
            report["original_shim_process"] != "EXIT_ZERO"):
        return False
    if report["host_stage"] == "MANAGED_ORIGINAL_PASS" and (
            report["host_process"] != "EXIT_ZERO"):
        return False
    if (report["signed_mzz_staging"]["staged"] == 0
            and report["loader_after_mzz"] != "NOT_RUN"):
        return False
    if (report["loader_after_mzz"] != "NOT_RUN"
            and report["extraction"] != "PE_AMD64"):
        return False
    if (report["loader_after_mzz"] != "NOT_RUN"
            and (report["loader"] not in {"MISSING_DEPENDENCY", "MISSING_EXPORT",
                                          "OTHER_LOAD_FAILURE"}
                 or report["signed_mzz_staging"]["staged"] < 1
                 or report["mzz_process"] == "NOT_RUN")):
        return False
    if (report["loader_after_mzz"] == "NOT_RUN"
            and report["mzz_process"] != "NOT_RUN"):
        return False
    if (report["host_stage"] == "NOT_RUN") != (report["host_process"] == "NOT_RUN"):
        return False
    if (report["host_stage"] != "NOT_RUN"
            and report["loader_after_mzz"] != "LOADED"):
        return False
    if report["managed_executed"] != (
            (report["host_stage"] == "MANAGED_ORIGINAL_PASS"
             and report["host_process"] == "EXIT_ZERO")
            or (report["original_shim_host"] == "MANAGED_ORIGINAL_PASS"
                and report["original_shim_process"] == "EXIT_ZERO")
            or (report["original_shim_retry"] == "MANAGED_ORIGINAL_PASS"
                and report["original_shim_retry_process"] == "EXIT_ZERO")):
        return False
    for key in ("installer_authenticode_preverified", "installer_sha256_verified",
                "managed_executed", "runtime_installed", "original_payload_artifact"):
        if type(report[key]) is not bool:
            return False
    if any(report[key] for key in ("runtime_installed",
                                    "original_payload_artifact")):
        return False
    if report["status"] == "NOT_RUN":
        return report == blank()
    if not (report["installer_authenticode_preverified"]
            and report["installer_sha256_verified"]):
        return False
    if report["selftest"] != "LOADED" and report["loader"] != "NOT_RUN":
        return False
    if report["extraction"] != "PE_AMD64" and report["loader"] != "NOT_RUN":
        return False
    if report["loader"] not in {"NOT_RUN", "TIMEOUT", "PROBE_ERROR"}:
        return report["status"] == "MEASURED" and report["extraction"] == "PE_AMD64"
    return report["status"] == "PARTIAL"


def parse_loader(raw: bytes, exit_code: int) -> str:
    if exit_code != 0 or not 1 <= len(raw) <= MAX_PROBE or b"\x00" in raw:
        return "PROBE_ERROR"
    try:
        lines = raw.decode("ascii").splitlines()
    except UnicodeError:
        return "PROBE_ERROR"
    values = {}
    for line in lines:
        m = LINE.fullmatch(line)
        if not m:
            if line.startswith("SWCOMPAT_NETFX48_ISOLATED_"):
                return "PROBE_ERROR"
            continue
        k, v = m.groups()
        if k not in LINES or v not in LINES[k] or k in values:
            return "PROBE_ERROR"
        values[k] = v
    return values["LOADER"] if set(values) == set(LINES) else "PROBE_ERROR"


def verify_original(installer: Path, expected_sha: str) -> None:
    if (installer.is_symlink() or not installer.is_file()
            or installer.name != "NDP48-x86-x64-AllOS-ENU.exe"
            or not SHA.fullmatch(expected_sha)):
        raise ValueError("Only original Microsoft .NET 4.8 media and trusted digest")
    size = installer.stat().st_size
    if not 15 * 1024 * 1024 <= size <= MAX_INSTALLER:
        raise ValueError("Incorrect original Microsoft installer size")
    digest = hashlib.sha256()
    with installer.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    if digest.hexdigest() != expected_sha.lower():
        raise ValueError("Original Microsoft publisher-authenticated digest mismatch")


def _run_private(argv: list[str], cwd: Path, *, stdout=None, timeout=70) -> int | None:
    try:
        return subprocess.run(
            argv, cwd=cwd, stdin=subprocess.DEVNULL,
            stdout=stdout if stdout is not None else subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, timeout=timeout, check=False,
        ).returncode
    except (OSError, subprocess.TimeoutExpired):
        return None


def extract_clr(installer: Path, sevenzip: Path, private: Path) -> tuple[str, Path | None]:
    archive_dir = private / "archives"
    archive_dir.mkdir()
    code = _run_private(
        [str(sevenzip), "e", "-y", str(installer),
         "-ir!*.mzz", "-o" + str(archive_dir)], private, timeout=115)
    if code is None or code > 1:
        return "MZZ_ERROR", None
    files = list(archive_dir.iterdir())
    if (len(files) > MAX_MZZ or any(x.is_symlink() or not x.is_file() for x in files)):
        return "MZZ_ERROR", None
    archives = [x for x in files if x.suffix.casefold() == ".mzz"]
    if not archives:
        return "NO_MZZ", None
    for archive in archives:
        with tempfile.TemporaryFile() as stdout:
            code = _run_private([str(sevenzip), "l", "-slt", str(archive)],
                                private, stdout=stdout, timeout=70)
            stdout.seek(0)
            raw = stdout.read(MAX_LIST + 1)
        names = matching_names(raw) if code == 0 else {}
        member = names.get("CLR_AMD64")
        if not member:
            continue
        # Named by the strict x64 CLR allowlist. Keep original file private,
        # outside the Wine prefix; no stub DLL or registry spoof is installed.
        target = private / "clr.dll"
        with target.open("xb") as output:
            code = _run_private(
                [str(sevenzip), "e", "-so", str(archive), member],
                private, stdout=output, timeout=90)
        if code != 0:
            return "EXTRACT_FAILED", None
        if not 512 <= target.stat().st_size <= MAX_CLR:
            return "INVALID_CLR_PE", None
        with target.open("rb") as stream:
            if pe_type(stream.read(8192)) != "PE_AMD64":
                return "INVALID_CLR_PE", None
        return "PE_AMD64", target
    return "NO_CLR", None


def _invoke(wine: Path, prefix: Path, fixture: Path,
            argument: str, *, original: bool,
            name_only: bool = False) -> tuple[str, str]:
    env = os.environ.copy()
    env.pop("WINEDLLOVERRIDES", None)
    env.update({"WINEPREFIX": str(prefix), "WINEARCH": "win64",
                "WINEDEBUG": "-all"})
    if original:
        env["WINEDLLOVERRIDES"] = "clr=n"
    if name_only:
        env["SWCOMPAT_LOAD_NAME_ONLY"] = "1"
    else:
        env.pop("SWCOMPAT_LOAD_NAME_ONLY", None)
    env["SWCOMPAT_LOAD_DLL_PATH"] = (
        r"C:\Windows\System32\kernel32.dll" if argument == "--selftest-windows"
        else argument
    )
    # Resolve before changing cwd. Otherwise build/fixture.exe with cwd=build
    # becomes build/build/fixture.exe, which makes Wine fail before the test.
    fixture = fixture.resolve(strict=True)
    with tempfile.TemporaryFile() as out:
        try:
            proc = subprocess.run(
                [str(wine), str(fixture)], cwd=fixture.parent,
                env=env, stdin=subprocess.DEVNULL, stdout=out,
                stderr=subprocess.DEVNULL, timeout=90, check=False)
        except subprocess.TimeoutExpired:
            return "TIMEOUT", "TIMEOUT"
        except OSError:
            return "PROBE_ERROR", "SPAWN_ERROR"
        if proc.returncode != 0:
            return "PROBE_ERROR", exit_class(proc.returncode)
        out.seek(0)
        raw = out.read(MAX_PROBE + 1)
    return parse_loader(raw, 0), "EXIT_ZERO"


def _wine_system_control(wine: Path, prefix: Path) -> str:
    env = os.environ.copy()
    env.pop("WINEDLLOVERRIDES", None)
    env.update({"WINEPREFIX": str(prefix), "WINEARCH": "win64", "WINEDEBUG": "-all"})
    try:
        proc = subprocess.run(
            [str(wine), "cmd.exe", "/c", "ver"], cwd=prefix, env=env,
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, timeout=35, check=False)
        return exit_class(proc.returncode)
    except subprocess.TimeoutExpired:
        return "TIMEOUT"
    except OSError:
        return "SPAWN_ERROR"


def _load(wine: Path, prefix: Path, fixture: Path,
          original: Path) -> tuple[str, str]:
    z = prefix / "dosdevices" / "z:"
    if not z.is_symlink() or z.resolve() != Path("/"):
        return "PROBE_ERROR", "NO_Z_DRIVE"
    windows_path = "Z:" + str(original.resolve(strict=True)).replace("/", "\\\\")
    return _invoke(wine, prefix, fixture, windows_path, original=True)


def direct_import_check(wine: Path, prefix: Path, fixture: Path,
                        original: Path,
                        _private_missing: list[str] | None = None) -> dict:
    """The exact original names stay in private memory and are never reported."""
    report = empty_dependencies()
    if _private_missing is not None:
        _private_missing.clear()
    if not 512 <= original.stat().st_size <= MAX_CLR:
        report["status"] = "PARTIAL"
        return report
    names: list[str] = []
    pe = parse_pe(original.read_bytes(), _private_direct_names=names)
    if (pe["pe"] != "PE_AMD64" or pe["import_table"] != "READABLE"
            or not 1 <= len(names) <= MAX_IMPORTS
            or len(names) != pe["import_count"]):
        report["status"] = "PARTIAL"
        return report
    report["status"] = "SCANNED"
    for name in names:
        outcome, process = _invoke(
            wine, prefix, fixture, name, original=False, name_only=True)
        bucket = ("loaded" if outcome == "LOADED" and process == "EXIT_ZERO"
                  else "missing" if outcome in {"MISSING_DEPENDENCY", "NOT_FOUND"}
                      and process == "EXIT_ZERO" else "other")
        report["checked"] += 1
        report[bucket] += 1
        report["families"][family(name)][bucket] += 1
        if bucket == "missing" and _private_missing is not None:
            _private_missing.append(name)
        if bucket == "other":
            report["status"] = "PARTIAL"
    assert valid_dependencies(report)
    return report



def parse_host(raw: bytes, exit_code: int) -> str:
    """An allowlisted, bounded read of the self-authored Win32 host fixture."""
    if exit_code != 0 or not 1 <= len(raw) <= MAX_PROBE or b"\x00" in raw:
        return "PROBE_ERROR"
    try:
        lines = raw.decode("ascii").splitlines()
    except UnicodeError:
        return "PROBE_ERROR"
    fields: dict[str, str] = {}
    for line in lines:
        m = HOST_LINE.fullmatch(line)
        if m is not None:
            key, value = m.groups()
            if key in fields or (key == "SCHEMA" and value != "1") or (
                    key == "STATUS" and value not in HOST_STATES - {
                        "NOT_RUN", "TIMEOUT", "PROBE_ERROR"}):
                return "PROBE_ERROR"
            fields[key] = value
        elif line.startswith("SWCOMPAT_NETFX48_HOST_"):
            return "PROBE_ERROR"
    return fields["STATUS"] if set(fields) == {"SCHEMA", "STATUS"} else "PROBE_ERROR"


def host_check(wine: Path, prefix: Path, host_fixture: Path,
               managed_fixture: Path, original: Path,
               original_shim: Path | None = None,
               shim_only: bool = False) -> tuple[str, str]:
    """Isolated hosting: no framework registration and no Mono success accepted."""
    z = prefix / "dosdevices" / "z:"
    if not z.is_symlink() or z.resolve() != Path("/"):
        return "PROBE_ERROR", "NO_Z_DRIVE"
    env = os.environ.copy()
    env.pop("WINEDLLOVERRIDES", None)
    env.update({"WINEPREFIX": str(prefix), "WINEARCH": "win64",
                "WINEDEBUG": "-all", "WINEDLLOVERRIDES": "clr=n",
                "SWCOMPAT_CLR_PATH": "Z:" + str(original.resolve(strict=True)).replace("/", "\\"),
                "SWCOMPAT_MANAGED_DLL": "Z:" + str(managed_fixture.resolve(strict=True)).replace("/", "\\")})
    if shim_only and original_shim is None:
        raise ValueError("Original Microsoft shim required for native-only differential")
    if shim_only:
        env["SWCOMPAT_SHIM_ONLY"] = "1"
    else:
        env.pop("SWCOMPAT_SHIM_ONLY", None)
    if original_shim is not None:
        if original_shim.name != "mscoreei.dll" or original_shim.is_symlink():
            raise ValueError("Only original Microsoft signed-package host shim")
        env["SWCOMPAT_ORIGINAL_SHIM_PATH"] = (
            "Z:" + str(original_shim.resolve(strict=True)).replace("/", "\\"))
    else:
        env.pop("SWCOMPAT_ORIGINAL_SHIM_PATH", None)
    host_fixture = host_fixture.resolve(strict=True)
    with tempfile.TemporaryFile() as output:
        try:
            proc = subprocess.run(
                [str(wine), str(host_fixture)], cwd=host_fixture.parent,
                stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.DEVNULL,
                env=env, timeout=90, check=False)
        except subprocess.TimeoutExpired:
            return "TIMEOUT", "TIMEOUT"
        except OSError:
            return "PROBE_ERROR", "SPAWN_ERROR"
        if proc.returncode:
            return "PROBE_ERROR", exit_class(proc.returncode)
        output.seek(0)
        raw = output.read(MAX_PROBE + 1)
    return parse_host(raw, 0), "EXIT_ZERO"


def trial(installer: Path, expected_sha: str, wine: Path, prefix: Path,
          sevenzip: Path, fixture: Path, host_fixture: Path | None = None,
          managed_fixture: Path | None = None) -> dict:
    validate_prefix(prefix)
    wine = wine.resolve(strict=True)
    sevenzip = sevenzip.resolve(strict=True)
    if (not wine.is_file() or not os.access(wine, os.X_OK)
            or not sevenzip.is_file() or not os.access(sevenzip, os.X_OK)
            or fixture.is_symlink() or not fixture.is_file()
            or fixture.name != "netfx48_isolated_loader.exe"
            or installer.resolve().is_relative_to(prefix.resolve())
            or fixture.resolve().is_relative_to(prefix.resolve())):
        raise ValueError("Invalid original media / independent Wine loader fixture")
    if (host_fixture is None) != (managed_fixture is None):
        raise ValueError("Both independent host fixtures required together")
    if host_fixture is not None and (
            host_fixture.is_symlink() or not host_fixture.is_file()
            or host_fixture.name != "netfx48_host_activation.exe"
            or managed_fixture is None or managed_fixture.is_symlink()
            or not managed_fixture.is_file()
            or managed_fixture.name != "netfx48_managed_host_check.dll"
            or host_fixture.resolve().is_relative_to(prefix.resolve())
            or managed_fixture.resolve().is_relative_to(prefix.resolve())):
        raise ValueError("Unsafe independent CLR host fixture")
    verify_original(installer, expected_sha)
    result = blank()
    result["status"] = "PARTIAL"
    result["installer_authenticode_preverified"] = True
    result["installer_sha256_verified"] = True
    result["wine_system_process"] = _wine_system_control(wine, prefix)
    if result["wine_system_process"] != "EXIT_ZERO":
        assert valid(result)
        return result
    result["selftest"], result["selftest_process"] = _invoke(
        wine, prefix, fixture, "--selftest-windows", original=False)
    if result["selftest"] != "LOADED":
        assert valid(result)
        return result
    with tempfile.TemporaryDirectory(prefix="swcompat-original-netfx48-") as private_name:
        private = Path(private_name).resolve()
        if private.is_relative_to(prefix.resolve()):
            raise ValueError("Original Microsoft CLR must remain outside Wine prefix")
        extraction, original = extract_clr(installer, sevenzip, private)
        result["extraction"] = extraction
        if extraction == "PE_AMD64" and original is not None:
            result["loader"], result["original_process"] = _load(
                wine, prefix, fixture, original)
            if result["loader"] not in {"TIMEOUT", "PROBE_ERROR"}:
                result["status"] = "MEASURED"
            missing_names: list[str] = []
            result["direct_imports"] = direct_import_check(
                wine, prefix, fixture, original, _private_missing=missing_names)
            if missing_names and result["loader"] == "MISSING_DEPENDENCY":
                result["signed_mzz_staging"] = stage_from_mzz(
                    private, sevenzip, missing_names)
                if result["signed_mzz_staging"]["staged"] > 0:
                    result["loader_after_mzz"], result["mzz_process"] = _load(
                        wine, prefix, fixture, original)
                    if (result["loader_after_mzz"] == "LOADED"
                            and host_fixture is not None and managed_fixture is not None):
                        result["host_stage"], result["host_process"] = host_check(
                            wine, prefix, host_fixture, managed_fixture, original)
                        # Compare the Wine-provided mscoree against the original
                        # Microsoft shim from the independently signed MZZ.
                        # No manual framework installation or registry spoofing.
                        result["original_shim_staging"] = stage_from_mzz(
                            private, sevenzip, ["mscoreei.dll"])
                        if result["original_shim_staging"]["staged"] == 1:
                            shim_path = private / "mscoreei.dll"
                            result["original_shim_only"], result["original_shim_only_process"] = host_check(
                                wine, prefix, host_fixture, managed_fixture, original,
                                original_shim=shim_path, shim_only=True)
                            result["original_shim_host"], result["original_shim_process"] = host_check(
                                wine, prefix, host_fixture, managed_fixture,
                                original, original_shim=shim_path)
                            if result["original_shim_host"] == "ORIGINAL_SHIM_MISSING_DEPENDENCY":
                                shim_missing: list[str] = []
                                result["original_shim_direct_imports"] = direct_import_check(
                                    wine, prefix, fixture, shim_path,
                                    _private_missing=shim_missing)
                                genuinely_missing = []
                                for dep in shim_missing:
                                    existing = private / dep
                                    previously_staged = False
                                    if (existing.is_file() and not existing.is_symlink()
                                            and 512 <= existing.stat().st_size <= MAX_CLR):
                                        with existing.open("rb") as native_stream:
                                            previously_staged = (
                                                pe_type(native_stream.read(8192)) == "PE_AMD64")
                                    if previously_staged:
                                        result["original_shim_reused"] += 1
                                    else:
                                        genuinely_missing.append(dep)
                                if genuinely_missing:
                                    result["original_shim_dependency_stage"] = stage_from_mzz(
                                        private, sevenzip, genuinely_missing)
                                    if result["original_shim_dependency_stage"]["staged"] > 0:
                                        result["original_shim_retry"], result["original_shim_retry_process"] = host_check(
                                            wine, prefix, host_fixture, managed_fixture,
                                            original, original_shim=shim_path)
                        result["managed_executed"] = (
                            (result["host_stage"] == "MANAGED_ORIGINAL_PASS"
                             and result["host_process"] == "EXIT_ZERO")
                            or (result["original_shim_host"] == "MANAGED_ORIGINAL_PASS"
                                and result["original_shim_process"] == "EXIT_ZERO")
                            or (result["original_shim_retry"] == "MANAGED_ORIGINAL_PASS"
                                and result["original_shim_retry_process"] == "EXIT_ZERO"))
    assert valid(result)
    return result


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Only an isolated original 4.8 CLR native-loader test")
    for name in ("installer", "wine", "prefix", "sevenzip", "fixture", "output"):
        ap.add_argument("--" + name, type=Path, required=True)
    ap.add_argument("--host-fixture", type=Path)
    ap.add_argument("--managed-fixture", type=Path)
    ap.add_argument("--signed-sha256", required=True)
    ap.add_argument("--agree-disposable-prefix", action="store_true", required=True)
    args = ap.parse_args(argv)
    if args.output.is_symlink() or args.output.resolve().is_relative_to(args.prefix.resolve()):
        ap.error("Only an external allowlisted report file")
    report = trial(args.installer, args.signed_sha256, args.wine,
                   args.prefix, args.sevenzip, args.fixture,
                   args.host_fixture, args.managed_fixture)
    assert valid(report)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, sort_keys=True), encoding="utf-8")
    for key in ("wine_system_process", "selftest", "selftest_process",
                "extraction", "loader",
                "original_process", "managed_executed", "runtime_installed"):
        print("AUTHENTIC_NETFX48_ISOLATED", key, report[key])
    print("AUTHENTIC_NETFX48_HOST", report["host_stage"],
          report["host_process"], report["managed_executed"])
    shim = report["original_shim_staging"]
    print("AUTHENTIC_NETFX48_ORIGINAL_SHIM",
          shim["status"], shim["located"], shim["staged"],
          report["original_shim_host"], report["original_shim_process"])
    shim_imports = report["original_shim_direct_imports"]
    print("AUTHENTIC_NETFX48_ORIGINAL_SHIM_IMPORTS",
          shim_imports["status"], shim_imports["checked"],
          shim_imports["loaded"], shim_imports["missing"],
          shim_imports["other"], report["original_shim_reused"])
    for family_name in FAMILIES:
        category = shim_imports["families"][family_name]
        if sum(category.values()):
            print("AUTHENTIC_NETFX48_ORIGINAL_SHIM_IMPORT_FAMILY", family_name,
                  category["loaded"], category["missing"], category["other"])
    repair = report["original_shim_dependency_stage"]
    print("AUTHENTIC_NETFX48_ORIGINAL_SHIM_DEP_STAGE",
          repair["status"], repair["missing_requested"],
          repair["located"], repair["staged"])
    print("AUTHENTIC_NETFX48_ORIGINAL_SHIM_RETRY",
          report["original_shim_retry"], report["original_shim_retry_process"])
    print("AUTHENTIC_NETFX48_ORIGINAL_SHIM_NATIVE_ONLY",
          report["original_shim_only"], report["original_shim_only_process"])
    staging = report["signed_mzz_staging"]
    print("AUTHENTIC_NETFX48_MZZ_STAGE", staging["status"],
          staging["missing_requested"], staging["located"], staging["staged"])
    print("AUTHENTIC_NETFX48_MZZ_RELOAD",
          report["loader_after_mzz"], report["mzz_process"])
    for family_name in FAMILIES:
        values = staging["families"][family_name]
        if values["located"]:
            print("AUTHENTIC_NETFX48_MZZ_FAMILY", family_name,
                  values["located"], values["staged"])
    dep = report["direct_imports"]
    print("AUTHENTIC_NETFX48_DIRECT", dep["status"],
          dep["checked"], dep["loaded"], dep["missing"], dep["other"])
    for key in FAMILIES:
        item = dep["families"][key]
        if sum(item.values()):
            print("AUTHENTIC_NETFX48_IMPORT_FAMILY", key,
                  item["loaded"], item["missing"], item["other"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
