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


def blank() -> dict:
    return {
        "status": "NOT_RUN", "installer_authenticode_preverified": False,
        "installer_sha256_verified": False, "extraction": "NOT_STARTED",
        "loader": "NOT_RUN", "selftest": "NOT_RUN",
        "wine_system_process": "NOT_RUN",
        "selftest_process": "NOT_RUN", "original_process": "NOT_RUN",
        "managed_executed": False,
        "runtime_installed": False, "original_payload_artifact": False,
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
            or report["original_process"] not in PROCESSES):
        return False
    for key in ("installer_authenticode_preverified", "installer_sha256_verified",
                "managed_executed", "runtime_installed", "original_payload_artifact"):
        if type(report[key]) is not bool:
            return False
    if any(report[key] for key in ("managed_executed", "runtime_installed",
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
            argument: str, *, original: bool) -> tuple[str, str]:
    env = os.environ.copy()
    env.pop("WINEDLLOVERRIDES", None)
    env.update({"WINEPREFIX": str(prefix), "WINEARCH": "win64",
                "WINEDEBUG": "-all"})
    if original:
        env["WINEDLLOVERRIDES"] = "clr=n"
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


def trial(installer: Path, expected_sha: str, wine: Path, prefix: Path,
          sevenzip: Path, fixture: Path) -> dict:
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
    assert valid(result)
    return result


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Only an isolated original 4.8 CLR native-loader test")
    for name in ("installer", "wine", "prefix", "sevenzip", "fixture", "output"):
        ap.add_argument("--" + name, type=Path, required=True)
    ap.add_argument("--signed-sha256", required=True)
    ap.add_argument("--agree-disposable-prefix", action="store_true", required=True)
    args = ap.parse_args(argv)
    if args.output.is_symlink() or args.output.resolve().is_relative_to(args.prefix.resolve()):
        ap.error("Only an external allowlisted report file")
    report = trial(args.installer, args.signed_sha256, args.wine,
                   args.prefix, args.sevenzip, args.fixture)
    assert valid(report)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, sort_keys=True), encoding="utf-8")
    for key in ("wine_system_process", "selftest", "selftest_process",
                "extraction", "loader",
                "original_process", "managed_executed", "runtime_installed"):
        print("AUTHENTIC_NETFX48_ISOLATED", key, report[key])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
