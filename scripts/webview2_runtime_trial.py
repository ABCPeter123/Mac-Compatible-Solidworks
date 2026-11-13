"""Opt-in WebView2 Evergreen installer trial in a disposable Wine prefix.

Never install on a native Windows machine or a user's existing Wine prefix.
The script requires a prefix-specific sentinel, the original Windows
controller probe, and a SHA-256 manifest for the official Microsoft installer.
Only bounded, allowlisted diagnostic results are exported. No installer stdout,
user paths, license data, or browser versions are included in the JSON report.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import tempfile
import time

from scripts.webview2_controller_report import MAX_BYTES, summarize as probe_summary

SENTINEL = ".swcompat-webview2-disposable"
MAX_INSTALLER_BYTES = 450 * 1024 * 1024
MIN_INSTALLER_BYTES = 8 * 1024 * 1024
DIGEST = re.compile(r"[0-9a-fA-F]{64}\Z")
TERMINATIONS = {"EXIT_ZERO", "EXIT_NONZERO", "TIMEOUT", "PROCESS_ERROR"}


def verify_installer(installer: Path, sha256_file: Path) -> str:
    """Verify complete file digest before ever executing the installer."""
    digest = sha256_file.read_text(encoding="ascii").strip()
    if not DIGEST.fullmatch(digest):
        raise ValueError("Expected a single SHA-256 digest in the manifest")
    if not installer.is_file() or installer.suffix.lower() != ".exe":
        raise ValueError("Missing Windows Evergreen runtime .exe")
    size = installer.stat().st_size
    if not MIN_INSTALLER_BYTES <= size <= MAX_INSTALLER_BYTES:
        raise ValueError("Installer outside expected standalone runtime size bounds")
    h = hashlib.sha256()
    with installer.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    if h.hexdigest().lower() != digest.lower():
        raise ValueError("WebView2 runtime installer SHA-256 mismatch")
    return digest.lower()


def validate_prefix(prefix: Path) -> None:
    if not (prefix / SENTINEL).is_file():
        raise ValueError("Refusing install outside a marked disposable Wine prefix")
    if not (prefix / "drive_c").is_dir() or not (prefix / "system.reg").is_file():
        raise ValueError("Wine prefix is not initialized")


def wine_environment(prefix: Path) -> dict[str, str]:
    env = os.environ.copy()
    env.update({"WINEPREFIX": str(prefix), "WINEARCH": "win64", "WINEDEBUG": "-all"})
    return env


def probe(wine: Path, exe: Path, env: dict[str, str], timeout_seconds: int = 75) -> dict:
    """Capture raw output only to an automatically removed local temporary file."""
    with tempfile.TemporaryFile() as log:
        try:
            run = subprocess.run(
                [str(wine), str(exe)], cwd=exe.parent, env=env,
                stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
                timeout=timeout_seconds, check=False,
            )
            returncode = run.returncode
        except (subprocess.TimeoutExpired, OSError):
            returncode = 124
        log.seek(0)
        raw = log.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        return probe_summary("", 1)
    return probe_summary(raw.decode("utf-8", errors="replace"), returncode)


def run_installer(
    wine: Path, installer: Path, env: dict[str, str], timeout_seconds: int
) -> tuple[str, int | None]:
    """Install only inside explicitly selected WINEPREFIX; never retain raw logs."""
    try:
        proc = subprocess.Popen(
            [str(wine), str(installer), "/silent", "/install"],
            cwd=installer.parent, env=env, stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
    except OSError:
        return "PROCESS_ERROR", None
    try:
        code = proc.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        # Terminate only the installer's process group, never the user's prefix.
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (OSError, AttributeError):
            proc.kill()
        proc.wait()
        return "TIMEOUT", None
    return ("EXIT_ZERO" if code == 0 else "EXIT_NONZERO"), code


def snapshot(report: dict) -> dict:
    return {
        "probe_result": report["probe_result"],
        "runtime_discovery": report["runtime_discovery"],
        "environment_creation": report["environment_creation"],
        "controller_creation": report["controller_creation"],
        "controller_created": report["controller_created"],
    }


def combine(before: dict, after: dict, termination: str, code: int | None) -> dict:
    if termination not in TERMINATIONS:
        raise ValueError("Unrecognized install termination")
    if before["probe_result"] == "COMPLETE" and after["probe_result"] == "COMPLETE":
        if before["controller_created"] and after["controller_created"]:
            transition = "REMAINED_READY"
        elif not before["controller_created"] and after["controller_created"]:
            transition = "BECAME_READY"
        elif before["controller_created"] and not after["controller_created"]:
            transition = "REGRESSED"
        else:
            transition = "REMAINED_UNAVAILABLE"
    else:
        transition = "UNKNOWN"
    return {
        "schema": 1,
        "component": "WebView2 Evergreen Standalone x64 runtime installer in disposable Wine",
        "scope": "OFFICIAL_INSTALLER_TRIAL_NOT_SOLIDWORKS",
        "installer_signature": "VERIFIED_BY_WINDOWS_CI_BEFORE_STAGING",
        "installer_sha256_verified": True,
        "installer_execution": termination,
        "installer_exit_code": code if termination in {"EXIT_ZERO", "EXIT_NONZERO"} else None,
        "before": snapshot(before),
        "after": snapshot(after),
        "controller_transition": transition,
        "runtime_installation_confirmed": (
            termination == "EXIT_ZERO"
            and after["runtime_discovery"] == "VERSION_FOUND"
            and after["probe_result"] == "COMPLETE"
        ),
        "browser_controller_confirmed": transition in {"BECAME_READY", "REMAINED_READY"},
        "html_rendering": "NOT_TESTED",
        "solidworks_compatibility": "NOT_DEMONSTRATED",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Opt-in official WebView2 runtime installation in disposable Wine only")
    parser.add_argument("--wine", type=Path, required=True)
    parser.add_argument("--prefix", type=Path, required=True)
    parser.add_argument("--installer", type=Path, required=True)
    parser.add_argument("--sha256-file", type=Path, required=True)
    parser.add_argument("--probe", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeout-seconds", type=int, default=240)
    parser.add_argument("--agree-disposable-prefix", action="store_true", required=True,
                        help="I confirm this Wine prefix contains no personal data")
    args = parser.parse_args(argv)
    if not 30 <= args.timeout_seconds <= 360:
        parser.error("Install timeout must be 30-360 seconds")
    if not args.agree_disposable_prefix:
        parser.error("Explicit disposable-prefix approval required")
    try:
        prefix = args.prefix.expanduser().resolve(strict=True)
        wine = args.wine.expanduser().resolve(strict=True)
        installer = args.installer.expanduser().resolve(strict=True)
        sha = args.sha256_file.expanduser().resolve(strict=True)
        exe = args.probe.expanduser().resolve(strict=True)
        output = args.output.expanduser().resolve()
        validate_prefix(prefix)
        if not wine.is_file() or not os.access(wine, os.X_OK):
            raise ValueError("Wine executable is not accessible")
        if not exe.is_file() or not (exe.parent / "WebView2Loader.dll").is_file():
            raise ValueError("Independent WebView2 probe or SDK loader missing")
        if output in {installer, sha, exe}:
            raise ValueError("Output must not overwrite test inputs")
        verify_installer(installer, sha)
        env = wine_environment(prefix)
        before = probe(wine, exe, env)
        termination, code = run_installer(wine, installer, env, args.timeout_seconds)
        if termination != "TIMEOUT":
            # Evergreen setup can launch helper processes before exiting.
            time.sleep(5)
        after = probe(wine, exe, env)
        result = combine(before, after, termination, code)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    except (OSError, ValueError) as exc:
        # Do not print filesystem paths or untrusted raw external errors.
        parser.error(str(exc) if isinstance(exc, ValueError) else "Trial setup failed")

    print("WebView2 runtime install attempt:", result["installer_execution"])
    print("Browser discovered before:", result["before"]["runtime_discovery"])
    print("Browser discovered after:", result["after"]["runtime_discovery"])
    print("Environment after:", result["after"]["environment_creation"])
    print("Controller after:", result["after"]["controller_creation"])
    print("WebView2 controller confirmed:", result["browser_controller_confirmed"])
    print("SOLIDWORKS compatibility: NOT_DEMONSTRATED")
    # Negative installation results are valid experiments, but never accept a
    # failed/incomplete probe as a complete result.
    return 0 if (result["before"]["probe_result"] == "COMPLETE"
                 and result["after"]["probe_result"] == "COMPLETE") else 1


if __name__ == "__main__":
    raise SystemExit(main())
