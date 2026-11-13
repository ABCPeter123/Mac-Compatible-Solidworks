"""Bounded, opt-in first launch of an authentic SOLIDWORKS bootstrapper in Wine.

This does not enter a serial number, accept terms, bypass licensing, install
prerequisites, or claim SOLIDWORKS was installed. Never export installer logs,
executable bytes, paths, serial numbers, or screenshots.
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

from scripts.installer_media_preflight import analyze_pe

SENTINEL = ".swcompat-solidworks-installer-disposable"
DIGEST_PATTERN = re.compile(r"[a-fA-F0-9]{64}\Z")
MIN_SIZE = 64 * 1024
MAX_SIZE = 1024 * 1024 * 1024


def verify_media(media: Path, sha256: str) -> dict:
    """Validate expected full digest and parse PE header without execution."""
    if not DIGEST_PATTERN.fullmatch(sha256):
        raise ValueError("A 64-character SHA-256 is required")
    if media.is_symlink() or not media.is_file() or media.suffix.lower() != ".exe":
        raise ValueError("A regular Windows .exe bootstrapper is required")
    size = media.stat().st_size
    if not MIN_SIZE <= size <= MAX_SIZE:
        raise ValueError("Bootstrapper exceeds supported size limits")
    digest = hashlib.sha256()
    with media.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    if digest.hexdigest() != sha256.lower():
        raise ValueError("Bootstrapper checksum mismatch")
    metadata = analyze_pe(media)
    if metadata.get("format") != "pe" or metadata.get("architecture") not in {"x86", "x64"}:
        raise ValueError("Unsupported or invalid Windows PE executable")
    return {
        "schema": 1,
        "media_verification": "SHA256_VERIFIED",
        "pe_architecture": metadata["architecture"],
        "publisher_signature": "CHECK_SEPARATELY_ON_WINDOWS",
        "serial_number": "NOT_ACCESSED",
        "license_activation": "NOT_ATTEMPTED",
        "solidworks_compatibility": "NOT_DEMONSTRATED",
    }


def validate_prefix(prefix: Path) -> None:
    if prefix.is_symlink() or not prefix.is_dir():
        raise ValueError("Missing regular Wine prefix")
    if not (prefix / SENTINEL).is_file():
        raise ValueError("Unmarked Wine prefix: refusing to launch")
    if not (prefix / "drive_c").is_dir() or not (prefix / "system.reg").is_file():
        raise ValueError("Wine prefix is not initialized")


def attempt_launch(wine: Path, prefix: Path, installer: Path, *, timeout: int) -> dict:
    """Run only inside marked disposable Wine, never native Windows."""
    if os.name == "nt":
        raise ValueError("Native Windows installer execution is forbidden")
    validate_prefix(prefix)
    if not wine.is_file() or not os.access(wine, os.X_OK):
        raise ValueError("Wine executable is missing")
    if timeout < 10 or timeout > 180:
        raise ValueError("Timeout outside controlled 10..180 second window")

    env = os.environ.copy()
    env.update({"WINEPREFIX": str(prefix), "WINEARCH": "win64", "WINEDEBUG": "-all"})
    observation = "START_FAILED"
    process_started = False
    process = None
    try:
        process = subprocess.Popen(
            [str(wine), str(installer)],
            cwd=str(prefix),
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        process_started = True
        try:
            rc = process.wait(timeout=timeout)
            observation = "EXIT_ZERO" if rc == 0 else "EXIT_NONZERO"
        except subprocess.TimeoutExpired:
            observation = "TIMEOUT"
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except (ProcessLookupError, PermissionError):
                pass
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except (ProcessLookupError, PermissionError):
                    pass
                process.wait(timeout=5)
    except OSError:
        observation = "START_FAILED"

    return {
        "schema": 1,
        "component": "Genuine SOLIDWORKS bootstrapper initial Wine launch",
        "media_verification": "SHA256_VERIFIED",
        "wine_process_created": process_started,
        "bootstrapper_process": observation,
        "installation_manager_ui": "NOT_VERIFIED",
        "full_installation": "NOT_VERIFIED",
        "activation": "NOT_ATTEMPTED",
        "cad_launch": "NOT_TESTED",
        "solidworks_compatibility": "NOT_DEMONSTRATED",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify signed-media digest and, optionally, perform a bounded Wine bootstrap launch")
    parser.add_argument("--installer", required=True, type=Path)
    parser.add_argument("--sha256", required=True, help="Digest of the full, user-authorized executable")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--wine", type=Path)
    parser.add_argument("--prefix", type=Path)
    parser.add_argument("--timeout-seconds", type=int, default=90)
    parser.add_argument("--agree-disposable-prefix", action="store_true")
    args = parser.parse_args(argv)
    try:
        installer = args.installer.expanduser()
        output = args.output.expanduser().resolve()
        if installer.resolve() == output:
            raise ValueError("Refusing to overwrite installer")
        summary = verify_media(installer, args.sha256)
        if args.wine or args.prefix or args.agree_disposable_prefix:
            if not (args.wine and args.prefix and args.agree_disposable_prefix):
                raise ValueError("Wine launch requires wine, prefix and explicit disposable-prefix agreement")
            prefix = args.prefix.expanduser().resolve()
            if output.is_relative_to(prefix):
                raise ValueError("Sanitized report must be outside the disposable prefix")
            observation = attempt_launch(args.wine.expanduser(), prefix, installer.resolve(), timeout=args.timeout_seconds)
            summary.update(observation)
        else:
            summary["component"] = "SOLIDWORKS bootstrapper static preflight only"
            summary["wine_process_created"] = False
            summary["bootstrapper_process"] = "NOT_EXECUTED"
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    except (OSError, ValueError) as exc:
        # Never print the supplied path, secret URL, executable text, or digest.
        parser.error("Media validation or controlled Wine launch failed")
    print("Media verification:", summary["media_verification"])
    print("Wine executable started:", summary["wine_process_created"])
    print("Bootstrapper process:", summary["bootstrapper_process"])
    print("SOLIDWORKS installation: NOT_VERIFIED")
    return 0 if summary["bootstrapper_process"] in {"NOT_EXECUTED", "EXIT_ZERO", "TIMEOUT"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
