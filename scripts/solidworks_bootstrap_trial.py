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
import threading
import re as regex

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



WINDOW_LINES = {
    "SWCOMPAT_SW_UI_CANDIDATE_PROCESSES",
    "SWCOMPAT_SW_UI_CANDIDATE_WINDOWS",
    "SWCOMPAT_SW_UI_OWNED_WINDOWS",
    "SWCOMPAT_SW_UI_VISIBLE_LARGE_WINDOWS",
    "SWCOMPAT_SW_UI_PARENT_LAYERED",
    "SWCOMPAT_SW_UI_PARENT_NO_REDIRECTION",
    "SWCOMPAT_SW_UI_CHILD_VISIBLE",
    "SWCOMPAT_SW_UI_CHILD_LAYERED",
    "SWCOMPAT_SW_UI_CHILD_NO_REDIRECTION",
}
WINDOW_ENUMS = {
    "SWCOMPAT_SW_UI_RESPONSIVENESS": {"RESPONSIVE", "UNRESPONSIVE", "NO_CANDIDATE"},
    "SWCOMPAT_SW_UI_GDI_CLIENT": {"NONUNIFORM", "UNIFORM", "READBACK_FAILED", "NO_CANDIDATE"},
    "SWCOMPAT_SW_UI_GDI_FAILURE_STAGE": {
        "NONE", "NO_CANDIDATE", "CLIENT_RECT_FAILED", "CLIENT_TOO_SMALL",
        "SOURCE_DC_FAILED", "MEMORY_DC_FAILED", "DIB_CREATE_FAILED",
        "BITMAP_SELECT_FAILED", "STRETCH_BLT_FAILED",
    },
    "SWCOMPAT_SW_UI_DIRECT_GETPIXEL": {
        "NONUNIFORM", "UNIFORM", "READBACK_FAILED", "NO_CANDIDATE",
    },
    "SWCOMPAT_SW_UI_CHILD_GDI": {
        "NONUNIFORM", "UNIFORM", "READBACK_FAILED", "NO_CHILD",
    },
}


def parse_window_probe(text: str) -> dict | None:
    """Accept a strict fixed-value Win32 report; never retain unknown output."""
    if len(text) > 4096:
        return None
    values = {}
    for line in text.splitlines():
        if line == "SWCOMPAT_SW_UI_PROBE=COMPLETE":
            if "COMPLETE" in values:
                return None
            values["COMPLETE"] = True
        elif "=" in line:
            key, value = line.split("=", 1)
            if key in values:
                return None
            if key in WINDOW_LINES and regex.fullmatch(r"[0-9]{1,5}", value):
                values[key] = int(value)
            elif key in WINDOW_ENUMS and value in WINDOW_ENUMS[key]:
                values[key] = value
            else:
                return None
        else:
            return None
    if len(values) != 1 + len(WINDOW_LINES) + len(WINDOW_ENUMS) or any(values[k] > 8192 for k in WINDOW_LINES):
        return None
    if values["SWCOMPAT_SW_UI_CANDIDATE_WINDOWS"] > values["SWCOMPAT_SW_UI_VISIBLE_LARGE_WINDOWS"]:
        return None
    if values["SWCOMPAT_SW_UI_OWNED_WINDOWS"] > values["SWCOMPAT_SW_UI_CANDIDATE_WINDOWS"]:
        return None
    no_candidate = values["SWCOMPAT_SW_UI_CANDIDATE_WINDOWS"] == 0
    for field in WINDOW_ENUMS:
        if field != "SWCOMPAT_SW_UI_CHILD_GDI":
            if (values[field] == "NO_CANDIDATE") != no_candidate:
                return None
    children = values["SWCOMPAT_SW_UI_CHILD_VISIBLE"]
    child_gdi = values["SWCOMPAT_SW_UI_CHILD_GDI"]
    if (children == 0) != (child_gdi == "NO_CHILD"):
        return None
    if (values["SWCOMPAT_SW_UI_CHILD_LAYERED"] > children
            or values["SWCOMPAT_SW_UI_CHILD_NO_REDIRECTION"] > children):
        return None
    if (values["SWCOMPAT_SW_UI_PARENT_LAYERED"] > values["SWCOMPAT_SW_UI_CANDIDATE_WINDOWS"]
            or values["SWCOMPAT_SW_UI_PARENT_NO_REDIRECTION"] > values["SWCOMPAT_SW_UI_CANDIDATE_WINDOWS"]):
        return None
    if no_candidate and children != 0:
        return None
    stage = values["SWCOMPAT_SW_UI_GDI_FAILURE_STAGE"]
    gdi = values["SWCOMPAT_SW_UI_GDI_CLIENT"]
    if not no_candidate:
        if gdi == "READBACK_FAILED" and stage == "NONE":
            return None
        if gdi != "READBACK_FAILED" and stage not in {"NONE",
                "CLIENT_RECT_FAILED", "CLIENT_TOO_SMALL", "SOURCE_DC_FAILED",
                "MEMORY_DC_FAILED", "DIB_CREATE_FAILED",
                "BITMAP_SELECT_FAILED", "STRETCH_BLT_FAILED"}:
            return None
    return {
        "candidate_processes": values["SWCOMPAT_SW_UI_CANDIDATE_PROCESSES"],
        "candidate_windows": values["SWCOMPAT_SW_UI_CANDIDATE_WINDOWS"],
        "owned_windows": values["SWCOMPAT_SW_UI_OWNED_WINDOWS"],
        "responsiveness": values["SWCOMPAT_SW_UI_RESPONSIVENESS"],
        "gdi_client": gdi,
        "gdi_failure_stage": stage,
        "direct_getpixel": values["SWCOMPAT_SW_UI_DIRECT_GETPIXEL"],
        "parent_layered": values["SWCOMPAT_SW_UI_PARENT_LAYERED"],
        "parent_no_redirection": values["SWCOMPAT_SW_UI_PARENT_NO_REDIRECTION"],
        "child_visible": children,
        "child_layered": values["SWCOMPAT_SW_UI_CHILD_LAYERED"],
        "child_no_redirection": values["SWCOMPAT_SW_UI_CHILD_NO_REDIRECTION"],
        "child_gdi": child_gdi,
    }


def sample_window_census(wine: Path, probe: Path, prefix: Path, env: dict) -> dict | None:
    """Execute our own Windows-only census without reading window titles or paths."""
    try:
        run = subprocess.run(
            [str(wine), str(probe)], cwd=str(prefix), env=env,
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, timeout=15, check=False,
            start_new_session=True,
        )
        if run.returncode != 0 or len(run.stdout) > 4096:
            return None
        return parse_window_probe(run.stdout.decode("ascii", errors="replace").strip())
    except (subprocess.TimeoutExpired, OSError):
        return None


def attempt_launch(wine: Path, prefix: Path, installer: Path, *, timeout: int, window_probe: Path | None = None) -> dict:
    """Run only inside marked disposable Wine, never native Windows."""
    if os.name == "nt":
        raise ValueError("Native Windows installer execution is forbidden")
    validate_prefix(prefix)
    if not wine.is_file() or not os.access(wine, os.X_OK):
        raise ValueError("Wine executable is missing")
    if timeout < 10 or timeout > 180:
        raise ValueError("Timeout outside controlled 10..180 second window")
    if window_probe is not None and (not window_probe.is_file() or window_probe.suffix.lower() != ".exe"):
        raise ValueError("Missing original Win32 window census executable")

    env = os.environ.copy()
    env.update({"WINEPREFIX": str(prefix), "WINEARCH": "win64", "WINEDEBUG": "-all"})
    observation = "START_FAILED"
    process_started = False
    process = None
    stop_monitor = threading.Event()
    observations: list[dict] = []
    monitor_thread = None
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
        if window_probe is not None:
            def observe() -> None:
                # Multiple samples reduce false negatives from slow installer startups.
                for interval in (8, 25, 30):
                    if stop_monitor.wait(interval):
                        return
                    sample = sample_window_census(wine, window_probe, prefix, env)
                    if sample is not None:
                        observations.append(sample)

            monitor_thread = threading.Thread(target=observe, daemon=True)
            monitor_thread.start()
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
    finally:
        stop_monitor.set()
        if monitor_thread is not None:
            monitor_thread.join(timeout=16)

    max_candidate_windows = max((s["candidate_windows"] for s in observations), default=0)
    max_owned_windows = max((s["owned_windows"] for s in observations), default=0)
    max_candidate_processes = max((s["candidate_processes"] for s in observations), default=0)
    responsiveness = (
        "RESPONSIVE" if any(s["responsiveness"] == "RESPONSIVE" for s in observations)
        else "UNRESPONSIVE" if any(s["responsiveness"] == "UNRESPONSIVE" for s in observations)
        else "NO_CANDIDATE" if observations
        else "NOT_VERIFIED"
    )
    gdi_client = (
        "NONUNIFORM" if any(s["gdi_client"] == "NONUNIFORM" for s in observations)
        else "UNIFORM" if any(s["gdi_client"] == "UNIFORM" for s in observations)
        else "READBACK_FAILED" if any(s["gdi_client"] == "READBACK_FAILED" for s in observations)
        else "NO_CANDIDATE" if observations
        else "NOT_VERIFIED"
    )
    direct_getpixel = (
        "NONUNIFORM" if any(s["direct_getpixel"] == "NONUNIFORM" for s in observations)
        else "UNIFORM" if any(s["direct_getpixel"] == "UNIFORM" for s in observations)
        else "READBACK_FAILED" if any(s["direct_getpixel"] == "READBACK_FAILED" for s in observations)
        else "NO_CANDIDATE" if observations
        else "NOT_VERIFIED"
    )
    child_visible_max = max((sample["child_visible"] for sample in observations), default=0)
    parent_layered_max = max((sample["parent_layered"] for sample in observations), default=0)
    parent_no_redirection_max = max((sample["parent_no_redirection"] for sample in observations), default=0)
    child_layered_max = max((sample["child_layered"] for sample in observations), default=0)
    child_no_redirection_max = max((sample["child_no_redirection"] for sample in observations), default=0)
    child_gdi = (
        "NONUNIFORM" if any(s["child_gdi"] == "NONUNIFORM" for s in observations)
        else "UNIFORM" if any(s["child_gdi"] == "UNIFORM" for s in observations)
        else "READBACK_FAILED" if any(s["child_gdi"] == "READBACK_FAILED" for s in observations)
        else "NO_CHILD" if observations
        else "NOT_VERIFIED"
    )
    gdi_failure_stages = sorted({
        s["gdi_failure_stage"] for s in observations
        if s["gdi_failure_stage"] not in {"NO_CANDIDATE", "NONE"}
    })
    # Fixed allowlist only, never report arbitrary strings or window content.
    gdi_failure_stage = (
        gdi_failure_stages[0] if gdi_failure_stages
        else "NONE" if max_candidate_windows > 0
        else "NO_CANDIDATE" if observations
        else "NOT_VERIFIED"
    )
    window_evidence = (
        "CANDIDATE_WINDOW_SEEN" if max_candidate_windows > 0
        else "NO_CANDIDATE_WINDOW_OBSERVED" if observations
        else "NOT_VERIFIED"
    )
    return {
        "schema": 1,
        "component": "Genuine SOLIDWORKS bootstrapper initial Wine launch",
        "media_verification": "SHA256_VERIFIED",
        "wine_process_created": process_started,
        "bootstrapper_process": observation,
        "installer_window_census": window_evidence,
        "census_samples_complete": len(observations),
        "candidate_installer_processes_max": max_candidate_processes,
        "candidate_visible_windows_max": max_candidate_windows,
        "installer_owned_windows_max": max_owned_windows,
        "installer_hwnd_responsiveness": responsiveness,
        "installer_gdi_client_variation": gdi_client,
        "installer_gdi_failure_stage": gdi_failure_stage,
        "installer_direct_getpixel": direct_getpixel,
        "installer_parent_layered_max": parent_layered_max,
        "installer_parent_no_redirection_max": parent_no_redirection_max,
        "installer_child_visible_max": child_visible_max,
        "installer_child_layered_max": child_layered_max,
        "installer_child_no_redirection_max": child_no_redirection_max,
        "installer_child_gdi": child_gdi,
        "macos_onscreen_pixels": "NOT_VERIFIED",
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
    parser.add_argument("--window-probe", type=Path, help="Original self-contained Win32 process/window census executable")
    parser.add_argument("--agree-disposable-prefix", action="store_true")
    args = parser.parse_args(argv)
    try:
        installer = args.installer.expanduser()
        output = args.output.expanduser().resolve()
        if installer.resolve() == output:
            raise ValueError("Refusing to overwrite installer")
        summary = verify_media(installer, args.sha256)
        if args.wine or args.prefix or args.agree_disposable_prefix or args.window_probe:
            if not (args.wine and args.prefix and args.agree_disposable_prefix):
                raise ValueError("Wine launch requires wine, prefix and explicit disposable-prefix agreement")
            prefix = args.prefix.expanduser().resolve()
            if output.is_relative_to(prefix):
                raise ValueError("Sanitized report must be outside the disposable prefix")
            observation = attempt_launch(
                args.wine.expanduser(), prefix, installer.resolve(),
                timeout=args.timeout_seconds,
                window_probe=args.window_probe.expanduser().resolve() if args.window_probe else None,
            )
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
    if "installer_window_census" in summary:
        print("Win32 installer window census:", summary["installer_window_census"])
        print("Candidate visible windows (max):", summary["candidate_visible_windows_max"])
        print("Candidate owned popup windows (max):", summary["installer_owned_windows_max"])
        print("Installer HWND responsiveness:", summary["installer_hwnd_responsiveness"])
        print("Installer GDI client readback:", summary["installer_gdi_client_variation"])
        print("Installer GDI failure stage:", summary["installer_gdi_failure_stage"])
        print("Installer direct GetPixel:", summary["installer_direct_getpixel"])
        print("Installer child HWNDs (max):", summary["installer_child_visible_max"])
        print("Installer child GDI:", summary["installer_child_gdi"])
        print("Installer parent no-redirection (max):", summary["installer_parent_no_redirection_max"])
        print("macOS onscreen installer pixels: NOT_VERIFIED")
    print("SOLIDWORKS installation: NOT_VERIFIED")
    return 0 if summary["bootstrapper_process"] in {"NOT_EXECUTED", "EXIT_ZERO", "TIMEOUT"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
