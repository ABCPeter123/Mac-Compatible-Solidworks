"""Independent macOS host window visibility probe for the original CAD-style Win32 app.

Tests an AppKit control window's screenshot before interpreting a screenshot of
the Wine window. Both images are immediately discarded; stdout and CI reports
contain fixed enum states only. This cannot prove physical mouse input or
genuine SOLIDWORKS CAD functionality.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import select
import subprocess
import time

from scripts.live_cad_session_trial import (
    DOCUMENT, EXE_NAME, EXPECTED, WIN_DOC, model_file_state, parse as parse_cad
)
from scripts.netfx481_trial import validate_prefix
from scripts.software_launch import environment, validate_prefix as validate_mesa

FIELDS = {"SCHEMA", "MODE", "WINDOW", "CAPTURE", "PIXEL"}
READY = b"SWCOMPAT_LIVE_HOST_CAPTURE_READY=PASS\n"
CAPTURE_VALUES = {"SUCCESS", "UNAVAILABLE"}
PIXEL_VALUES = {"PASS", "MISMATCH", "NOT_TESTED"}
WINDOW_VALUES = {"FOUND", "NOT_FOUND"}
NATIVE_STATES = {"PASS", "PIXEL_MISMATCH", "CAPTURE_UNAVAILABLE", "PROCESS_ERROR"}
WINE_STATES = {"PASS", "PIXEL_MISMATCH", "CAPTURE_UNAVAILABLE", "WINDOW_NOT_FOUND", "NOT_EXECUTED", "PROCESS_ERROR"}
APP_STATES = {"PASS", "FAIL", "TIMEOUT", "NOT_READY", "PROCESS_ERROR"}
CHECK_STATES = {"PASS", "FAIL", "NOT_RUN"}
FILE_STATES = {"EXACT", "ABSENT", "MISMATCH", "LINKED", "IO_ERROR"}
MAX_OUTPUT = 8192


def parse_capture(raw: bytes, mode: str, code: int) -> str:
    if mode not in {"NATIVE", "WINE"} or code != 0 or len(raw) > 1024 or b"\x00" in raw:
        return "PROCESS_ERROR"
    try:
        lines = raw.decode("ascii").splitlines()
    except UnicodeDecodeError:
        return "PROCESS_ERROR"
    values: dict[str, str] = {}
    for line in lines:
        if not line.startswith("SWCOMPAT_HOST_PIXELS_"):
            continue
        if "=" not in line:
            return "PROCESS_ERROR"
        key, val = line[len("SWCOMPAT_HOST_PIXELS_"):].split("=", 1)
        if key not in FIELDS or key in values:
            return "PROCESS_ERROR"
        values[key] = val
    if (set(values) != FIELDS or values["SCHEMA"] != "1"
            or values["MODE"] != mode
            or values["WINDOW"] not in WINDOW_VALUES
            or values["CAPTURE"] not in CAPTURE_VALUES
            or values["PIXEL"] not in PIXEL_VALUES):
        return "PROCESS_ERROR"
    if values["WINDOW"] == "NOT_FOUND":
        if values["CAPTURE"] != "UNAVAILABLE" or values["PIXEL"] != "NOT_TESTED":
            return "PROCESS_ERROR"
        return "WINDOW_NOT_FOUND" if mode == "WINE" else "PROCESS_ERROR"
    if values["CAPTURE"] == "UNAVAILABLE":
        return "CAPTURE_UNAVAILABLE" if values["PIXEL"] == "NOT_TESTED" else "PROCESS_ERROR"
    if values["PIXEL"] == "PASS":
        return "PASS"
    if values["PIXEL"] == "MISMATCH":
        return "PIXEL_MISMATCH"
    return "PROCESS_ERROR"


def capture(host: Path, mode: str, timeout: int = 12) -> str:
    try:
        p = subprocess.run(
            [str(host), mode.lower()],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL, timeout=timeout, check=False,
        )
    except (subprocess.TimeoutExpired, OSError):
        return "PROCESS_ERROR"
    return parse_capture(p.stdout, mode, p.returncode)


def ready_line(process: subprocess.Popen[bytes], timeout: int = 15) -> tuple[bool, bytes]:
    """Bounded, strict readiness protocol; do not publish opaque Wine output."""
    if process.stdout is None:
        return False, b""
    deadline = time.monotonic() + timeout
    seen = bytearray()
    while time.monotonic() < deadline and len(seen) <= MAX_OUTPUT:
        available, _, _ = select.select(
            [process.stdout.fileno()], [], [],
            min(0.25, max(0, deadline - time.monotonic()))
        )
        if not available:
            if process.poll() is not None:
                # One last iteration may still drain buffered output.
                continue
            continue
        chunk = os.read(process.stdout.fileno(), 1024)
        if not chunk:
            break
        seen.extend(chunk)
        if seen.count(READY) == 1:
            return True, bytes(seen)
        if seen.count(READY) > 1:
            break
    return False, bytes(seen)


def run_gui(wine: Path, prefix: Path, fixture: Path, host: Path,
            hold_timeout: int = 48) -> tuple[str, str]:
    try:
        win = subprocess.Popen(
            [str(wine), str(fixture), "capture", WIN_DOC],
            cwd=fixture.parent, env=environment(prefix),
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
    except OSError:
        return "PROCESS_ERROR", "NOT_EXECUTED"
    head = b""
    captured = "NOT_EXECUTED"
    status = "NOT_READY"
    try:
        is_ready, head = ready_line(win, timeout=15)
        if is_ready:
            captured = capture(host, "WINE", timeout=10)
        try:
            tail, _ = win.communicate(timeout=hold_timeout)
        except subprocess.TimeoutExpired:
            win.kill()
            win.communicate(timeout=6)
            return "TIMEOUT", captured
        raw = head + tail
        # Exact CAD app marker grammar, plus one additional host readiness line.
        if is_ready and raw.count(READY) == 1:
            checked = parse_cad(raw.replace(READY, b""), win.returncode, "run")
            status = "PASS" if checked["result"] == "PASS" else "FAIL"
        else:
            status = "NOT_READY"
    finally:
        if win.poll() is None:
            win.kill()
            win.communicate(timeout=6)
    return status, captured


def trial(wine: Path, prefix: Path, fixture: Path, host: Path) -> dict:
    if os.name != "posix" or any(x.is_symlink() for x in (wine, prefix, fixture, host)):
        raise ValueError("Require unlinked disposable Wine prefix and self-authored fixtures")
    try:
        wine, prefix, fixture, host = (
            x.resolve(strict=True) for x in (wine, prefix, fixture, host)
        )
    except OSError as exc:
        raise ValueError("Required original test component missing") from exc
    validate_prefix(prefix)
    validate_mesa(prefix)
    if (not wine.is_file() or not os.access(wine, os.X_OK)
            or not host.is_file() or not os.access(host, os.X_OK)
            or not fixture.is_file() or fixture.name.casefold() != EXE_NAME):
        raise ValueError("Missing original x64 Win32 or macOS capture fixture")
    doc = prefix / "drive_c" / DOCUMENT
    if model_file_state(doc) != "ABSENT":
        raise ValueError("Refuse existing model at fixed synthetic test path")
    native = capture(host, "NATIVE", timeout=15)
    app = "NOT_READY"
    wine_screen = "NOT_EXECUTED"
    file_check = "ABSENT"
    independent = "NOT_RUN"
    cleaned = False
    try:
        app, wine_screen = run_gui(wine, prefix, fixture, host)
        file_check = model_file_state(doc)
        if app == "PASS" and file_check == "EXACT":
            try:
                result = subprocess.run(
                    [str(wine), str(fixture), "verify", WIN_DOC],
                    cwd=fixture.parent, env=environment(prefix),
                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL, timeout=20, check=False,
                )
                independent = ("PASS"
                               if parse_cad(result.stdout, result.returncode, "verify")["result"] == "PASS"
                               else "FAIL")
            except (OSError, subprocess.TimeoutExpired):
                independent = "FAIL"
    finally:
        if not doc.is_symlink() and doc.is_file():
            try:
                doc.unlink()
            except OSError:
                pass
        cleaned = model_file_state(doc) == "ABSENT"
    host_visible = native == "PASS" and wine_screen == "PASS"
    return {
        "schema": 1, "scope": "HOST_WINDOW_SCREENSHOT_NOT_SOLIDWORKS",
        "native_control": native,
        "wine_host_pixels": wine_screen,
        "windows_3d_session": app,
        "saved_model": file_check,
        "independent_model_reopen": independent,
        "cleanup": "REMOVED" if cleaned else "FAILED",
        "host_window_visibility_proven": host_visible,
        "native_solidworks_compatibility": "NOT_DEMONSTRATED",
    }


def validate(report: dict) -> bool:
    if type(report) is not dict or set(report) != {
        "schema", "scope", "native_control", "wine_host_pixels",
        "windows_3d_session", "saved_model", "independent_model_reopen",
        "cleanup", "host_window_visibility_proven", "native_solidworks_compatibility"
    }:
        return False
    if (type(report["schema"]) is not int or report["schema"] != 1
            or report["scope"] != "HOST_WINDOW_SCREENSHOT_NOT_SOLIDWORKS"
            or report["native_solidworks_compatibility"] != "NOT_DEMONSTRATED"
            or report["native_control"] not in NATIVE_STATES
            or report["wine_host_pixels"] not in WINE_STATES
            or report["windows_3d_session"] not in APP_STATES
            or report["saved_model"] not in FILE_STATES
            or report["independent_model_reopen"] not in CHECK_STATES
            or report["cleanup"] not in {"REMOVED", "FAILED"}
            or type(report["host_window_visibility_proven"]) is not bool):
        return False
    return report["host_window_visibility_proven"] == (
        report["native_control"] == "PASS" and report["wine_host_pixels"] == "PASS"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="macOS native-control-calibrated Wine viewport screenshot probe")
    for key in ("wine", "prefix", "fixture", "host", "output"):
        parser.add_argument("--" + key, required=True, type=Path)
    parser.add_argument("--agree-disposable-prefix", required=True, action="store_true")
    parser.add_argument("--require-macos-window-pixels", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.output.is_symlink() or args.output.resolve() in {
            x.resolve() for x in (args.wine, args.prefix, args.fixture, args.host)
        }:
            raise ValueError("Unexpected output target")
        result = trial(args.wine, args.prefix, args.fixture, args.host)
        if not validate(result):
            raise ValueError("Invalid host compositor report")
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="ascii")
    except (OSError, ValueError):
        parser.error("Invalid isolated Wine or macOS host screenshot trial")
    for key in ("native_control", "wine_host_pixels", "windows_3d_session",
                "saved_model", "independent_model_reopen", "cleanup"):
        print("Host CAD pixel experiment", key, result[key])
    print("Host macOS pixels VERIFIED:", result["host_window_visibility_proven"])
    print("SOLIDWORKS compatibility: NOT DEMONSTRATED")
    if result["windows_3d_session"] != "PASS" or result["independent_model_reopen"] != "PASS":
        return 1
    if args.require_macos_window_pixels and not result["host_window_visibility_proven"]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
