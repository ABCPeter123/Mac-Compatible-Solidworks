"""Isolated, terminal-first Wine compatibility lab. Python standard library only."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys

from . import __version__
from .analysis import analyze, recommendations

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_PREFIX = Path.home() / "Library/Application Support/SWCompat/prefixes/solidworks-lab"
DEFAULT_LOGS = Path.home() / "Library/Logs/SWCompat"

def find_wine(explicit: str | None = None) -> Path | None:
    candidate = explicit or os.environ.get("SWCOMPAT_WINE") or shutil.which("wine")
    if candidate:
        which = shutil.which(candidate)
        location = Path(which or candidate).expanduser()
        if location.is_file() and os.access(location, os.X_OK):
            return location.resolve()
    for name in ("Wine Stable.app", "Wine Staging.app", "Wine Devel.app"):
        location = Path("/Applications") / name / "Contents/Resources/wine/bin/wine"
        if location.is_file() and os.access(location, os.X_OK):
            return location
    return None

def run_text(command: list[str], timeout: int = 8) -> tuple[int, str]:
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)
        return result.returncode, (result.stdout + result.stderr).strip()
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 127, str(exc)

def diagnostic(wine: Path | None, prefix: Path) -> dict:
    mac = None
    if platform.system() == "Darwin":
        _, mac = run_text(["sw_vers", "-productVersion"])
    rosetta = "not applicable"
    if platform.system() == "Darwin" and platform.machine() == "arm64":
        status, _ = run_text(["arch", "-x86_64", "/usr/bin/true"])
        rosetta = "available" if status == 0 else "not detected"
    status, version = run_text([str(wine), "--version"]) if wine else (127, "not found")
    return {
        "host_os": platform.system(),
        "macos_version": mac,
        "cpu_arch": platform.machine(),
        "python_version": platform.python_version(),
        "rosetta": rosetta,
        "wine_path": str(wine) if wine else None,
        "wine_version": version,
        "wine_responds": status == 0,
        "prefix": str(prefix),
        "prefix_exists": prefix.is_dir(),
        "mingw_compiler": shutil.which("x86_64-w64-mingw32-gcc"),
    }

def wine_environment(prefix: Path, debug: bool = False) -> dict[str, str]:
    env = os.environ.copy()
    env["WINEPREFIX"] = str(prefix)
    env["WINEARCH"] = "win64"
    env["WINEDEBUG"] = "+timestamp,+seh,+loaddll,+wgl,+opengl" if debug else "-all"
    return env

def log_path(directory: Path, label: str) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    return directory / f"{stamp}-{label}-{os.getpid()}.log"

def capture(command: list[str], prefix: Path, logs: Path, label: str, timeout: int = 180, debug: bool = False) -> tuple[int, Path]:
    path = log_path(logs, label)
    with path.open("w", encoding="utf-8") as output:
        output.write(f"# SWCompat {__version__} {label}; process arguments omitted\n")
        output.flush()
        try:
            run = subprocess.run(command, env=wine_environment(prefix, debug), stdout=output,
                                 stderr=subprocess.STDOUT, timeout=timeout, check=False)
            return run.returncode, path
        except subprocess.TimeoutExpired:
            output.write("\nSWCOMPAT_TIMED_OUT=1\n")
            return 124, path
        except OSError as exc:
            output.write(f"SWCOMPAT_PROCESS_ERROR={exc}\n")
            return 127, path

def summarize(path: Path) -> None:
    report = analyze(path)
    print(f"Analyzed {report.lines} lines; Wine errors: {sum(report.errors.values())}; exceptions: {report.exceptions}")
    if report.missing_dlls:
        print("Missing DLLs:", ", ".join(report.missing_dlls))
    for suggestion in recommendations(report):
        print("Next:", suggestion)

def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Experimental SOLIDWORKS macOS/Wine diagnostics")
    p.add_argument("--wine", help="Explicit Wine binary, or use SWCOMPAT_WINE")
    p.add_argument("--prefix", type=Path, default=DEFAULT_PREFIX)
    p.add_argument("--logs-dir", type=Path, default=DEFAULT_LOGS)
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="command", required=True)
    doctor = sub.add_parser("doctor", help="Print host and runtime capabilities")
    doctor.add_argument("--json", action="store_true")
    sub.add_parser("init", help="Create an isolated 64-bit Wine prefix")
    sub.add_parser("probe-win32", help="Run cmd.exe /c ver through Wine")
    wgl = sub.add_parser("probe-wgl", help="Run the Windows x64 OpenGL/WGL probe")
    wgl.add_argument("--exe", type=Path, default=ROOT / "build/wgl_probe.exe")
    bitmap = sub.add_parser("probe-bitmap", help="Test offscreen Wine WGL bitmap rendering")
    bitmap.add_argument("--exe", type=Path, default=ROOT / "build/wgl_bitmap_probe.exe")
    prereq = sub.add_parser("probe-prereqs", help="Read-only Windows installer API and runtime reconnaissance")
    prereq.add_argument("--exe", type=Path, default=ROOT / "build/win_prereq_probe.exe")
    installer = sub.add_parser("install", help="Launch a legitimately obtained SOLIDWORKS installer")
    installer.add_argument("exe", type=Path)
    launcher = sub.add_parser("launch", help="Launch an existing Windows executable")
    launcher.add_argument("exe", type=Path)
    reader = sub.add_parser("analyze", help="Review a Wine log")
    reader.add_argument("log", type=Path)
    return p

def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    prefix, logs = args.prefix.expanduser().resolve(), args.logs_dir.expanduser().resolve()
    if args.command == "analyze":
        log = args.log.expanduser()
        if not log.is_file():
            print(f"Log not found: {log}", file=sys.stderr)
            return 2
        summarize(log)
        return 0
    wine = find_wine(args.wine)
    if args.command == "doctor":
        report = diagnostic(wine, prefix)
        if args.json:
            print(json.dumps(report, indent=2))
        else:
            for key, value in report.items():
                print(f"{key:20}: {value}")
        return 0
    if not wine:
        print("Wine not found. Run 'python3 -m swcompat doctor'.", file=sys.stderr)
        return 2
    if args.command == "init":
        boot = wine.with_name("wineboot")
        if not boot.is_file():
            fallback = shutil.which("wineboot")
            if not fallback:
                print("wineboot missing; install a complete Wine distribution.", file=sys.stderr)
                return 2
            boot = Path(fallback)
        prefix.parent.mkdir(parents=True, exist_ok=True)
        status, path = capture([str(boot), "--init"], prefix, logs, "init", timeout=240)
        print(f"init: {status}; log: {path}")
        if status:
            summarize(path)
        return status
    if not prefix.is_dir():
        print("Wine prefix missing. Run 'python3 -m swcompat init'.", file=sys.stderr)
        return 2
    if args.command == "probe-win32":
        status, path = capture([str(wine), "cmd.exe", "/c", "ver"], prefix, logs, "win32", timeout=90)
        print(f"Win32 probe: {'PASS' if status == 0 else 'FAIL'}; log: {path}")
        if status:
            summarize(path)
        return status
    if args.command == "probe-prereqs":
        exe = args.exe.expanduser().resolve()
        if not exe.is_file():
            print(f"Missing prerequisite executable: {exe}", file=sys.stderr)
            return 2
        status, path = capture([str(wine), str(exe)], prefix, logs, "prereqs", timeout=60)
        output = path.read_text(encoding="utf-8", errors="replace")
        complete = status == 0 and "SWCOMPAT_PREREQ_SCHEMA=1" in output and "SWCOMPAT_PREREQ_PROBE=PASS" in output
        print(f"Installer prerequisite probe: {'COMPLETE' if complete else 'FAILED'}; log: {path}")
        for line in output.splitlines():
            if line.startswith("SWCOMPAT_PREREQ_"):
                print(line)
        if not complete:
            summarize(path)
        return 0 if complete else (status or 1)
    if args.command in ("probe-wgl", "probe-bitmap"):
        exe = args.exe.expanduser().resolve()
        if not exe.is_file():
            print(f"Missing probe executable: {exe}; run ./scripts/build-wgl-probe.sh", file=sys.stderr)
            return 2
        is_bitmap = args.command == "probe-bitmap"
        label = "bitmap" if is_bitmap else "wgl"
        success_marker = "SWCOMPAT_BITMAP_WGL=PASS" if is_bitmap else "SWCOMPAT_WGL=PASS"
        status, path = capture([str(wine), str(exe)], prefix, logs, label, timeout=90, debug=True)
        output = path.read_text(encoding="utf-8", errors="replace")
        passed = status == 0 and success_marker in output
        print(f"{'Offscreen WGL' if is_bitmap else 'WGL'} probe: {'PASS' if passed else 'FAIL'}; log: {path}")
        for line in output.splitlines():
            if line.startswith(("OPENGL_", "SWCOMPAT_")):
                print(line)
        if not passed:
            summarize(path)
        return 0 if passed else (status or 1)
    if args.command in ("install", "launch"):
        exe = args.exe.expanduser().resolve()
        if not exe.is_file() or exe.suffix.lower() not in (".exe", ".msi"):
            print(f"Expected an existing .exe or .msi: {exe}", file=sys.stderr)
            return 2
        command = [str(wine), str(exe)] if exe.suffix.lower() == ".exe" else [str(wine), "msiexec.exe", "/i", str(exe)]
        log = log_path(logs, args.command)
        with log.open("w", encoding="utf-8") as output:
            output.write("# Launcher command and executable path deliberately omitted\n")
            output.flush()
            try:
                child = subprocess.Popen(command, env=wine_environment(prefix, debug=True),
                                         stdout=output, stderr=subprocess.STDOUT, start_new_session=True)
            except OSError as exc:
                print(f"Launch failed: {exc}", file=sys.stderr)
                return 127
        print(f"Process started (PID {child.pid}). Log: {log}")
        print("A successful launch does not mean installation, activation, or CAD functionality works.")
        return 0
    return 2

if __name__ == "__main__":
    raise SystemExit(main())
