"""Launch a licensed Windows executable using isolated Mesa llvmpipe on Wine.

This is a diagnostic Windows launcher, not a SOLIDWORKS installer or activation tool.
Requires an already initialized Wine prefix with verified Windows x64 Mesa DLLs.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import subprocess
import sys

from scripts.stage_zink import AMD64, pe_machine, wait_for_prefix
from swcompat.cli import DEFAULT_LOGS, DEFAULT_PREFIX, find_wine, log_path

DLLS = ("opengl32.dll", "libgallium_wgl.dll")


def environment(prefix: Path, existing: dict[str, str] | None = None) -> dict[str, str]:
    env = dict(os.environ if existing is None else existing)
    env.update({
        "WINEPREFIX": str(prefix),
        "WINEARCH": "win64",
        "WINEDLLOVERRIDES": "opengl32,libgallium_wgl,libglapi=n,b",
        "GALLIUM_DRIVER": "llvmpipe",
        "MESA_LOADER_DRIVER_OVERRIDE": "llvmpipe",
        "LIBGL_ALWAYS_SOFTWARE": "1",
    })
    return env


def validate_prefix(prefix: Path) -> Path:
    if not wait_for_prefix(prefix, timeout_seconds=3):
        raise ValueError(f"Uninitialized or incomplete Wine prefix: {prefix}")
    dll_dir = prefix / "drive_c/windows/system32"
    for name in DLLS:
        path = dll_dir / name
        if not path.is_file() or pe_machine(path) != AMD64:
            raise ValueError(
                f"Windows x64 Mesa {name} missing. "
                "Stage the verified Mesa 25.1.9 archive with scripts.stage_zink."
            )
    return dll_dir


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Launch a licensed Windows .exe using Mesa llvmpipe CPU OpenGL on macOS Wine"
    )
    parser.add_argument("--wine", help="Path to a Wine executable")
    parser.add_argument("--prefix", type=Path, default=DEFAULT_PREFIX)
    parser.add_argument("--logs-dir", type=Path, default=DEFAULT_LOGS)
    parser.add_argument("--exe", type=Path, required=True, help="Existing, legitimately obtained Windows executable")
    parser.add_argument("arguments", nargs=argparse.REMAINDER, help="Executable arguments, after --")
    args = parser.parse_args(argv)

    wine = find_wine(args.wine)
    if wine is None:
        parser.error("Wine not found. Provide --wine or the SWCOMPAT_WINE environment variable.")
    prefix = args.prefix.expanduser().resolve()
    try:
        validate_prefix(prefix)
    except ValueError as exc:
        parser.error(str(exc))
    exe = args.exe.expanduser().resolve()
    if not exe.is_file() or exe.suffix.lower() != ".exe":
        parser.error(f"Expected an existing Windows .exe: {exe}")
    arguments = args.arguments[1:] if args.arguments[:1] == ["--"] else args.arguments
    logs_dir = args.logs_dir.expanduser().resolve()
    logfile = log_path(logs_dir, "llvmpipe")
    command = [str(wine), str(exe), *arguments]

    try:
        with logfile.open("w", encoding="utf-8") as log:
            log.write("# SWCompat Mesa llvmpipe diagnostic launch; executable arguments omitted\n")
            log.flush()
            process = subprocess.Popen(
                command, env=environment(prefix), stdin=subprocess.DEVNULL,
                stdout=log, stderr=subprocess.STDOUT, start_new_session=True,
            )
    except OSError as exc:
        print(f"Process could not start: {exc}", file=sys.stderr)
        return 127
    print(f"Wine process started, PID {process.pid}. Log: {logfile}")
    print("Launch is not proof of installation, activation, or working SOLIDWORKS CAD functionality.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
