"""Convert local Unix media paths to Win32 paths using the selected Wine prefix.

Windows tools such as msiexec.exe require drive-qualified Windows paths.
A host-side path must never be handed to Windows Installer as though it were
already a Windows path. Use the same Wine prefix for conversion and install.
"""
from __future__ import annotations

import os
from pathlib import Path
import re
import shutil
import subprocess

_WINDOWS_ABSOLUTE = re.compile(r"^[A-Za-z]:\\[^\r\n\x00]*\Z")


def windows_media_path(wine: Path, prefix: Path, path: Path) -> str:
    """Use winepath's actual DOS-drive mappings; safe Z: fallback only if mapped.

    Never print raw Wine output (paths may contain usernames/private data).
    """
    source = path.expanduser()
    if source.is_symlink():
        raise ValueError("Linked media is not accepted")
    target = source.resolve(strict=True)
    if not target.is_file():
        raise ValueError("Windows Installer needs a real local media file")
    if os.name == "nt":
        raise ValueError("Path conversion must run through Wine")
    env = os.environ.copy()
    env.update({"WINEPREFIX": str(prefix), "WINEARCH": "win64", "WINEDEBUG": "-all"})
    sibling = wine.with_name("winepath")
    winepath = sibling if sibling.is_file() and os.access(sibling, os.X_OK) else shutil.which("winepath")
    commands = []
    if winepath:
        commands.append([str(winepath), "-w", str(target)])
    # Wine bundles do not always expose a Unix winepath wrapper. Its built-in
    # Win32 program can still convert paths against the selected Wine prefix.
    commands.append([str(wine), "winepath.exe", "-w", str(target)])
    for command in commands:
        try:
            run = subprocess.run(command, env=env, capture_output=True,
                                 timeout=15, check=False)
        except (OSError, subprocess.TimeoutExpired):
            continue
        if run.returncode != 0 or len(run.stdout) > 4096:
            continue
        try:
            value = run.stdout.decode("utf-8", errors="strict").strip()
        except UnicodeDecodeError:
            continue
        if _WINDOWS_ABSOLUTE.fullmatch(value):
            return value

    # Safe deterministic fallback only where Wine's Z: mapping to / exists.
    # Never assume a drive is available or points to the Mac filesystem.
    zdrive = prefix / "dosdevices" / "z:"
    if zdrive.is_symlink() and zdrive.resolve() == Path("/"):
        if not any(c in target.name for c in '<>:"|?*'):
            return "Z:" + str(target).replace("/", "\\")
    raise ValueError("Could not map installation media to a Wine Windows drive")
