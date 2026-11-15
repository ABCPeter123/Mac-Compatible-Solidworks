"""Ephemeral, private MSI action-name transport for genuine Microsoft setup.

Only the action *identifier* found in the original Wine error trace is stored.
Never print, serialize, upload, hash, or include this identifier in a report.
"""
from __future__ import annotations

import os
from pathlib import Path
import re

from scripts.netfx481_trial import validate_prefix

FILENAME = "swcompat_original_netfx40_failed_action.private"
ACTION_RE = re.compile(rb"[A-Za-z_][A-Za-z0-9_.]{0,119}\Z")


def private_path(prefix: Path) -> Path:
    validate_prefix(prefix)
    drive = prefix / "drive_c"
    if drive.is_symlink() or not drive.is_dir():
        raise ValueError("Invalid isolated Wine drive")
    return drive / FILENAME


def store(prefix: Path, value: bytes | None) -> bool:
    """Write one validated private name only once into a marked disposable prefix."""
    if value is None:
        return False
    if type(value) is not bytes or not ACTION_RE.fullmatch(value):
        return False
    target = private_path(prefix)
    if target.exists() or target.is_symlink():
        raise ValueError("Private action transport already exists")
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as out:
        out.write(value)
    return True


def consume(prefix: Path) -> str | None:
    """Read and delete the original identifier, even if content is invalid."""
    target = private_path(prefix)
    if target.is_symlink():
        raise ValueError("Linked private MSI action input")
    if not target.is_file():
        return None
    try:
        with target.open("rb") as stream:
            raw = stream.read(122)
        if ACTION_RE.fullmatch(raw):
            return raw.decode("ascii")
        return None
    finally:
        target.unlink(missing_ok=True)
