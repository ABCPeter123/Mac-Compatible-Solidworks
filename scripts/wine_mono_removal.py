"""Uninstall Wine Mono MSI packages only in a marked disposable Wine test prefix.

Wine Mono upstream explicitly requires uninstalling it before native Microsoft
.NET Framework 4.8.1 or earlier. Use Wine uninstaller commands, not arbitrary
DLL deletion or unrelated registry edits. Never operate on user prefixes.
"""
from __future__ import annotations
import os
from pathlib import Path
import re
import subprocess
import tempfile

_GUID = re.compile(r"^\{?[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}?$")
_MONO_NAMES = {"Wine Mono Windows Support", "Wine Mono Runtime", "Wine Mono"}
MAX_LIST_BYTES = 32768
MAX_PACKAGES = 8


def parse_uninstaller_list(raw: bytes) -> tuple[str, ...]:
    """Parse only Wine's Mono MSI descriptions and GUIDs. Fail closed."""
    if len(raw) > MAX_LIST_BYTES or b"\x00" in raw:
        raise ValueError("Untrusted Wine uninstaller inventory")
    try:
        source = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ValueError("Wine uninstaller output invalid") from exc
    found: set[str] = set()
    for line in source.splitlines():
        if "Wine Mono" not in line:
            continue
        # Wine programs/uninstaller/main.c formats --list as GUID|||name.
        if line.count("|||") != 1:
            raise ValueError("Unrecognized Wine Mono uninstaller record")
        raw_guid, description = line.split("|||", 1)
        guid = raw_guid.strip()
        name = description.strip()
        if not any(name == known or name.startswith(known + " |")
                   for known in _MONO_NAMES):
            raise ValueError("Unexpected Wine Mono uninstaller description")
        if not _GUID.fullmatch(guid):
            raise ValueError("Unrecognized Wine Mono MSI product identifier")
        found.add(guid.upper())
        if len(found) > MAX_PACKAGES:
            raise ValueError("Unexpected number of Wine Mono packages")
    return tuple(sorted(found))


def _env(prefix: Path) -> dict[str, str]:
    env = os.environ.copy()
    env.pop("WINEDLLOVERRIDES", None)
    env.update({"WINEPREFIX": str(prefix), "WINEARCH": "win64", "WINEDEBUG": "-all"})
    return env


def inventory(wine: Path, prefix: Path) -> tuple[str, ...]:
    from scripts.netfx481_trial import validate_prefix
    validate_prefix(prefix)
    with tempfile.TemporaryFile() as out:
        try:
            proc = subprocess.run(
                [str(wine), "uninstaller", "--list"], cwd=prefix,
                env=_env(prefix), stdin=subprocess.DEVNULL,
                stdout=out, stderr=subprocess.STDOUT,
                check=False, timeout=45,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ValueError("Wine uninstaller inventory unavailable") from exc
        if proc.returncode != 0:
            raise ValueError("Wine uninstaller inventory did not succeed")
        out.seek(0)
        return parse_uninstaller_list(out.read(MAX_LIST_BYTES + 1))


def remove_mono(wine: Path, prefix: Path, before: dict) -> dict[str, object]:
    """Remove only verified Wine Mono product GUIDs and validate absence."""
    from scripts.netfx481_trial import validate_prefix
    validate_prefix(prefix)
    if before.get("clr_family") != "MONO":
        return {"before": 0, "after": 0, "action": "NOT_APPLICABLE"}
    try:
        products = inventory(wine, prefix)
    except ValueError:
        return {"before": None, "after": None, "action": "INVENTORY_FAILED"}
    if not products:
        return {"before": 0, "after": 0, "action": "MONO_NOT_REGISTERED"}
    for guid in products:
        try:
            proc = subprocess.run(
                [str(wine), "uninstaller", "--remove", guid],
                cwd=prefix, env=_env(prefix), stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                timeout=90, check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            return {"before": len(products), "after": None, "action": "REMOVE_FAILED"}
        if proc.returncode != 0:
            return {"before": len(products), "after": None, "action": "REMOVE_FAILED"}
    try:
        remaining = inventory(wine, prefix)
    except ValueError:
        return {"before": len(products), "after": None, "action": "VERIFY_FAILED"}
    return {
        "before": len(products),
        "after": len(remaining),
        "action": "REMOVED" if len(remaining) == 0 else "VERIFY_FAILED",
    }
