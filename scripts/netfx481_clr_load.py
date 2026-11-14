"""Run only our own native Windows x64 CLR loader fixture in marked Wine.

A successful LoadLibraryW call shows loader compatibility for one DLL but is
not proof of a genuine Microsoft-authenticated file or managed CLR execution.
"""
from __future__ import annotations
import os
from pathlib import Path
import subprocess
import tempfile

STATUSES = {"NOT_REQUESTED", "NOT_FOUND", "LINKED", "LOAD_FAILED", "LOADED", "NOT_VERIFIED"}
PREFIX = "SWCOMPAT_CLR_LOAD_"
MAX_OUTPUT = 1024


def parse(raw: bytes, exit_code: int) -> str:
    if exit_code != 0 or len(raw) > MAX_OUTPUT or b"\x00" in raw:
        return "NOT_VERIFIED"
    try:
        lines = raw.decode("ascii").splitlines()
    except UnicodeError:
        return "NOT_VERIFIED"
    values: dict[str, str] = {}
    for line in lines:
        if not line.startswith(PREFIX):
            continue
        if "=" not in line:
            return "NOT_VERIFIED"
        key, value = line[len(PREFIX):].split("=", 1)
        if key not in ("SCHEMA", "STATUS") or key in values:
            return "NOT_VERIFIED"
        values[key] = value
    return (values["STATUS"] if set(values) == {"SCHEMA", "STATUS"}
            and values["SCHEMA"] == "1"
            and values["STATUS"] in (STATUSES - {"NOT_REQUESTED", "NOT_VERIFIED"})
            else "NOT_VERIFIED")


def run(wine: Path, prefix: Path, fixture: Path, timeout: int = 25) -> str:
    from scripts.netfx481_trial import validate_prefix
    validate_prefix(prefix)
    if (fixture.is_symlink() or not fixture.is_file()
            or fixture.name.casefold() != "netfx481_clr_load.exe"):
        raise ValueError("Expected self-authored Windows CLR loader probe")
    env = os.environ.copy()
    env.pop("WINEDLLOVERRIDES", None)
    env.update({"WINEPREFIX": str(prefix), "WINEARCH": "win64", "WINEDEBUG": "-all"})
    with tempfile.TemporaryFile() as out:
        try:
            proc = subprocess.run(
                [str(wine), str(fixture)], cwd=fixture.parent, env=env,
                stdin=subprocess.DEVNULL, stdout=out, stderr=subprocess.DEVNULL,
                timeout=timeout, check=False,
            )
            rc = proc.returncode
        except (OSError, subprocess.TimeoutExpired):
            rc = 124
        out.seek(0)
        raw = out.read(MAX_OUTPUT + 1)
    return parse(raw, rc)
