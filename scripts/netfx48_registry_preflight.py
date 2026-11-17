"""Read-only preflight for contradictory .NET 4.x Release registrations.

Wine/Proton may retain registrations from Wine Mono in either registry view.
Classify only fixed outcomes; never expose raw reg.exe output, keys or values.
No registration is written or deleted by this diagnostic.
"""
from __future__ import annotations

import os
from pathlib import Path
import re
import subprocess
import tempfile

from scripts.netfx481_trial import validate_prefix

KEYS = {
    "native64": r"HKLM\Software\Microsoft\NET Framework Setup\NDP\v4\Full",
    "wow32": r"HKLM\Software\Wow6432Node\Microsoft\NET Framework Setup\NDP\v4\Full",
}
STATES = {"NOT_RUN", "ABSENT", "OLDER_RELEASE", "NETFX48_RANGE",
          "AT_LEAST_481", "UNAVAILABLE", "MALFORMED"}
MAX_BYTES = 4096
RELEASE_LINE = re.compile(
    r"^\s*Release\s+REG_DWORD\s+(0x[0-9a-fA-F]{1,8}|[0-9]{1,10})\s*$",
    re.IGNORECASE,
)
# Only a recognizable registry-not-found diagnostic qualifies as absence.
# Locale differences or any ambiguous failure remain UNAVAILABLE.
ABSENT_MESSAGE = re.compile(
    r"(?i)\b(?:unable to find|cannot find|not found|does not exist)\b"
)


def blank() -> dict:
    return {key: "NOT_RUN" for key in KEYS}


def valid(value: object) -> bool:
    return (type(value) is dict and set(value) == set(KEYS)
            and all(type(v) is str and v in STATES
                    for v in value.values()))


def parse(raw: bytes, exit_code: int) -> str:
    if len(raw) > MAX_BYTES or b"\x00" in raw:
        return "MALFORMED"
    try:
        output = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        return "UNAVAILABLE"
    if exit_code != 0:
        return "ABSENT" if exit_code == 1 and ABSENT_MESSAGE.search(output) else "UNAVAILABLE"
    values = [line.group(1) for text in output.splitlines()
              if (line := RELEASE_LINE.fullmatch(text))]
    if len(values) != 1:
        return "MALFORMED"
    try:
        release = int(values[0], 0) if values[0].lower().startswith("0x") else int(values[0], 10)
    except ValueError:
        return "MALFORMED"
    if release >= 533320:
        return "AT_LEAST_481"
    if release >= 528040:
        return "NETFX48_RANGE"
    return "OLDER_RELEASE"


def inspect(wine: Path, prefix: Path) -> dict:
    validate_prefix(prefix)
    if (wine.is_symlink() or not wine.is_file() or not os.access(wine, os.X_OK)):
        raise ValueError("Expected pinned executable Wine binary")
    env = os.environ.copy()
    env.pop("WINEDLLOVERRIDES", None)
    env.update({"WINEPREFIX": str(prefix), "WINEARCH": "win64",
                "WINEDEBUG": "-all"})
    result = {}
    for view, key in KEYS.items():
        with tempfile.TemporaryFile() as stream:
            try:
                child = subprocess.run(
                    [str(wine), "reg.exe", "query", key, "/v", "Release"],
                    cwd=prefix, env=env, stdin=subprocess.DEVNULL,
                    stdout=stream, stderr=subprocess.DEVNULL,
                    timeout=20, check=False)
            except (OSError, subprocess.TimeoutExpired):
                result[view] = "UNAVAILABLE"
                continue
            stream.seek(0)
            result[view] = parse(stream.read(MAX_BYTES + 1), child.returncode)
    assert valid(result)
    return result
