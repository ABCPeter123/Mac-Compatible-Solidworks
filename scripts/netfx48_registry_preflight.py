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
VERSION_KEYS = {"native64_version": KEYS["native64"],
                "wow32_version": KEYS["wow32"]}
FIELDS = {**KEYS, **VERSION_KEYS}
STATES = {"NOT_RUN", "ABSENT", "OLDER_RELEASE", "NETFX48_RANGE",
          "AT_LEAST_481", "UNAVAILABLE", "MALFORMED"}
VERSION_STATES = {"NOT_RUN", "ABSENT", "V4_0", "V4_1_TO_4_6",
                  "V4_7_PLUS", "OTHER_VERSION", "UNAVAILABLE", "MALFORMED"}
VERSION_LINE = re.compile(
    r"^\s*Version\s+REG_SZ\s+([0-9]{1,3}(?:\.[0-9]{1,8}){1,3})\s*$",
    re.IGNORECASE,
)
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
    return {key: "NOT_RUN" for key in FIELDS}


def valid(value: object) -> bool:
    return (type(value) is dict and set(value) == set(FIELDS)
            and all(type(value[k]) is str and value[k] in STATES for k in KEYS)
            and all(type(value[k]) is str and value[k] in VERSION_STATES
                    for k in VERSION_KEYS))


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


def parse_version(raw: bytes, exit_code: int) -> str:
    """Classify the legacy Full\\Version string without exporting its value."""
    if len(raw) > MAX_BYTES or b"\x00" in raw:
        return "MALFORMED"
    try:
        output = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        return "UNAVAILABLE"
    if exit_code != 0:
        return ("ABSENT" if exit_code == 1 and ABSENT_MESSAGE.search(output)
                else "UNAVAILABLE")
    values = [match.group(1) for text in output.splitlines()
              if (match := VERSION_LINE.fullmatch(text))]
    if len(values) != 1:
        return "MALFORMED"
    major, minor, *_ = (int(part) for part in values[0].split("."))
    if major != 4:
        return "OTHER_VERSION"
    if minor == 0:
        return "V4_0"
    if minor < 7:
        return "V4_1_TO_4_6"
    return "V4_7_PLUS"


def inspect(wine: Path, prefix: Path) -> dict:
    validate_prefix(prefix)
    if (wine.is_symlink() or not wine.is_file() or not os.access(wine, os.X_OK)):
        raise ValueError("Expected pinned executable Wine binary")
    env = os.environ.copy()
    env.pop("WINEDLLOVERRIDES", None)
    env.update({"WINEPREFIX": str(prefix), "WINEARCH": "win64",
                "WINEDEBUG": "-all"})
    result = {}
    for view, key in FIELDS.items():
        value_name = "Version" if view in VERSION_KEYS else "Release"
        with tempfile.TemporaryFile() as stream:
            try:
                child = subprocess.run(
                    [str(wine), "reg.exe", "query", key, "/v", value_name],
                    cwd=prefix, env=env, stdin=subprocess.DEVNULL,
                    stdout=stream, stderr=stream,
                    timeout=20, check=False)
            except (OSError, subprocess.TimeoutExpired):
                result[view] = "UNAVAILABLE"
                continue
            stream.seek(0)
            raw = stream.read(MAX_BYTES + 1)
            result[view] = (parse_version(raw, child.returncode)
                            if view in VERSION_KEYS else parse(raw, child.returncode))
    assert valid(result)
    return result
