"""Bounded, read-only original Microsoft NGen log evidence in a disposable Wine prefix.

Only material appended after the signed MSI started may contribute signals.
The private log, assembly names, paths, command lines, and original text
never enter reports, CI output, exception messages or artifacts.
"""
from __future__ import annotations

from pathlib import Path
import re

PATHS = {
    "X64": ("Framework64", "v4.0.30319", "ngen.log"),
    "X86": ("Framework", "v4.0.30319", "ngen.log"),
}
MAX_LOG_BYTES = 4 * 1024 * 1024
STATUSES = {"NOT_RUN", "NO_LOG", "UNCHANGED", "CLASSIFIED", "UNSAFE",
            "UNREADABLE", "TOO_LARGE"}
SIGNALS = {
    "PATH_NOT_FOUND", "FILE_NOT_FOUND", "SERVICE_MISSING",
    "ACCESS_DENIED", "NGEN_COMPILE", "NGEN_FAILURE",
}
EXPRESSIONS = {
    "PATH_NOT_FOUND": re.compile(r"(?i)0x80070003"),
    "FILE_NOT_FOUND": re.compile(r"(?i)0x80070002"),
    "SERVICE_MISSING": re.compile(r"(?i)0x80070424"),
    "ACCESS_DENIED": re.compile(r"(?i)0x80070005"),
    "NGEN_COMPILE": re.compile(r"(?i)\\bcompiling assembly\\b"),
    "NGEN_FAILURE": re.compile(
        r"(?i)(?:\\bngen failed\\b|\\berror compiling\\b|"
        r"\\bfailed to generate native code\\b)"
    ),
}


def blank() -> dict:
    return {"x64": "NOT_RUN", "x86": "NOT_RUN", "signals": []}


def valid(result: object) -> bool:
    if type(result) is not dict or set(result) != set(blank()):
        return False
    if any(type(result[field]) is not str or result[field] not in STATUSES
           for field in ("x64", "x86")):
        return False
    signals = result["signals"]
    if (type(signals) is not list
            or any(type(v) is not str or v not in SIGNALS for v in signals)
            or signals != sorted(set(signals))):
        return False
    return not signals or "CLASSIFIED" in (result["x64"], result["x86"])


def _file(prefix: Path, arch: str) -> Path:
    return prefix / "drive_c" / "windows" / "Microsoft.NET" / PATHS[arch][0] / PATHS[arch][1] / PATHS[arch][2]


def _status(path: Path, prefix: Path) -> tuple[str, int]:
    base = prefix
    for part in path.relative_to(prefix).parts:
        base = base / part
        if base.is_symlink():
            return "UNSAFE", 0
    try:
        if not path.exists():
            return "NO_LOG", 0
        if not path.is_file():
            return "UNSAFE", 0
        size = path.stat().st_size
    except OSError:
        return "UNREADABLE", 0
    if size > MAX_LOG_BYTES:
        return "TOO_LARGE", 0
    return "CLASSIFIED", size


def baseline(prefix: Path) -> dict:
    """Internal offsets, never written to a report or exported to CI."""
    if prefix.is_symlink() or not prefix.is_dir():
        return {arch: ("UNSAFE", 0) for arch in PATHS}
    return {arch: _status(_file(prefix, arch), prefix) for arch in PATHS}


def inspect(prefix: Path, before: dict) -> dict:
    if type(before) is not dict or set(before) != set(PATHS):
        raise ValueError("Unrecognized private NGen baseline")
    report = blank()
    all_signals: set[str] = set()
    for arch, key in (("X64", "x64"), ("X86", "x86")):
        state, start = before[arch]
        if (state not in STATUSES or type(start) is not int
                or start < 0 or start > MAX_LOG_BYTES):
            raise ValueError("Invalid private NGen offset")
        if state in {"UNSAFE", "UNREADABLE", "TOO_LARGE"}:
            report[key] = state
            continue
        path = _file(prefix, arch)
        current, size = _status(path, prefix)
        if current != "CLASSIFIED":
            report[key] = current
            continue
        if state == "CLASSIFIED" and size == start:
            report[key] = "UNCHANGED"
            continue
        # Truncation or log replacement is not trusted as newly appended MSI
        # evidence. The only accepted differential is strictly appended bytes.
        if state == "CLASSIFIED" and size < start:
            report[key] = "UNCHANGED"
            continue
        offset = start if state == "CLASSIFIED" else 0
        try:
            with path.open("rb") as stream:
                stream.seek(offset)
                raw = stream.read(MAX_LOG_BYTES + 1)
        except OSError:
            report[key] = "UNREADABLE"
            continue
        if not raw or len(raw) > MAX_LOG_BYTES:
            report[key] = "UNCHANGED" if not raw else "TOO_LARGE"
            continue
        # NGen logs may be Unicode. An undecodable log must never be copied
        # into the public report.
        if raw.startswith(b"\\xff\\xfe"):
            decoded = raw.decode("utf-16-le", errors="replace")
        else:
            decoded = raw.decode("utf-8", errors="replace")
        report[key] = "CLASSIFIED"
        all_signals.update(
            code for code, pattern in EXPRESSIONS.items()
            if pattern.search(decoded)
        )
    report["signals"] = sorted(all_signals)
    assert valid(report)
    return report
