"""Bounded private triage for Wine Rosetta WoW64 x86 native/CLR failures.

Bug 60494 documents new WoW64 32-bit execution hangs under Rosetta where
wow64cpu runs an x64 thunk in 32-bit mode. This is a *candidate fingerprint*,
not a presumed cause of our native Microsoft .NET failure. No Wine trace,
vendor paths, addresses, exception text or originals enter the public report.
"""
from __future__ import annotations

import os
from pathlib import Path
import re
import select
import subprocess
import time

from scripts.netfx40_to_48_intermediate import _terminate_group
from scripts.netfx481_trial import parse_probe, validate_prefix

MAX_CAPTURE = 1024 * 1024
NATIVE_NAME = "netfx40_wow64_native_smoke.exe"
MANAGED_NAME = "netfx40_wow64_managed_probe.exe"
RUN = {"NOT_RUN", "EXIT_ZERO", "EXIT_NONZERO", "TIMED_OUT",
       "TIMED_OUT_CLEANUP_DENIED", "START_FAILED"}
SEH = {"NOT_RUN", "NO_EXCEPTION", "WOW64CPU_MODE_CANDIDATE",
       "ACCESS_VIOLATION", "OTHER_EXCEPTION", "TOO_LARGE", "UNREADABLE"}
CLR = {"NOT_RUN", "MICROSOFT_CLR_CANDIDATE", "MONO", "UNKNOWN", "NOT_VERIFIED"}
MANAGED = {"NOT_RUN", "PASS", "FAIL", "NOT_VERIFIED"}
FAULT = re.compile(r"(?i)dispatch_exception\s+code=c0000005")
MODE = re.compile(r"(?i)\bcs=(?:0*107|0*23)\b")
WOW64CPU = re.compile(r"(?i)\bwow64cpu\b|addr=(?:0*7bf[0-9a-f]{3,6})\b")
NATIVE_MARKERS = (b"SWCOMPAT_WOW64_NATIVE_SCHEMA=1",
                  b"SWCOMPAT_WOW64_NATIVE_RESULT=PASS")


def blank() -> dict:
    return {"native_run": "NOT_RUN", "native_seh": "NOT_RUN",
            "native_control": False, "managed_run": "NOT_RUN",
            "managed_seh": "NOT_RUN", "managed_family": "NOT_RUN",
            "managed_execution": "NOT_RUN"}


def valid(result: object) -> bool:
    if type(result) is not dict or set(result) != set(blank()):
        return False
    for key, values in (("native_run", RUN), ("native_seh", SEH),
                        ("managed_run", RUN), ("managed_seh", SEH),
                        ("managed_family", CLR), ("managed_execution", MANAGED)):
        if type(result[key]) is not str or result[key] not in values:
            return False
    if type(result["native_control"]) is not bool:
        return False
    if result["native_control"] and result["native_run"] != "EXIT_ZERO":
        return False
    if result["managed_run"] == "NOT_RUN":
        return (result["managed_seh"] == "NOT_RUN"
                and result["managed_family"] == "NOT_RUN"
                and result["managed_execution"] == "NOT_RUN"
                and (result == blank()
                     or (result["native_run"] == "TIMED_OUT_CLEANUP_DENIED"
                         and result["native_seh"] != "NOT_RUN"
                         and not result["native_control"])))
    if (result["native_run"] == "NOT_RUN"
            or result["native_seh"] == "NOT_RUN"
            or result["managed_seh"] == "NOT_RUN"):
        return False
    if result["managed_family"] == "NOT_RUN" or result["managed_execution"] == "NOT_RUN":
        return False
    return not (result["managed_execution"] == "PASS"
                and result["managed_run"] != "EXIT_ZERO")


def classify_seh(data: bytes, truncated: bool) -> str:
    if truncated:
        return "TOO_LARGE"
    try:
        text = data.decode("utf-8", "replace")
    except (ValueError, TypeError):
        return "UNREADABLE"
    if not text:
        return "NO_EXCEPTION"
    # Only self-authored executable diagnostics + Wine's controlled +seh.
    # A matching x86 CS + failing wow64cpu range is a candidate, not proof.
    if FAULT.search(text) and MODE.search(text) and WOW64CPU.search(text):
        return "WOW64CPU_MODE_CANDIDATE"
    if FAULT.search(text):
        return "ACCESS_VIOLATION"
    if "dispatch_exception" in text:
        return "OTHER_EXCEPTION"
    return "NO_EXCEPTION"


def _capture(wine: Path, prefix: Path, fixture: Path, timeout: int,
             *, managed: bool) -> tuple[str, str, bytes]:
    env = os.environ.copy()
    env.pop("WINEDLLOVERRIDES", None)
    env.update({"WINEPREFIX": str(prefix), "WINEARCH": "win64",
                "WINEDEBUG": "+seh"})
    if managed:
        env["WINEDLLOVERRIDES"] = "mscoree=n;clr=n"
    try:
        child = subprocess.Popen(
            [str(wine), str(fixture)], env=env, cwd=prefix,
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, start_new_session=True)
    except OSError:
        return "START_FAILED", "NO_EXCEPTION", b""
    # Continuously drain the pipe so a repeating Wine exception cannot grow
    # a private disk log or accumulate unbounded subprocess output in memory.
    raw = bytearray()
    truncated = False
    deadline = time.monotonic() + timeout
    status = "TIMED_OUT"
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired([str(wine), str(fixture)], timeout)
            readable, _, _ = select.select(
                [child.stdout], [], [], min(remaining, 0.25))
            if not readable:
                continue
            block = os.read(child.stdout.fileno(), 16384)
            if not block:
                rc = child.wait(timeout=remaining)
                status = "EXIT_ZERO" if rc == 0 else "EXIT_NONZERO"
                break
            remaining_capacity = max(0, MAX_CAPTURE + 1 - len(raw))
            raw.extend(block[:remaining_capacity])
            if len(block) > remaining_capacity or len(raw) > MAX_CAPTURE:
                truncated = True
    except subprocess.TimeoutExpired:
        try:
            _terminate_group(child)
            status = "TIMED_OUT"
        except (OSError, subprocess.TimeoutExpired):
            # Never launch further Wine processes in a dirty prefix.
            status = "TIMED_OUT_CLEANUP_DENIED"
    finally:
        if child.stdout is not None:
            child.stdout.close()
    return status, classify_seh(bytes(raw[:MAX_CAPTURE]), truncated), bytes(raw[:MAX_CAPTURE])

def inspect(wine: Path, prefix: Path, native: Path, managed: Path) -> dict:
    validate_prefix(prefix)
    if (wine.is_symlink() or not wine.is_file()
            or native.is_symlink() or managed.is_symlink()
            or native.name != NATIVE_NAME or managed.name != MANAGED_NAME
            or not native.is_file() or not managed.is_file()):
        raise ValueError("Only fixed self-authored native and managed x86 controls allowed")
    # The signed Windows job already independently compiles and runs the 32-bit
    # native exe, and verifies the managed 32BITREQUIRED PE32 metadata.
    n_run, n_seh, n_raw = _capture(wine, prefix, native, 25, managed=False)
    native_control = (n_run == "EXIT_ZERO" and n_seh != "TOO_LARGE"
                      and all(m in n_raw.splitlines() for m in NATIVE_MARKERS))
    result = blank()
    result.update(native_run=n_run, native_seh=n_seh,
                  native_control=native_control)
    if n_run == "TIMED_OUT_CLEANUP_DENIED":
        assert valid(result)
        return result
    m_run, m_seh, m_raw = _capture(wine, prefix, managed, 70, managed=True)
    # Never publish Wine +seh traces or paths. Extract *only* self-authored
    # fixed SWCOMPAT_NETFX481_ records before the existing strict parser.
    markers = [line for line in m_raw.splitlines()
               if line.startswith(b"SWCOMPAT_NETFX481_") and len(line) <= 128]
    parsed = parse_probe(b"\n".join(markers) if m_seh != "TOO_LARGE" else b"",
                         0 if m_run == "EXIT_ZERO"
                         else 1 if m_run == "EXIT_NONZERO" else 124)
    result.update(managed_run=m_run, managed_seh=m_seh,
                  managed_family=parsed["clr_family"],
                  managed_execution=parsed["managed"])
    assert valid(result)
    return result
