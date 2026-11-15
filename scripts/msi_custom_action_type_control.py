"""Bounded native-Windows-vs-Wine MSI Type 19 control, no vendor binaries.

A self-authored MSI intentionally fails its Type 19 custom action. The
independent original Microsoft .NET run returned TRACE_MISSING; this control
determines whether the same Wine trace and Python classifier can capture an
actual custom action. Never interpret success here as Microsoft CLR readiness.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading

from scripts.netfx481_trial import validate_prefix
from scripts.netfx40_msi_custom_type import (
    parse, validate as validate_type, relevant, MAX_LINE_BYTES,
    MAX_RETAINED_LINES, MAX_RETAINED_BYTES
)
from swcompat.wine_paths import windows_media_path

PROCESS = {"NONZERO", "ZERO", "TIMEOUT", "LAUNCH_FAILED", "PIPE_INCOMPLETE"}
STATES = {"MEASURED"}


def inspect(wine: Path, prefix: Path, msi: Path, sha256_file: Path,
            *, timeout: int = 120) -> dict:
    if os.name == "nt":
        raise ValueError("Wine MSI experiment must not run on native Windows")
    if any(p.is_symlink() for p in (wine, prefix, msi, sha256_file)):
        raise ValueError("Reject linked MSI control inputs")
    validate_prefix(prefix)
    if not wine.is_file() or not os.access(wine, os.X_OK):
        raise ValueError("Missing selected Wine executable")
    if msi.name != "swcompat_custom_action_type_control.msi" or not msi.is_file():
        raise ValueError("Unexpected self-authored MSI")
    expected = sha256_file.read_text(encoding="ascii").strip().lower()
    if len(expected) != 64 or any(c not in "0123456789abcdef" for c in expected):
        raise ValueError("Invalid pinned MSI SHA256")
    h = hashlib.sha256()
    with msi.open("rb") as f:
        for block in iter(lambda: f.read(65536), b""):
            h.update(block)
    if h.hexdigest() != expected:
        raise ValueError("Self-authored MSI differs from native Windows build")
    path = windows_media_path(wine, prefix, msi)
    env = os.environ.copy()
    env.update({
        "WINEPREFIX": str(prefix), "WINEARCH": "win64",
        "WINEDEBUG": "-all,err+msi,fixme+msi,trace+msi",
    })
    raw = bytearray()
    overflow = False
    lines = 0
    incomplete = False
    result = "LAUNCH_FAILED"
    try:
        proc = subprocess.Popen(
            [str(wine), "msiexec.exe", "/i", path, "/qn", "/norestart"],
            cwd=prefix, env=env, stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
        )
    except OSError:
        proc = None
    if proc is not None:
        def drain() -> None:
            nonlocal overflow, lines, incomplete
            assert proc.stderr is not None
            try:
                with proc.stderr as pipe:
                    while True:
                        line = pipe.readline(MAX_LINE_BYTES + 1)
                        if not line:
                            break
                        if not relevant(line):
                            continue
                        if lines >= MAX_RETAINED_LINES or len(raw) + len(line) > MAX_RETAINED_BYTES:
                            overflow = True
                            continue
                        raw.extend(line)
                        lines += 1
            except OSError:
                incomplete = True

        worker = threading.Thread(target=drain, daemon=True)
        worker.start()
        try:
            code = proc.wait(timeout=timeout)
            result = "ZERO" if code == 0 else "NONZERO"
        except subprocess.TimeoutExpired:
            result = "TIMEOUT"
            proc.kill()
            proc.wait(timeout=15)
        except OSError:
            result = "PIPE_INCOMPLETE"
            proc.kill()
        worker.join(timeout=5)
        if worker.is_alive() or incomplete:
            result = "PIPE_INCOMPLETE"
    reason = ("PROCESS_INCOMPLETE" if result in {"TIMEOUT", "LAUNCH_FAILED", "PIPE_INCOMPLETE"}
              else "LINE_LIMIT" if overflow and lines >= MAX_RETAINED_LINES
              else "BYTE_LIMIT" if overflow else "UNKNOWN")
    evidence = parse(bytes(raw), truncated=overflow or result in
                     {"TIMEOUT", "LAUNCH_FAILED", "PIPE_INCOMPLETE"},
                     capture_reason=reason)
    return {"status": "MEASURED", "msi_process": result,
            "custom_action_type": evidence,
            "native_microsoft_clr": False,
            "solidworks_compatibility": "NOT_DEMONSTRATED"}


def validate(report: dict) -> bool:
    return (
        type(report) is dict
        and set(report) == {
            "status", "msi_process", "custom_action_type",
            "native_microsoft_clr", "solidworks_compatibility"
        }
        and report["status"] in STATES
        and report["msi_process"] in PROCESS
        and validate_type(report["custom_action_type"])
        and report["native_microsoft_clr"] is False
        and report["solidworks_compatibility"] == "NOT_DEMONSTRATED"
    )


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Original self-authored MSI Type 19 under Wine")
    for name in ("wine", "prefix", "msi", "sha256", "output"):
        p.add_argument("--" + name, type=Path, required=True)
    p.add_argument("--timeout", type=int, default=120)
    p.add_argument("--agree-disposable-prefix", action="store_true")
    args = p.parse_args(argv)
    if not args.agree_disposable_prefix or not 15 <= args.timeout <= 180:
        raise ValueError("Requires bounded disposable original test agreement")
    report = inspect(args.wine.resolve(), args.prefix.resolve(),
                     args.msi.resolve(), args.sha256.resolve(), timeout=args.timeout)
    if not validate(report):
        raise ValueError("Unsafe MSI control result")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, sort_keys=True), encoding="utf-8")
    for key in ("status", "msi_process"):
        print("SWCOMPAT ORIGINAL MSI TYPE19", key, report[key])
    for key in ("status", "family", "base_type", "execution", "capture_reason"):
        print("SWCOMPAT ORIGINAL MSI CUSTOM ACTION", key, report["custom_action_type"][key])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
