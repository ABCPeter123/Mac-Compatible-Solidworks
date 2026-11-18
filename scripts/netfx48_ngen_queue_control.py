"""Opt-in genuine Microsoft NGen queue coordination for a disposable Wine MSI trial.

Microsoft documents 'ngen queue pause' before framework servicing, followed
by 'ngen queue continue'. This launches only existing Microsoft .NET 4.0 NGen
executables, in the already verified native CLR4 Wine prefix. No MSI changes,
service registration, fabricated NGen binary, raw logs or command output.
"""
from __future__ import annotations

from pathlib import Path
from typing import Callable

from scripts.netfx481_trial import validate_prefix

RUN_CODES = {"NOT_RUN", "SUCCESS", "EXIT_NONZERO", "TIMED_OUT",
             "TIMED_OUT_CLEANUP_DENIED", "START_FAILED", "NOT_FOUND", "UNSAFE"}
STATUSES = {"NOT_RUN", "PREPARED", "COMPLETE", "INCOMPLETE", "DIRTY"}
ARCS = {
    "x64": ("Framework64", "v4.0.30319", "ngen.exe"),
    "x86": ("Framework", "v4.0.30319", "ngen.exe"),
}
# Compatible with the bounded private process runner in netfx40_to_48_signed_msi.
Runner = Callable[..., str]


def blank() -> dict:
    return {
        "status": "NOT_RUN", "x64_pause": "NOT_RUN", "x86_pause": "NOT_RUN",
        "x64_continue": "NOT_RUN", "x86_continue": "NOT_RUN",
    }


def valid(report: object) -> bool:
    if type(report) is not dict or set(report) != set(blank()):
        return False
    if (type(report["status"]) is not str or report["status"] not in STATUSES
            or any(type(report[key]) is not str or report[key] not in RUN_CODES
                   for key in blank() if key != "status")):
        return False
    if report["status"] == "NOT_RUN":
        return report == blank()
    pauses = [report[key + "_pause"] for key in ARCS]
    resumes = [report[key + "_continue"] for key in ARCS]
    if report["status"] == "PREPARED":
        return all(p == "SUCCESS" for p in pauses) and all(
            r == "NOT_RUN" for r in resumes)
    if report["status"] == "COMPLETE":
        return all(p == "SUCCESS" for p in pauses) and all(
            r == "SUCCESS" for r in resumes)
    if report["status"] == "DIRTY":
        return (any(x == "TIMED_OUT_CLEANUP_DENIED" for x in pauses + resumes)
                or (all(p == "SUCCESS" for p in pauses)
                    and all(r == "NOT_RUN" for r in resumes)))
    return (any(p != "SUCCESS" for p in pauses)
            or any(r != "SUCCESS" for r in resumes))


def _source(prefix: Path, arch: str) -> tuple[Path, str]:
    path = prefix / "drive_c" / "windows" / "Microsoft.NET"
    for part in ARCS[arch]:
        path = path / part
    root = prefix
    for part in path.relative_to(prefix).parts:
        root = root / part
        if root.is_symlink():
            return path, "UNSAFE"
    try:
        if not path.exists():
            return path, "NOT_FOUND"
        if not path.is_file() or not 4096 <= path.stat().st_size <= 2 * 1024 * 1024:
            return path, "UNSAFE"
        with path.open("rb") as handle:
            if handle.read(2) != b"MZ":
                return path, "UNSAFE"
    except OSError:
        return path, "UNSAFE"
    return path, "SUCCESS"


def _command(wine: Path, prefix: Path, env: dict, arch: str,
             operation: str, runner: Runner) -> str:
    path, state = _source(prefix, arch)
    if state != "SUCCESS":
        return state
    safe_env = dict(env)
    # Prove that Wine Mono did not satisfy native Microsoft NGen servicing.
    safe_env["WINEDLLOVERRIDES"] = "mscoree=n;clr=n"
    result = runner([str(wine), str(path), "queue", operation],
                    safe_env, prefix, 40)
    return result if result in RUN_CODES - {"NOT_RUN", "NOT_FOUND", "UNSAFE"} else "START_FAILED"


def prepare(wine: Path, prefix: Path, env: dict, runner: Runner) -> dict:
    validate_prefix(prefix)
    result = blank()
    for arch in ARCS:
        result[arch + "_pause"] = _command(wine, prefix, env, arch, "pause", runner)
        if result[arch + "_pause"] != "SUCCESS":
            break
    if all(result[a + "_pause"] == "SUCCESS" for a in ARCS):
        result["status"] = "PREPARED"
    elif any(result[a + "_pause"] == "TIMED_OUT_CLEANUP_DENIED"
             for a in ARCS):
        # No more Wine calls, including continue, if process cleanup failed.
        result["status"] = "DIRTY"
    else:
        # If the first queue was paused, do not leave it paused after failing
        # to prepare the other architecture. Never continue an unpaused queue.
        for arch in ARCS:
            if result[arch + "_pause"] == "SUCCESS":
                result[arch + "_continue"] = _command(
                    wine, prefix, env, arch, "continue", runner)
                if result[arch + "_continue"] == "TIMED_OUT_CLEANUP_DENIED":
                    break
        result["status"] = ("DIRTY" if any(
            result[a + "_continue"] == "TIMED_OUT_CLEANUP_DENIED" for a in ARCS)
            else "INCOMPLETE")
    if not valid(result):
        raise ValueError("Invalid original NGen queue preparation")
    return result


def resume(wine: Path, prefix: Path, env: dict,
           report: dict, runner: Runner, *, dirty: bool = False) -> dict:
    validate_prefix(prefix)
    if not valid(report) or report["status"] != "PREPARED":
        raise ValueError("Original NGen queue was not prepared")
    result = dict(report)
    if dirty:
        # An installer process group survived cleanup. Never run any further
        # commands in a contaminated prefix. The report remains failed.
        result["status"] = "DIRTY"
    else:
        for arch in ARCS:
            result[arch + "_continue"] = _command(
                wine, prefix, env, arch, "continue", runner)
            if result[arch + "_continue"] == "TIMED_OUT_CLEANUP_DENIED":
                break
        result["status"] = ("DIRTY" if any(
            result[a + "_continue"] == "TIMED_OUT_CLEANUP_DENIED" for a in ARCS)
            else "COMPLETE" if all(
                result[a + "_continue"] == "SUCCESS" for a in ARCS)
            else "INCOMPLETE")
    if not valid(result):
        raise ValueError("Invalid original NGen queue restoration")
    return result
