"""Bounded original Microsoft CLR4 NGen queue drain before authentic 4.8 MSI.

Tests the hypothesis that an incomplete original Microsoft CLR4 setup leaves
native-image compilation queued and blocks the subsequent 4.8 signed MSI.
Uses Microsoft's documented `ngen.exe executeQueuedItems` command, not an
installer bypass or an NGen stub. No vendor output or paths are published.
The preflight is opt-in and must never be used in a user's Wine prefix.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile
from collections.abc import Callable

from scripts.netfx48_ngen_progress import (
    NgenProgress, blank as progress_blank, valid as valid_progress,
    SAMPLE_INTERVAL,
)

from scripts.netfx48_ngen_wine_trace import (
    blank as trace_blank, valid as valid_trace,
    classify_private_stream,
)

from scripts.netfx481_trial import validate_prefix
from scripts.netfx481_payload_audit import pe_type
from scripts.netfx40_msxml3_restart import validate as valid_restart
from scripts.netfx40_to_48_intermediate import _terminate_group

STATUS = {"NOT_RUN", "READY", "BLOCKED"}
STEP = {"NOT_RUN", "SUCCESS", "FILE_MISSING", "UNSAFE_FILE",
        "INVALID_PE", "START_FAILED", "TIMED_OUT",
        "TIMED_OUT_CLEANUP_DENIED", "EXIT_NONZERO"}
PATHS = {
    "x64": ("Framework64", "PE_AMD64"),
    "x86": ("Framework", "PE_I386"),
}
TIMEOUT = 180
PROGRESS_GRACE_SECONDS = 180
MAX_PROGRESS_EXTENSIONS = 2  # Never exceed 540 seconds per architecture.


def blank() -> dict:
    return {"status": "NOT_RUN", "x64": "NOT_RUN",
            "x86": "NOT_RUN", "ready": False,
            "wine_trace": {"x64": trace_blank(), "x86": trace_blank()},
            "ngen_progress": progress_blank()}


def valid(report: object) -> bool:
    if type(report) is not dict or set(report) != set(blank()):
        return False
    if (report["status"] not in STATUS
            or report["x64"] not in STEP or report["x86"] not in STEP
            or type(report["ready"]) is not bool
            or not valid_progress(report["ngen_progress"])
            or type(report["wine_trace"]) is not dict
            or set(report["wine_trace"]) != {"x64", "x86"}
            or any(not valid_trace(report["wine_trace"][arch]) for arch in ("x64", "x86"))
            or any(report[arch] == "NOT_RUN"
                   and report["wine_trace"][arch] != trace_blank()
                   for arch in ("x64", "x86"))):
        return False
    if report["status"] == "NOT_RUN":
        return report == blank()
    if report["ready"] or report["status"] == "READY":
        return (report["status"] == "READY" and report["ready"]
                and report["x64"] == report["x86"] == "SUCCESS")
    return (report["status"] == "BLOCKED" and not report["ready"]
            and report["x64"] != "NOT_RUN"
            and (report["x64"] != "SUCCESS" and report["x86"] == "NOT_RUN"
                 or report["x64"] == "SUCCESS"
                 and report["x86"] not in {"NOT_RUN", "SUCCESS"}))


def _ngen(prefix: Path, architecture: str) -> tuple[Path, str]:
    framework, expected = PATHS[architecture]
    base = prefix / "drive_c" / "windows" / "Microsoft.NET" / framework / "v4.0.30319"
    # Reject any linked path component, not just final ngen.exe.
    path = prefix
    for component in ("drive_c", "windows", "Microsoft.NET", framework,
                      "v4.0.30319", "ngen.exe"):
        path = path / component
        if path.is_symlink():
            return path, "UNSAFE_FILE"
    try:
        if not path.is_file():
            return path, "FILE_MISSING"
        size = path.stat().st_size
        if not 4096 <= size <= 40 * 1024 * 1024:
            return path, "INVALID_PE"
        with path.open("rb") as inp:
            kind = pe_type(inp.read(8192))
    except OSError:
        return path, "UNSAFE_FILE"
    return path, "SUCCESS" if kind == expected else "INVALID_PE"


def _execute(wine: Path, prefix: Path, executable: Path, *,
             observe_wine_failures: bool = False,
             progress: Callable[[], None] | None = None,
             progress_count: Callable[[], int] | None = None,
             extend_if_progress: bool = False) -> tuple[str, dict]:
    """Execute the *original* NGen; retain Wine diagnostics privately.

    Only err-level Wine channels are selected. Vendor stdout is discarded,
    native stderr is never returned, and its anonymous temporary file is
    removed upon return. No Windows error addresses or command lines escape.
    """
    if extend_if_progress and (progress is None or progress_count is None):
        raise ValueError("NGen grace requires verified progress sampling")
    env = os.environ.copy()
    env.update({
        "WINEPREFIX": str(prefix), "WINEARCH": "win64",
        "WINEDEBUG": ("-all,err+seh,err+ntdll,err+ole,err+rpc"
                      if observe_wine_failures else "-all"),
        "WINEDLLOVERRIDES": "mscoree=n;clr=n",
    })
    with tempfile.TemporaryFile() as trace:
        try:
            process = subprocess.Popen(
                [str(wine), str(executable), "executeQueuedItems"],
                cwd=prefix, env=env, start_new_session=True,
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=trace if observe_wine_failures else subprocess.DEVNULL)
        except OSError:
            return "START_FAILED", trace_blank()
        try:
            if progress is None:
                code = process.wait(timeout=TIMEOUT)
            else:
                remaining = TIMEOUT
                # Snapshot the current architecture's counter so earlier
                # processes cannot earn this NGen invocation a grace period.
                previous_growth = progress_count() if extend_if_progress else 0
                extensions = 0
                while remaining > 0:
                    interval = min(SAMPLE_INTERVAL, remaining)
                    try:
                        code = process.wait(timeout=interval)
                        break
                    except subprocess.TimeoutExpired:
                        remaining -= interval
                        progress()  # NGen log sizes only; original text is private
                        if remaining <= 0:
                            # A queue that actually grew during THIS budget
                            # earns one 180s grace interval, at most twice.
                            # A log that stays unchanged cannot keep extending
                            # a hung original ngen.exe indefinitely.
                            grown = progress_count() if extend_if_progress else 0
                            if (extend_if_progress
                                    and extensions < MAX_PROGRESS_EXTENSIONS
                                    and grown > previous_growth):
                                previous_growth = grown
                                extensions += 1
                                remaining = PROGRESS_GRACE_SECONDS
                            else:
                                raise
            status = "SUCCESS" if code == 0 else "EXIT_NONZERO"
        except subprocess.TimeoutExpired:
            try:
                _terminate_group(process)
                status = "TIMED_OUT"
            except PermissionError:
                status = "TIMED_OUT_CLEANUP_DENIED"
        diagnostic = (classify_private_stream(trace) if observe_wine_failures
                      else trace_blank())
    return status, diagnostic


def inspect(wine: Path, prefix: Path, native40: dict, *,
            observe_wine_failures: bool = False,
            extend_if_progress: bool = False) -> dict:
    if type(extend_if_progress) is not bool:
        raise ValueError("Adaptive NGen grace opt-in must be boolean")
    if type(observe_wine_failures) is not bool:
        raise ValueError("Wine trace opt-in must be boolean")
    if os.name == "nt" or prefix.is_symlink() or wine.is_symlink():
        raise ValueError("Only disposable non-Windows original CLR4 experiments")
    validate_prefix(prefix)
    if (not valid_restart(native40)
            or not native40["persistent_native_managed"]
            or native40["runtime_family"] != "MICROSOFT_CLR_CANDIDATE"
            or native40["native_only_managed"] != "PASS"):
        raise ValueError("Requires authenticated persistent Microsoft CLR4")
    if not wine.is_file() or not os.access(wine, os.X_OK):
        raise ValueError("Wine engine is not executable")
    # Don't touch any global user prefix or account-local permanent prefix.
    root = os.environ.get("RUNNER_TEMP")
    if (not root or Path(root).is_symlink()
            or prefix.resolve().parent != Path(root).resolve()
            or prefix.name != "netfx40-msxml3-prefix"):
        raise ValueError("NGen queue drain restricted to ephemeral CI prefix")
    result = blank()
    progress = NgenProgress(prefix)
    for arch in ("x64", "x86"):
        executable, status = _ngen(prefix, arch)
        if status == "SUCCESS":
            result[arch], result["wine_trace"][arch] = _execute(
                wine, prefix, executable, observe_wine_failures=observe_wine_failures,
                progress=progress.sample,
                progress_count=lambda arch=arch: progress.report[
                    arch + "_growth_windows"],
                extend_if_progress=extend_if_progress)
            # If process-group cleanup was denied, do not access its live
            # logs again or execute another original Wine command.
            if result[arch] != "TIMED_OUT_CLEANUP_DENIED":
                progress.sample()
        else:
            result[arch] = status
        if result[arch] != "SUCCESS":
            result["status"] = "BLOCKED"
            break
    else:
        result["status"], result["ready"] = "READY", True
    result["ngen_progress"] = progress.snapshot()
    assert valid(result)
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Drain genuine native Microsoft NGen queue")
    for key in ("wine", "prefix", "native40-report", "output"):
        parser.add_argument("--" + key, type=Path, required=True)
    parser.add_argument("--observe-wine-failures", action="store_true")
    parser.add_argument("--extend-if-progress", action="store_true",
                        help="Allow at most 2 extra 180s waits only on log growth")
    parser.add_argument("--agree-disposable-prefix", required=True,
                        action="store_true")
    args = parser.parse_args(argv)
    if args.output.is_symlink() or args.output.resolve().is_relative_to(args.prefix.resolve()):
        parser.error("NGen report must remain outside disposable Wine prefix")
    report = inspect(args.wine, args.prefix,
                     json.loads(args.native40_report.read_text(encoding="ascii")),
                     observe_wine_failures=args.observe_wine_failures,
                     extend_if_progress=args.extend_if_progress)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, sort_keys=True), encoding="ascii")
    for key in ("status", "x64", "x86", "ready", "wine_trace", "ngen_progress"):
        print("Original CLR4 NGen preflight", key, report[key])
    return 0 if report["ready"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
