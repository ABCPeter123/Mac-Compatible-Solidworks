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


def blank() -> dict:
    return {"status": "NOT_RUN", "x64": "NOT_RUN",
            "x86": "NOT_RUN", "ready": False}


def valid(report: object) -> bool:
    if type(report) is not dict or set(report) != set(blank()):
        return False
    if (report["status"] not in STATUS
            or report["x64"] not in STEP or report["x86"] not in STEP
            or type(report["ready"]) is not bool):
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


def _execute(wine: Path, prefix: Path, executable: Path) -> str:
    env = os.environ.copy()
    env.update({
        "WINEPREFIX": str(prefix), "WINEARCH": "win64",
        "WINEDEBUG": "-all", "WINEDLLOVERRIDES": "mscoree=n;clr=n",
    })
    try:
        process = subprocess.Popen(
            [str(wine), str(executable), "executeQueuedItems"],
            cwd=prefix, env=env, start_new_session=True,
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL)
    except OSError:
        return "START_FAILED"
    try:
        return "SUCCESS" if process.wait(timeout=TIMEOUT) == 0 else "EXIT_NONZERO"
    except subprocess.TimeoutExpired:
        try:
            _terminate_group(process)
        except PermissionError:
            return "TIMED_OUT_CLEANUP_DENIED"
        return "TIMED_OUT"


def inspect(wine: Path, prefix: Path, native40: dict) -> dict:
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
    for arch in ("x64", "x86"):
        executable, status = _ngen(prefix, arch)
        result[arch] = status if status != "SUCCESS" else _execute(wine, prefix, executable)
        if result[arch] != "SUCCESS":
            result["status"] = "BLOCKED"
            break
    else:
        result["status"], result["ready"] = "READY", True
    assert valid(result)
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Drain genuine native Microsoft NGen queue")
    for key in ("wine", "prefix", "native40-report", "output"):
        parser.add_argument("--" + key, type=Path, required=True)
    parser.add_argument("--agree-disposable-prefix", required=True,
                        action="store_true")
    args = parser.parse_args(argv)
    if args.output.is_symlink() or args.output.resolve().is_relative_to(args.prefix.resolve()):
        parser.error("NGen report must remain outside disposable Wine prefix")
    report = inspect(args.wine, args.prefix,
                     json.loads(args.native40_report.read_text(encoding="ascii")))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, sort_keys=True), encoding="ascii")
    for key in ("status", "x64", "x86", "ready"):
        print("Original CLR4 NGen preflight", key, report[key])
    return 0 if report["ready"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
