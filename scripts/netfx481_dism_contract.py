"""Detect Wine's DISM servicing false success using a guaranteed missing CAB.

No Microsoft or user data is installed, extracted, edited, read, logged or
uploaded. DISM must reject an absent package. Exit 0 would mean the interface
is not credible for authentic .NET Framework 4.8.1 servicing.

This is a diagnostic, NOT a DISM replacement.
"""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import subprocess
from scripts.netfx481_trial import validate_prefix

STATES = {"NOT_RUN", "DISM_FALSE_SUCCESS", "DISM_REJECTED_MISSING_CAB",
          "PROCESS_TIMEOUT", "PROCESS_FAILED", "REFUSED_NONEMPTY_TARGET"}
CAB = r"C:\swcompat_probe_missing\definitely-not-a-package.cab"


def blank(status: str = "NOT_RUN") -> dict:
    if status not in STATES:
        raise ValueError("Unknown DISM contract state")
    return {"status": status, "missing_cab_exists": False,
            "genuine481_servicing_proven": False}


def validate(result: dict) -> bool:
    return (type(result) is dict and set(result) == set(blank())
            and result["status"] in STATES
            and result["missing_cab_exists"] is False
            and result["genuine481_servicing_proven"] is False)


def run(wine: Path, prefix: Path) -> dict:
    if os.name == "nt" or wine.is_symlink() or prefix.is_symlink():
        raise ValueError("Only isolated non-Windows Wine tests")
    wine, prefix = wine.resolve(strict=True), prefix.resolve(strict=True)
    validate_prefix(prefix)
    if not wine.is_file() or not os.access(wine, os.X_OK):
        raise ValueError("Nonexecutable Wine build")
    # This path must not exist. We never create a CAB or inject fake servicing
    # state. A real Windows DISM must not exit success for this operation.
    target = prefix / "drive_c" / "swcompat_probe_missing"
    if target.exists() or target.is_symlink():
        return blank("REFUSED_NONEMPTY_TARGET")
    env = os.environ.copy()
    env.pop("WINEDLLOVERRIDES", None)
    env.update({"WINEPREFIX": str(prefix), "WINEARCH": "win64", "WINEDEBUG": "-all"})
    try:
        completed = subprocess.run(
            [str(wine), "dism.exe", "/Online", "/Add-Package",
             "/PackagePath:" + CAB, "/NoRestart"],
            cwd=prefix, env=env, stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=45, check=False)
    except subprocess.TimeoutExpired:
        return blank("PROCESS_TIMEOUT")
    except OSError:
        return blank("PROCESS_FAILED")
    result = blank("DISM_FALSE_SUCCESS" if completed.returncode == 0
                   else "DISM_REJECTED_MISSING_CAB")
    if target.exists() or target.is_symlink():
        return blank("REFUSED_NONEMPTY_TARGET")
    assert validate(result)
    return result


def main() -> int:
    p = argparse.ArgumentParser(description="Wine DISM false-success contract")
    for key in ("wine", "prefix", "output"):
        p.add_argument("--" + key, required=True, type=Path)
    p.add_argument("--agree-disposable-prefix", action="store_true", required=True)
    args = p.parse_args()
    result = run(args.wine, args.prefix)
    assert validate(result)
    if args.output.is_symlink():
        raise ValueError("Linked output")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, sort_keys=True), encoding="ascii")
    for key in ("status", "genuine481_servicing_proven"):
        print("Original .NET 4.8.1 DISM prerequisite", key, result[key])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
