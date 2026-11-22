"""Verify Wine actually committed an initialized disposable prefix.

Wineboot can report process exit 0 before asynchronous wineserver registry
creation has finished. Never create system.reg or fabricate registration.
Allow one bounded genuine Wineboot update only in the exact marked ephemeral
CI prefix. The only emitted evidence is a finite category.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import time

PREFIX_NAME = "netfx40-msxml3-prefix"
SENTINEL = ".swcompat-netfx481-disposable"
STATES = {"READY", "MISSING_DRIVE", "MISSING_REGISTRY", "MISSING_BOTH"}
OUTCOMES = {
    "READY_IMMEDIATE", "READY_AFTER_SETTLE", "READY_AFTER_WINEBOOT",
    "WINEBOOT_FAILED", "WINEBOOT_TIMEOUT", "WINEBOOT_START_FAILED",
    "PREFIX_INCOMPLETE",
}
UPDATES = {"NOT_RUN", "EXIT_ZERO", "EXIT_NONZERO", "TIMEOUT", "START_FAILED"}


def _validate_input(wine: Path, prefix: Path) -> None:
    if os.name == "nt" or not os.environ.get("RUNNER_TEMP"):
        raise ValueError("Readiness check requires an ephemeral CI Wine host")
    runner = Path(os.environ["RUNNER_TEMP"])
    if (runner.is_symlink() or not runner.is_dir()
            or prefix.name != PREFIX_NAME
            or prefix.parent.resolve() != runner.resolve()
            or prefix.is_symlink() or not prefix.is_dir()
            or wine.is_symlink() or not wine.is_file()
            or not os.access(wine, os.X_OK)):
        raise ValueError("Invalid isolated Wine readiness input")
    for part in (prefix / SENTINEL, prefix / "drive_c", prefix / "system.reg"):
        if part.is_symlink():
            raise ValueError("Linked Wine prefix input refused")
    if not (prefix / SENTINEL).is_file():
        raise ValueError("Wine prefix must be explicitly marked disposable")


def _state(prefix: Path) -> str:
    # The marker was checked separately. The prefix must become complete
    # from Wine itself; touching system.reg would invalidate this trial.
    drive = (prefix / "drive_c").is_dir()
    registry = (prefix / "system.reg").is_file()
    if drive and registry:
        return "READY"
    if not drive and not registry:
        return "MISSING_BOTH"
    return "MISSING_DRIVE" if not drive else "MISSING_REGISTRY"


def _settle(prefix: Path, checks: int = 12) -> str:
    for attempt in range(checks):
        state = _state(prefix)
        if state == "READY":
            return state
        if attempt + 1 < checks:
            time.sleep(2)
    return _state(prefix)


def blank(initial: str, status: str, final: str, update: str) -> dict:
    return {
        "status": status,
        "initial": initial,
        "final": final,
        "update": update,
        "ready": status.startswith("READY_"),
    }


def valid(value: object) -> bool:
    if type(value) is not dict or set(value) != set(blank("READY", "READY_IMMEDIATE", "READY", "NOT_RUN")):
        return False
    if (value["initial"] not in STATES or value["final"] not in STATES
            or value["status"] not in OUTCOMES
            or value["update"] not in UPDATES
            or type(value["ready"]) is not bool
            or value["ready"] != value["status"].startswith("READY_")):
        return False
    status = value["status"]
    if status == "READY_IMMEDIATE":
        return value["initial"] == value["final"] == "READY" and value["update"] == "NOT_RUN"
    if status == "READY_AFTER_SETTLE":
        return (value["initial"] != "READY" and value["final"] == "READY"
                and value["update"] == "NOT_RUN")
    if status == "READY_AFTER_WINEBOOT":
        return value["final"] == "READY" and value["update"] == "EXIT_ZERO"
    if status == "PREFIX_INCOMPLETE":
        return value["final"] != "READY" and value["update"] == "EXIT_ZERO"
    return status == {
        "EXIT_NONZERO": "WINEBOOT_FAILED",
        "TIMEOUT": "WINEBOOT_TIMEOUT",
        "START_FAILED": "WINEBOOT_START_FAILED",
    }.get(value["update"]) and value["initial"] != "READY"


def inspect(wine: Path, prefix: Path) -> dict:
    _validate_input(wine, prefix)
    initial = _state(prefix)
    if initial == "READY":
        result = blank(initial, "READY_IMMEDIATE", "READY", "NOT_RUN")
    else:
        current = _settle(prefix)
        if current == "READY":
            result = blank(initial, "READY_AFTER_SETTLE", current, "NOT_RUN")
        else:
            env = os.environ.copy()
            env.update({
                "WINEPREFIX": str(prefix), "WINEARCH": "win64",
                "WINEDEBUG": "-all", "WINEDLLOVERRIDES": "mscoree,mshtml=d",
                "WINE_SKIP_MONO_INSTALLATION": "1",
                "WINE_SKIP_GECKO_INSTALLATION": "1",
            })
            try:
                run = subprocess.run(
                    [str(wine), "wineboot.exe", "--update"], cwd=prefix,
                    env=env, stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    timeout=90, check=False)
                update = "EXIT_ZERO" if run.returncode == 0 else "EXIT_NONZERO"
            except subprocess.TimeoutExpired:
                update = "TIMEOUT"
            except OSError:
                update = "START_FAILED"
            final = _settle(prefix) if update == "EXIT_ZERO" else _state(prefix)
            status = {
                "EXIT_NONZERO": "WINEBOOT_FAILED",
                "TIMEOUT": "WINEBOOT_TIMEOUT",
                "START_FAILED": "WINEBOOT_START_FAILED",
            }.get(update, "READY_AFTER_WINEBOOT" if final == "READY"
                  else "PREFIX_INCOMPLETE")
            result = blank(initial, status, final, update)
    assert valid(result)
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify genuine Wineboot prefix state")
    for field in ("wine", "prefix", "output"):
        parser.add_argument("--" + field, type=Path, required=True)
    parser.add_argument("--agree-disposable-prefix", action="store_true", required=True)
    args = parser.parse_args(argv)
    if args.output.is_symlink() or args.output.resolve().is_relative_to(args.prefix.resolve()):
        parser.error("Readiness report must be outside marked prefix")
    result = inspect(args.wine, args.prefix)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, sort_keys=True), encoding="ascii")
    for key in ("status", "initial", "final", "update", "ready"):
        print("Wine prefix initialization", key, result[key])
    return 0 if result["ready"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
