"""Functional, cross-process COM activation and cleanup in a disposable Wine prefix."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from scripts.functional_smoke import execute, wine_environment, wine_path
from swcompat.cli import find_wine

PHASES = ("absent", "register", "activate", "unregister", "absent")


def completed(run: dict, phase: str) -> bool:
    return (run.get("exit_code") == 0
            and "SWCOMPAT_COM_CHECK=PASS" in run.get("output", "").splitlines()
            and f"SWCOMPAT_COM_PHASE={phase}" in run.get("output", "").splitlines())


def lifecycle(host: str, wine: str | None, prefix: Path,
              checker: Path, server: Path) -> dict:
    if not checker.is_file() or not server.is_file():
        raise ValueError("Both self-authored COM binaries are required")
    env = wine_environment(prefix, host)
    dll_argument = wine_path(server) if host == "wine" else str(server)
    report = {"host": host, "scenario": "user_scoped_com_registration_activation"}
    prefix_cmd = [wine] if host == "wine" else []

    def run(phase: str) -> dict:
        args = [str(checker), phase]
        if phase in ("register", "unregister"):
            args.append(dll_argument)
        return execute(prefix_cmd + args, env, timeout=60)

    # Start from a clean test registration, but never hide whether it was dirty.
    report["before"] = run("absent")
    if not completed(report["before"], "absent"):
        report["passed"] = False
        report["reason"] = "Test COM class unexpectedly registered before starting"
        report["cleanup"] = run("unregister")
        return report

    try:
        report["register"] = run("register")
        if completed(report["register"], "register"):
            report["activate"] = run("activate")
    finally:
        report["unregister"] = run("unregister")
        report["after"] = run("absent")

    report["passed"] = all(completed(report.get(key, {}), phase)
                           for key, phase in (("before", "absent"),
                                              ("register", "register"),
                                              ("activate", "activate"),
                                              ("unregister", "unregister"),
                                              ("after", "absent")))
    report["scope"] = ("Registers an original HKCU COM server DLL and activates it "
                       "in a separate Win32 process; not SOLIDWORKS COM compatibility")
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", choices=["native", "wine"], required=True)
    parser.add_argument("--wine", default=None)
    parser.add_argument("--prefix", type=Path, default=Path.home() / ".wine")
    parser.add_argument("--checker", type=Path, required=True)
    parser.add_argument("--dll", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    wine = find_wine(args.wine) if args.host == "wine" else None
    if args.host == "wine" and not wine:
        parser.error("Wine binary unavailable")
    try:
        result = lifecycle(args.host, str(wine) if wine else None,
                           args.prefix.expanduser().resolve(),
                           args.checker.resolve(), args.dll.resolve())
    except ValueError as exc:
        result = {"host": args.host, "passed": False, "error": str(exc)}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print("COM lifecycle: " + ("PASS" if result["passed"] else "FAIL"))
    for stage in ("before", "register", "activate", "unregister", "after", "cleanup"):
        if stage in result:
            entry = result[stage]
            print(f"{stage}: exit={entry['exit_code']}")
            for line in entry["output"].splitlines():
                if line.startswith("SWCOMPAT_COM_"):
                    print("  " + line[:220])
    print("Report:", args.output)
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
