"""Exercise Service Control Manager functionality with an original Windows service.

The service does no work beyond reporting SERVICE_RUNNING and responding to STOP.
Use only a temporary Wine prefix or a short-lived authorized Windows CI runner.
"""
from __future__ import annotations
import argparse
import json
import subprocess
import time
from pathlib import Path
from scripts.functional_smoke import execute, wine_environment, wine_path
from swcompat.cli import find_wine

SEQUENCE = ("absent", "install", "start", "stop", "delete", "absent")
STATE = {"start": "4", "stop": "1"}  # SERVICE_RUNNING, SERVICE_STOPPED


def succeeded(data: dict, phase: str) -> bool:
    lines = set(data.get("output", "").splitlines())
    return (data.get("exit_code") == 0
            and f"SWCOMPAT_SERVICE_PHASE={phase}" in lines
            and "SWCOMPAT_SERVICE_CHECK=PASS" in lines
            and (phase not in STATE or f"SWCOMPAT_SERVICE_STATE={STATE[phase]}" in lines))


def _run_sequence(host: str, wine: str | None, prefix: Path, exe: Path,
                  diagnose_access: bool = False) -> dict:
    if not exe.is_file():
        raise ValueError(f"Service test executable missing: {exe}")
    env = wine_environment(prefix, host)
    binary_path = wine_path(exe) if host == "wine" else str(exe)
    command = [str(exe)] if host == "native" else [str(wine), str(exe)]
    report = {"scenario": "service_create_start_stop_delete", "host": host}
    def run(phase: str) -> dict:
        args = [phase]
        if phase == "install":
            args.append(binary_path)
        return execute(command + args, env, timeout=45)

    before = run("absent")
    report["before"] = before
    if not succeeded(before, "absent"):
        report["passed"] = False
        report["reason"] = "A service with the fixed test name already exists"
        return report

    try:
        report["install"] = run("install")
        if succeeded(report["install"], "install"):
            # Some Wine service databases take a moment to expose a newly
            # created service to another Windows process. Record that delay.
            for attempt in range(25):
                observation = run("status")
                report["registration_visibility"] = observation
                report["registration_poll_attempts"] = attempt + 1
                if succeeded(observation, "status"):
                    break
                time.sleep(0.4)

            if succeeded(report["registration_visibility"], "status"):
                if diagnose_access:
                    report["access_rights"] = run("access")
                # Wine's service database can briefly return 1055 (locked)
                # or 1060 (not visible) while services.exe finishes startup.
                # Only retry these diagnosed transients; do not mask failures.
                for attempt in range(12):
                    report["start"] = run("start")
                    report["startup_attempts"] = attempt + 1
                    if succeeded(report["start"], "start"):
                        break
                    markers = set(report["start"].get("output", "").splitlines())
                    if not ({"SWCOMPAT_SERVICE_ERROR=1055",
                             "SWCOMPAT_SERVICE_ERROR=1060"} & markers):
                        break
                    if attempt < 11:
                        time.sleep(4.0)
                if succeeded(report["start"], "start"):
                    report["after_start"] = run("status")
                    if succeeded(report["after_start"], "status"):
                        report["stop"] = run("stop")
    finally:
        if "stop" not in report:
            report["cleanup_stop"] = run("stop")
        report["delete"] = run("delete")
        report["after"] = run("absent")
        # DeleteService marks a service for deletion; an in-flight process or
        # Wine service database update can delay final disappearance.
        if succeeded(report["delete"], "delete"):
            for attempt in range(25):
                if succeeded(report["after"], "absent"):
                    break
                time.sleep(0.4)
                report["after"] = run("absent")
                report["deletion_poll_attempts"] = attempt + 2

    report["passed"] = all(succeeded(report.get(name, {}), phase)
        for name, phase in (("before", "absent"), ("install", "install"),
                            ("registration_visibility", "status"),
                            ("start", "start"), ("after_start", "status"),
                            ("stop", "stop"), ("delete", "delete"),
                            ("after", "absent")))
    report["passed"] = report["passed"] and (
        "SWCOMPAT_SERVICE_STATE=4" in
        report.get("after_start", {}).get("output", "").splitlines())
    report["scope"] = (
        "Original harmless Windows service tests SCM create, start, running, "
        "stop and deregistration. No SOLIDWORKS service, kernel driver or "
        "licensing behavior tested.")
    return report


def run_sequence(host: str, wine: str | None, prefix: Path, exe: Path,
                 keepalive: bool = False, diagnose_access: bool = False) -> dict:
    if not keepalive:
        return _run_sequence(host, wine, prefix, exe, diagnose_access=diagnose_access)
    if host != "wine" or not wine:
        raise ValueError("The keepalive experiment is restricted to a Wine prefix")
    if not exe.is_file():
        raise ValueError(f"Missing harmless Wine test executable: {exe}")
    env = wine_environment(prefix, "wine")
    keeper = subprocess.Popen([str(wine), str(exe), "hold"], env=env,
                              stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL, start_new_session=True)
    try:
        time.sleep(1.0)
        if keeper.poll() is not None:
            raise ValueError("Wine keepalive client terminated before SCM test")
        report = _run_sequence(host, wine, prefix, exe, diagnose_access=diagnose_access)
        report["wine_keepalive_client"] = True
        return report
    finally:
        if keeper.poll() is None:
            keeper.terminate()
            try:
                keeper.wait(timeout=5)
            except subprocess.TimeoutExpired:
                keeper.kill()
                keeper.wait(timeout=5)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", choices=["wine", "native"], required=True)
    parser.add_argument("--prefix", type=Path, default=Path.home() / ".wine")
    parser.add_argument("--wine")
    parser.add_argument("--keepalive", action="store_true",
                        help="Keep an independent Wine client active between SCM operations")
    parser.add_argument("--diagnose-access", action="store_true",
                        help="Record individual SCM OpenServiceW rights after registration")
    parser.add_argument("--exe", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    wine = find_wine(args.wine) if args.host == "wine" else None
    if args.host == "wine" and not wine:
        parser.error("Wine executable unavailable")
    try:
        report = run_sequence(args.host, str(wine) if wine else None,
                              args.prefix.expanduser().resolve(), args.exe.expanduser().resolve(),
                              keepalive=args.keepalive,
                              diagnose_access=args.diagnose_access)
    except ValueError as exc:
        report = {"host": args.host, "passed": False, "error": str(exc)}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Windows service lifecycle: {'PASS' if report['passed'] else 'FAIL'}")
    for step in ("before","install","registration_visibility","access_rights","start","after_start","stop","cleanup_stop","delete","after"):
        if step in report:
            data=report[step]
            print(f"{step}: exit_code={data['exit_code']}")
            for line in data["output"].splitlines():
                if line.startswith("SWCOMPAT_SERVICE_"):
                    print(line[:300])
    print("Report:",args.output)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
