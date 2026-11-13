"""Fail-closed, privacy-limited WebView2 environment/controller probe report.

The input is stdout of the independent Windows probe, not arbitrary install
logs. Only fixed status markers and syntactically valid HRESULTs are exported.
A completed probe can observe a failed environment or controller; it is not a
successful browser/renderer test unless both stages report READY.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re

MAX_BYTES = 512 * 1024
HRESULT = re.compile(r"0x[0-9a-fA-F]{8}\Z")
STATUS_ENV = {"READY", "REQUEST_FAILED", "CALLBACK_FAILED", "TIMEOUT"}
STATUS_CONTROLLER = {
    "READY", "NOT_REACHED", "REQUEST_FAILED", "CALLBACK_FAILED",
    "INTERFACE_FAILED", "TIMEOUT",
}
FIELDS = {
    "SCHEMA", "WINDOW", "RUNTIME", "RUNTIME_HRESULT",
    "ENVIRONMENT", "ENVIRONMENT_HRESULT",
    "CONTROLLER", "CONTROLLER_HRESULT", "PROBE",
}


def summarize(log: str, exit_code: int) -> dict:
    recognized: dict[str, list[str]] = {}
    for line in log.splitlines():
        if not line.startswith("SWCOMPAT_WV2_") or "=" not in line or len(line) > 128:
            continue
        name, value = line.split("=", 1)
        name = name.removeprefix("SWCOMPAT_WV2_")
        if name in FIELDS:
            recognized.setdefault(name, []).append(value.strip())

    def once(name: str) -> str | None:
        values = recognized.get(name, [])
        return values[0] if len(values) == 1 else None

    runtime = once("RUNTIME")
    env = once("ENVIRONMENT")
    controller = once("CONTROLLER")

    def code(name: str) -> str | None:
        value = once(name)
        return value.upper() if value is not None and HRESULT.fullmatch(value) else None

    runtime_code = code("RUNTIME_HRESULT")
    env_code = code("ENVIRONMENT_HRESULT")
    controller_code = code("CONTROLLER_HRESULT")
    runtime_good = (
        runtime_code is not None
        and runtime in ("VERSION_FOUND", "NOT_DISCOVERED")
        and ((int(runtime_code, 16) < 0x80000000) == (runtime == "VERSION_FOUND"))
    )
    env_good = (
        env in STATUS_ENV and env_code is not None
        and ((int(env_code, 16) < 0x80000000) == (env == "READY"))
        and (env != "TIMEOUT" or env_code == "0X800705B4")
    )
    controller_good = (
        controller in STATUS_CONTROLLER
        and ((controller == "NOT_REACHED") == (env != "READY"))
        and (
            (controller == "NOT_REACHED" and controller_code is None
             and "CONTROLLER_HRESULT" not in recognized)
            or (controller != "NOT_REACHED" and controller_code is not None
                and ((int(controller_code, 16) < 0x80000000)
                     == (controller == "READY"))
                and (controller != "TIMEOUT" or controller_code == "0X800705B4"))
        )
    )
    valid = (
        exit_code == 0
        and once("SCHEMA") == "1"
        and once("WINDOW") == "PASS"
        and once("PROBE") == "COMPLETE"
        and runtime_good and env_good and controller_good
    )
    return {
        "schema": 1,
        "component": "Microsoft WebView2 SDK asynchronous Win32 environment/controller",
        "probe_result": "COMPLETE" if valid else "FAILED_OR_INCOMPLETE",
        "runtime_discovery": runtime if valid else "UNKNOWN",
        "environment_creation": env if valid else "UNKNOWN",
        "controller_creation": controller if valid else "UNKNOWN",
        "environment_hresult": env_code if valid else None,
        "controller_hresult": controller_code if valid else None,
        "controller_created": bool(valid and controller == "READY"),
        "html_rendering": "NOT_TESTED",
        "physical_input": "NOT_TESTED",
        "solidworks_compatibility": "NOT_DEMONSTRATED",
        "interpretation": (
            "COMPLETE means the bounded probe returned coherent diagnostic markers. "
            "Only READY means that the relevant WebView2 COM stage succeeded. "
            "No controller creation, HTML rendering, SOLIDWORKS installation, "
            "activation or CAD function is implied by a generic successful CI job."
        ),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Summarize original WebView2 Win32 environment smoke")
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--exit-code", type=int, required=True)
    parser.add_argument("--require-controller", action="store_true",
                        help="Fail unless the original Windows probe creates a real controller")
    args = parser.parse_args(argv)
    try:
        source = args.input.expanduser().resolve(strict=True)
        output = args.output.expanduser().resolve(strict=False)
        if source == output:
            raise ValueError("Cannot overwrite source input")
        with source.open("rb") as stream:
            raw = stream.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise ValueError("Probe log exceeds input limit")
        report = summarize(raw.decode("utf-8-sig", errors="replace"), args.exit_code)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    except (ValueError, OSError) as exc:
        parser.error(str(exc) if isinstance(exc, ValueError) else "Cannot read or write probe report")
    print("WebView2 environment/controller probe:", report["probe_result"])
    print("Runtime discovery:", report["runtime_discovery"])
    print("Environment:", report["environment_creation"])
    print("Controller:", report["controller_creation"])
    if report["probe_result"] != "COMPLETE":
        return 1
    if args.require_controller and not report["controller_created"]:
        print("Required real WebView2 controller: FAILED")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
