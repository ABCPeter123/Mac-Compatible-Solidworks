"""Sanitized summary of the independent Windows WebView2 loader probe.

No source log lines, executable paths, installed browser versions or private
metadata are exported. A loader query is not a browser-controller smoke test.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re

MAX_LOG_BYTES = 512 * 1024
VALID_RUNTIME = {"VERSION_FOUND", "NOT_DISCOVERED"}
HRESULT = re.compile(r"0x[0-9A-Fa-f]{8}\Z")


def summarize(text: str, exit_code: int) -> dict:
    """Allowlist only exact probe markers, excluding all arbitrary log content."""
    values: dict[str, list[str]] = {}
    for line in text.splitlines():
        if not line.startswith("SWCOMPAT_WEBVIEW2_"):
            continue
        if "=" not in line or len(line) > 160:
            continue
        key, value = line.split("=", 1)
        if key in (
            "SWCOMPAT_WEBVIEW2_RUNTIME",
            "SWCOMPAT_WEBVIEW2_LOADER",
            "SWCOMPAT_WEBVIEW2_PROBE",
            "SWCOMPAT_WEBVIEW2_VERSION_QUERY_HRESULT",
        ):
            values.setdefault(key, []).append(value.strip())

    def one(name: str) -> str | None:
        v = values.get("SWCOMPAT_WEBVIEW2_" + name, [])
        return v[0] if len(v) == 1 else None

    loader = one("LOADER")
    runtime = one("RUNTIME")
    probe = one("PROBE")
    code = one("VERSION_QUERY_HRESULT")
    valid_code = code is not None and HRESULT.fullmatch(code) is not None
    return_code = int(code, 16) if valid_code else None
    coherent = (
        valid_code
        and runtime in VALID_RUNTIME
        and (runtime == "VERSION_FOUND") == ((return_code & 0x80000000) == 0)
    )
    passed = (exit_code == 0 and loader == "PASS"
              and probe == "COMPLETE" and coherent)
    return {
        "schema": 1,
        "component": "Microsoft WebView2 SDK x64 loader query",
        "probe_result": "COMPLETE" if passed else "FAILED_OR_INCOMPLETE",
        "loader_callable": passed,
        "runtime_discovery": runtime if passed else "UNKNOWN",
        "query_hresult": code.upper() if passed else None,
        "runtime_controller_creation": "NOT_TESTED",
        "solidworks_compatibility": "NOT_DEMONSTRATED",
        "interpretation": (
            "VERSION_FOUND means only that the SDK loader returned a browser version. "
            "NOT_DISCOVERED means its version lookup failed; the exact cause is not "
            "established. Neither state proves WebView2 controller creation, "
            "SOLIDWORKS installation, activation, or CAD functionality."
        ),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Summarize Windows WebView2 loader probe safely")
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--exit-code", type=int, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        src = args.input.expanduser().resolve(strict=True)
        dst = args.output.expanduser().resolve(strict=False)
        if src == dst:
            raise ValueError("Output must not replace the input")
        with src.open("rb") as stream:
            data = stream.read(MAX_LOG_BYTES + 1)
        if len(data) > MAX_LOG_BYTES:
            raise ValueError("Probe log exceeds input limit")
        report = summarize(data.decode("utf-8", errors="replace"), args.exit_code)
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    except (ValueError, OSError) as exc:
        parser.error(str(exc) if isinstance(exc, ValueError) else "Cannot process probe log")
    print("WebView2 SDK loader query:", report["probe_result"])
    print("Browser runtime version query:", report["runtime_discovery"])
    print("WebView2 controller creation: NOT_TESTED")
    return 0 if report["probe_result"] == "COMPLETE" else 1


if __name__ == "__main__":
    raise SystemExit(main())
