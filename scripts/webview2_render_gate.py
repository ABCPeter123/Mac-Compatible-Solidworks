"""Fail-closed evidence gate for WebView2 browser-render diagnostics on Wine.

A completed diagnostic may prove a *known blocker*, not pixel rendering.
CI only tolerates the exact previously observed Chromium screenshot timeout
AFTER a genuine controller, successful DOM and completed GDI readback.
The --require-pixels switch remains strict for release/acceptance checks.
Only sanitized reports are accepted or exported.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

MAX_JSON_BYTES = 65536
RESULTS = {"SCREENSHOT_PIXELS_VERIFIED", "GDI_PIXELS_VERIFIED",
           "KNOWN_CAPTURE_BLOCKER", "UNEXPECTED_FAILURE"}


def classify(runtime: dict, render: dict, gdi: dict) -> dict:
    def safe(data: object, key: str):
        return data.get(key) if isinstance(data, dict) else None

    before, after = safe(runtime, "before"), safe(runtime, "after")
    runtime_ok = (
        safe(runtime, "schema") == 1
        and safe(runtime, "solidworks_compatibility") == "NOT_DEMONSTRATED"
        and safe(runtime, "installer_execution") == "EXIT_ZERO"
        and safe(runtime, "runtime_installation_confirmed") is True
        and safe(runtime, "browser_controller_confirmed") is True
        and safe(before, "probe_result") == "COMPLETE"
        and safe(before, "runtime_discovery") == "NOT_DISCOVERED"
        and safe(after, "probe_result") == "COMPLETE"
        and safe(after, "runtime_discovery") == "VERSION_FOUND"
        and safe(after, "environment_creation") == "READY"
        and safe(after, "controller_creation") == "READY"
        and safe(after, "controller_created") is True
    )
    gdi_client = safe(gdi, "window_client_bitblt")
    gdi_desktop = safe(gdi, "desktop_bitblt")
    gdi_ok = (
        safe(gdi, "schema") == 1
        and safe(gdi, "diagnostic") == "COMPLETE"
        and safe(gdi, "dom_execution") == "PASS"
        and safe(gdi, "solidworks_compatibility") == "NOT_DEMONSTRATED"
        and gdi_client in {"PIXELS_MATCH", "NO_MATCH", "API_FAILED"}
        and gdi_desktop in {"PIXELS_MATCH", "NO_MATCH", "API_FAILED"}
        and safe(gdi, "gdi_pixel_evidence")
        == ("VERIFIED" if "PIXELS_MATCH" in (gdi_client, gdi_desktop) else "NOT_VERIFIED")
    )
    render_ok = safe(render, "schema") == 1 and safe(render, "solidworks_compatibility") == "NOT_DEMONSTRATED"
    screenshot_proven = (
        render_ok and safe(render, "result") == "PASS"
        and safe(render, "screenshot_pixel_validation") == "PASS"
        and safe(render, "failure_stage") == "NONE"
        and safe(render, "png_capture_method") in {"CAPTURE_PREVIEW", "CDP_FALLBACK"}
    )
    known_timeout = (
        render_ok and safe(render, "result") == "FAIL"
        and safe(render, "screenshot_pixel_validation") == "FAIL"
        and safe(render, "failure_stage") == "CDP_TIMEOUT"
        and safe(render, "png_capture_method") == "UNKNOWN"
        and safe(render, "capture_preview_api") == "UNKNOWN"
    )
    if not (runtime_ok and gdi_ok):
        state = "UNEXPECTED_FAILURE"
    elif screenshot_proven:
        state = "SCREENSHOT_PIXELS_VERIFIED"
    elif safe(gdi, "gdi_pixel_evidence") == "VERIFIED":
        state = "GDI_PIXELS_VERIFIED"
    elif known_timeout:
        state = "KNOWN_CAPTURE_BLOCKER"
    else:
        state = "UNEXPECTED_FAILURE"
    pixel_proof = state in {"SCREENSHOT_PIXELS_VERIFIED", "GDI_PIXELS_VERIFIED"}
    return {
        "schema": 1,
        "component": "WebView2 Wine browser rendering evidence classification",
        "result": state,
        "diagnostic_complete": state != "UNEXPECTED_FAILURE",
        "controller_and_dom": "PASS" if runtime_ok and gdi_ok else "UNKNOWN",
        "browser_pixels": "VERIFIED" if pixel_proof else "NOT_VERIFIED",
        "browser_screenshot_api": "VERIFIED" if state == "SCREENSHOT_PIXELS_VERIFIED"
                                  else "NOT_VERIFIED",
        "capture_blocker": "CONFIRMED" if state == "KNOWN_CAPTURE_BLOCKER"
                           else "NOT_CLASSIFIED",
        "macos_pixel_rendering": "DEMONSTRATED_IN_HOSTED_TEST" if pixel_proof
                                 else "NOT_DEMONSTRATED",
        "solidworks_compatibility": "NOT_DEMONSTRATED",
    }


def load_report(path: Path) -> dict:
    with path.open("rb") as stream:
        data = stream.read(MAX_JSON_BYTES + 1)
    if len(data) > MAX_JSON_BYTES:
        raise ValueError("Report exceeds bounded size limit")
    result = json.loads(data)
    if not isinstance(result, dict):
        raise ValueError("Invalid report shape")
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Classify only exact sanitized Wine WebView2 rendering outcomes")
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--render", type=Path, required=True)
    parser.add_argument("--gdi", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--require-pixels", action="store_true",
                        help="Strict acceptance: reject a completed known negative diagnostic")
    args = parser.parse_args(argv)
    try:
        src = [p.expanduser().resolve(strict=True) for p in (args.runtime, args.render, args.gdi)]
        dst = args.output.expanduser().resolve()
        if dst in src:
            raise ValueError("Output must not overwrite evidence")
        result = classify(*(load_report(p) for p in src))
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        parser.error(str(exc) if isinstance(exc, ValueError) else "Cannot read sanitized evidence")
    print("WebView2 render diagnostic:", result["result"])
    print("Actual browser pixel proof:", result["browser_pixels"])
    print("Capture blocker:", result["capture_blocker"])
    print("SOLIDWORKS compatibility: NOT_DEMONSTRATED")
    if not result["diagnostic_complete"]:
        return 1
    return 0 if (not args.require_pixels or result["browser_pixels"] == "VERIFIED") else 1


if __name__ == "__main__":
    raise SystemExit(main())
