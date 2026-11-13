"""Sanitized GDI framebuffer diagnostics for a synthetic WebView2 test window.

The original Win32 executable samples only two fixed colors from its own
synthetic browser page. Logs can contain sensitive Wine diagnostics; keep
only a strict allowlist of the exact GDI markers. A process exit failure
from a separate screenshot API does not invalidate already completed
GDI observations. This report never claims SOLIDWORKS compatibility.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

MAX_BYTES = 512 * 1024
GDI_STATES = {"PIXELS_MATCH", "NO_MATCH", "API_FAILED"}
FIELDS = {"SCHEMA", "DOM", "CLIENT", "DESKTOP", "PROBE"}


def summarize(log: str) -> dict:
    observed: dict[str, list[str]] = {}
    for line in log.splitlines():
        if not line.startswith("SWCOMPAT_WV2_GDI_") or "=" not in line or len(line) > 128:
            continue
        key, value = line.split("=", 1)
        key = key.removeprefix("SWCOMPAT_WV2_GDI_")
        if key in FIELDS:
            observed.setdefault(key, []).append(value.strip())

    def once(field: str) -> str | None:
        values = observed.get(field, [])
        return values[0] if len(values) == 1 else None

    client, desktop = once("CLIENT"), once("DESKTOP")
    complete = (once("SCHEMA") == "1" and once("DOM") == "PASS"
                and once("PROBE") == "COMPLETE"
                and client in GDI_STATES and desktop in GDI_STATES)
    proof = complete and (client == "PIXELS_MATCH" or desktop == "PIXELS_MATCH")
    return {
        "schema": 1,
        "component": "Win32 GDI pixel readback of synthetic WebView2 HWND",
        "diagnostic": "COMPLETE" if complete else "INCOMPLETE",
        "dom_execution": "PASS" if complete else "UNKNOWN",
        "window_client_bitblt": client if complete else "UNKNOWN",
        "desktop_bitblt": desktop if complete else "UNKNOWN",
        "gdi_pixel_evidence": "VERIFIED" if proof else ("NOT_VERIFIED" if complete else "UNKNOWN"),
        "webview2_capture_preview": "NOT_EVALUATED_HERE",
        "webview2_devtools_screenshot": "NOT_EVALUATED_HERE",
        "physical_mac_display": "NOT_TESTED",
        "solidworks_compatibility": "NOT_DEMONSTRATED",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Report only allowlisted GDI pixel observations")
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--require-pixels", action="store_true",
                        help="Require matching blue and green pixel samples in a GDI readback")
    args = parser.parse_args(argv)
    try:
        inp = args.input.expanduser().resolve(strict=True)
        out = args.output.expanduser().resolve()
        if inp == out:
            raise ValueError("Cannot overwrite the source log")
        with inp.open("rb") as f:
            data = f.read(MAX_BYTES + 1)
        if len(data) > MAX_BYTES:
            raise ValueError("Probe log exceeds size limit")
        report = summarize(data.decode("utf-8-sig", errors="replace"))
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    except (OSError, ValueError) as exc:
        parser.error(str(exc) if isinstance(exc, ValueError) else "Cannot load or write local GDI evidence")
    print("GDI framebuffer diagnostics:", report["diagnostic"])
    print("HWND client readback:", report["window_client_bitblt"])
    print("Desktop readback:", report["desktop_bitblt"])
    print("Actual synthetic pixels:", report["gdi_pixel_evidence"])
    print("SOLIDWORKS compatibility: NOT_DEMONSTRATED")
    return 0 if (report["diagnostic"] == "COMPLETE"
                 and (not args.require_pixels or report["gdi_pixel_evidence"] == "VERIFIED")) else 1


if __name__ == "__main__":
    raise SystemExit(main())
