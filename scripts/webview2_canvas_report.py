"""Report Chromium Canvas 2D pixel/PNG operations independently of screen output.

The only accepted markers come from the original Windows x64 probe after
actual Chromium ExecuteScript callbacks. No canvas pixels or encoded page
bytes leave the runner. A complete diagnostic is not compositor evidence.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

MAX_LOG_BYTES = 512 * 1024
FIELDS = frozenset({"2D", "PNG", "PROBE"})


def summarize(log: str) -> dict:
    observed: dict[str, list[str]] = {}
    for line in log.splitlines():
        if not line.startswith("SWCOMPAT_WV2_CANVAS_") or len(line) > 120 or "=" not in line:
            continue
        field, value = line.split("=", 1)
        field = field.removeprefix("SWCOMPAT_WV2_CANVAS_")
        if field in FIELDS:
            observed.setdefault(field, []).append(value.strip())

    def once(key: str) -> str | None:
        entries = observed.get(key, [])
        return entries[0] if len(entries) == 1 else None

    two_d = once("2D") == "PASS"
    png = once("PNG") == "PASS"
    complete = two_d and png and once("PROBE") == "COMPLETE"
    return {
        "schema": 1,
        "component": "WebView2 internal HTML Canvas 2D pixels and PNG encoding",
        "result": "COMPLETE" if complete else "INCOMPLETE",
        "canvas_2d_get_image_data": "PASS" if two_d else "NOT_VERIFIED",
        "canvas_2d_expected_rgb": "VERIFIED" if two_d else "NOT_VERIFIED",
        "canvas_to_data_url_png": "PASS" if png else "NOT_VERIFIED",
        "window_compositor_pixels": "NOT_TESTED_HERE",
        "webview2_capture_preview": "NOT_TESTED_HERE",
        "solidworks_compatibility": "NOT_DEMONSTRATED",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate browser-internal Canvas 2D readback")
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        log = args.input.expanduser().resolve(strict=True)
        out = args.output.expanduser().resolve()
        if out == log:
            raise ValueError("Refusing to overwrite the source log")
        with log.open("rb") as stream:
            raw = stream.read(MAX_LOG_BYTES + 1)
        if len(raw) > MAX_LOG_BYTES:
            raise ValueError("Canvas probe log exceeds size limit")
        result = summarize(raw.decode("utf-8-sig", errors="replace"))
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    except (OSError, ValueError) as exc:
        parser.error(str(exc) if isinstance(exc, ValueError) else "Unable to read or write Canvas probe report")
    print("Canvas getImageData:", result["canvas_2d_get_image_data"])
    print("Canvas PNG encoder:", result["canvas_to_data_url_png"])
    print("WebView2 canvas diagnostic:", result["result"])
    print("Window compositor pixels: NOT_TESTED_HERE")
    print("SOLIDWORKS compatibility: NOT_DEMONSTRATED")
    return 0 if result["result"] == "COMPLETE" else 1


if __name__ == "__main__":
    raise SystemExit(main())
