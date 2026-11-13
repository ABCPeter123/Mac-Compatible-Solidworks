"""Read exact Chromium CSS layout / animation-frame markers from the Win32 probe.

This report distinguishes CSS layout and hit testing from presentation cadence.
No browser window pixels, page content, paths, or process logs are exported.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path

MAX_LOG_BYTES = 512 * 1024
RAF = frozenset({"TICKED", "STALLED", "SCRIPT_FAILED"})
FIELDS = frozenset({"CSS", "RAF", "PROBE"})


def summarize(raw: str) -> dict:
    marks: dict[str, list[str]] = {}
    for line in raw.splitlines():
        if not line.startswith("SWCOMPAT_WV2_LAYOUT_") or len(line) > 120 or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.removeprefix("SWCOMPAT_WV2_LAYOUT_")
        if key in FIELDS:
            marks.setdefault(key, []).append(value.strip())

    def only(key: str) -> str | None:
        values = marks.get(key, [])
        return values[0] if len(values) == 1 else None

    css = only("CSS") == "PASS"
    raf = only("RAF")
    complete = css and raf in RAF and only("PROBE") == "COMPLETE"
    return {
        "schema": 1,
        "component": "WebView2 CSS box geometry, hit testing and rAF scheduling",
        "diagnostic": "COMPLETE" if complete else "INCOMPLETE",
        "css_box_layout_hit_testing": "PASS" if css else "NOT_VERIFIED",
        "request_animation_frame": raf if complete else "UNKNOWN",
        "browser_window_pixels": "NOT_TESTED_HERE",
        "compositor_output": "NOT_VERIFIED",
        "solidworks_compatibility": "NOT_DEMONSTRATED",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate sanitized CSS and frame scheduling diagnostic")
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        src = args.input.expanduser().resolve(strict=True)
        dest = args.output.expanduser().resolve()
        if src == dest:
            raise ValueError("Source and output files must differ")
        with src.open("rb") as source:
            data = source.read(MAX_LOG_BYTES + 1)
        if len(data) > MAX_LOG_BYTES:
            raise ValueError("Source process log exceeds limit")
        result = summarize(data.decode("utf-8-sig", errors="replace"))
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    except (OSError, ValueError) as exc:
        parser.error(str(exc) if isinstance(exc, ValueError) else "Unable to read or write diagnostic")
    print("Chromium CSS layout/hit test:", result["css_box_layout_hit_testing"])
    print("Chromium animation frame callbacks:", result["request_animation_frame"])
    print("Layout diagnostic:", result["diagnostic"])
    print("Window pixels: NOT_TESTED_HERE")
    return 0 if result["diagnostic"] == "COMPLETE" else 1


if __name__ == "__main__":
    raise SystemExit(main())
