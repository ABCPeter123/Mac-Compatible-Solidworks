"""Verify an independently rendered WebView2 page and synthetic screenshot pixels.

No browser binaries, screenshot bytes, user paths, HTML, license details or
arbitrary process logs are exported. The validator accepts only fixed markers
and *pixels in a locally generated fixed-color synthetic page*. Screenshots
are never uploaded as GitHub Actions artifacts.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import struct
import zlib

MAX_LOG_BYTES = 512 * 1024
MAX_PNG_BYTES = 16 * 1024 * 1024
MAX_PIXELS = 2048 * 2048
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
FIELDS = {"SCHEMA", "ENVIRONMENT", "CONTROLLER", "NAVIGATION",
          "DOM", "PREVIEW", "PROBE"}
STAGES = {
    "LOADER", "LOADER_EXPORT", "COM", "WINDOW_CLASS", "WINDOW_CREATE",
    "TEMP_DIRECTORY", "ENVIRONMENT_REQUEST", "ENVIRONMENT_TIMEOUT",
    "ENVIRONMENT_CALLBACK", "CONTROLLER_REQUEST", "CONTROLLER_TIMEOUT",
    "CONTROLLER_CALLBACK", "WEBVIEW_INTERFACE", "CONTROLLER_BOUNDS",
    "CONTROLLER_VISIBLE", "NAVIGATION_HANDLER", "NAVIGATION_REQUEST",
    "NAVIGATION_TIMEOUT", "NAVIGATION_CALLBACK", "SCRIPT_REQUEST",
    "SCRIPT_TIMEOUT", "SCRIPT_DOM", "PREVIEW_STREAM", "PREVIEW_REQUEST",
    "PREVIEW_TIMEOUT", "PREVIEW_CALLBACK", "PREVIEW_WRITE",
}
HRESULT = re.compile(r"0x[0-9A-Fa-f]{8}\Z")


def parse_markers(stdout: str, exit_code: int) -> tuple[bool, str]:
    values: dict[str, list[str]] = {}
    for line in stdout.splitlines():
        if not line.startswith("SWCOMPAT_WV2_RENDER_") or "=" not in line or len(line) > 160:
            continue
        key, value = line.split("=", 1)
        key = key.removeprefix("SWCOMPAT_WV2_RENDER_")
        if key in FIELDS | {"STAGE", "HRESULT"}:
            values.setdefault(key, []).append(value.strip())

    def once(key: str) -> str | None:
        entries = values.get(key, [])
        return entries[0] if len(entries) == 1 else None

    passed = (
        exit_code == 0 and
        once("SCHEMA") == "1" and
        once("ENVIRONMENT") == "READY" and
        once("CONTROLLER") == "READY" and
        once("NAVIGATION") == "PASS" and
        once("DOM") == "PASS" and
        once("PREVIEW") == "PASS" and
        once("PROBE") == "PASS" and
        "STAGE" not in values and "HRESULT" not in values
    )
    if passed:
        return True, "NONE"
    stage = once("STAGE")
    code = once("HRESULT")
    if (exit_code != 0 and once("PROBE") == "FAIL" and
            stage in STAGES and code is not None and HRESULT.fullmatch(code)):
        return False, stage
    return False, "UNKNOWN"


def _paeth(a: int, b: int, c: int) -> int:
    p = a + b - c
    x, y, z = abs(p - a), abs(p - b), abs(p - c)
    return a if x <= y and x <= z else b if y <= z else c


def decode_samples(data: bytes) -> tuple[int, int, tuple[int, int, int], tuple[int, int, int]]:
    """Decode limited noninterlaced RGB/RGBA PNG and inspect two actual pixels.

    Strict bounds, CRCs and PNG scanline filters prevent trusting the filename
    alone. No third-party codecs or external resources are required.
    """
    if len(data) < 48 or len(data) > MAX_PNG_BYTES or not data.startswith(PNG_SIGNATURE):
        raise ValueError("PNG signature or byte-size failure")
    offset, width, height, bpp = len(PNG_SIGNATURE), None, None, None
    chunks: list[bytes] = []
    seen_ihdr = seen_iend = False
    while offset + 12 <= len(data):
        size = struct.unpack_from(">I", data, offset)[0]
        typ = data[offset + 4:offset + 8]
        end = offset + 12 + size
        if size > MAX_PNG_BYTES or end > len(data):
            raise ValueError("Invalid PNG chunk length")
        payload = data[offset + 8:offset + 8 + size]
        crc = struct.unpack_from(">I", data, offset + 8 + size)[0]
        if zlib.crc32(typ + payload) & 0xffffffff != crc:
            raise ValueError("Invalid PNG chunk CRC")
        if not seen_ihdr and typ != b"IHDR":
            raise ValueError("IHDR must precede image chunks")
        if typ == b"IHDR":
            if seen_ihdr or size != 13:
                raise ValueError("Invalid or duplicate IHDR")
            seen_ihdr = True
            width, height, depth, color, comp, filtering, interlace = struct.unpack(">IIBBBBB", payload)
            if (not 200 <= width <= 2048 or not 150 <= height <= 2048 or
                    width * height > MAX_PIXELS or depth != 8 or
                    color not in (2, 6) or comp or filtering or interlace):
                raise ValueError("Unsupported PNG dimensions or pixel format")
            bpp = 3 if color == 2 else 4
        elif typ == b"IDAT":
            if seen_iend:
                raise ValueError("IDAT after IEND")
            chunks.append(payload)
        elif typ == b"IEND":
            if size or seen_iend:
                raise ValueError("Malformed PNG end")
            seen_iend = True
            if end != len(data):
                raise ValueError("Trailing PNG bytes")
            break
        offset = end

    if not (seen_ihdr and seen_iend and chunks and width and height and bpp):
        raise ValueError("Incomplete PNG")
    stride = width * bpp
    expected = (stride + 1) * height
    # Limit inflated output; a malformed PNG cannot allocate unbounded memory.
    decomp = zlib.decompressobj()
    pixels = decomp.decompress(b"".join(chunks), expected + 1)
    if len(pixels) > expected or not decomp.eof or decomp.unused_data:
        raise ValueError("Unexpected PNG deflate stream length")
    pixels += decomp.flush()
    if len(pixels) != expected:
        raise ValueError("Incorrect PNG scanline length")

    blue_pos = (width // 10, height // 10)
    green_pos = (width // 2, height // 2)
    selections = {}
    prev = bytearray(stride)
    for row_index in range(height):
        start = row_index * (stride + 1)
        method = pixels[start]
        row = bytearray(pixels[start + 1:start + 1 + stride])
        if method > 4:
            raise ValueError("Unsupported PNG filter")
        for i in range(stride):
            left = row[i - bpp] if i >= bpp else 0
            above = prev[i]
            upper_left = prev[i - bpp] if i >= bpp else 0
            if method == 1:
                row[i] = (row[i] + left) & 255
            elif method == 2:
                row[i] = (row[i] + above) & 255
            elif method == 3:
                row[i] = (row[i] + (left + above) // 2) & 255
            elif method == 4:
                row[i] = (row[i] + _paeth(left, above, upper_left)) & 255
        for name, (col, target_row) in (("background", blue_pos), ("foreground", green_pos)):
            if row_index == target_row:
                idx = col * bpp
                selections[name] = tuple(row[idx:idx + 3])
        prev = row
    return width, height, selections["background"], selections["foreground"]


def _matches(actual: tuple[int, int, int], target: tuple[int, int, int]) -> bool:
    return all(abs(a - b) <= 20 for a, b in zip(actual, target))


def summarize(log: str, exit_code: int, screenshot: bytes | None) -> dict:
    probe_pass, failure_stage = parse_markers(log, exit_code)
    width = height = None
    pixels_pass = False
    if probe_pass and screenshot is not None:
        try:
            width, height, background, foreground = decode_samples(screenshot)
            pixels_pass = (_matches(background, (19, 83, 147))
                           and _matches(foreground, (29, 205, 91)))
        except (ValueError, KeyError, zlib.error, struct.error):
            pass
    full_pass = probe_pass and pixels_pass
    return {
        "schema": 1,
        "component": "Microsoft WebView2 local HTML / DOM / PNG pixel rendering",
        "result": "PASS" if full_pass else "FAIL",
        "browser_environment_and_controller": "READY" if probe_pass else "UNKNOWN",
        "local_html_navigation": "PASS" if probe_pass else "UNKNOWN",
        "javascript_dom_execution": "PASS" if probe_pass else "UNKNOWN",
        "png_capture": "PASS" if probe_pass else "UNKNOWN",
        "screenshot_pixel_validation": "PASS" if pixels_pass else "FAIL",
        "screenshot_width": width,
        "screenshot_height": height,
        "failure_stage": failure_stage if failure_stage != "NONE" else
            ("PIXEL_VALIDATION" if not pixels_pass else "NONE"),
        "network_navigation": "NOT_USED",
        "physical_input": "NOT_TESTED",
        "solidworks_compatibility": "NOT_DEMONSTRATED",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate WebView2 synthetic HTML and rendered PNG pixels")
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--screenshot", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--exit-code", type=int, required=True)
    args = parser.parse_args(argv)
    try:
        src = args.input.expanduser().resolve(strict=True)
        screenshot = args.screenshot.expanduser().resolve(strict=False)
        output = args.output.expanduser().resolve()
        if output in {src, screenshot}:
            raise ValueError("Report must not replace test evidence")
        with src.open("rb") as f:
            logs = f.read(MAX_LOG_BYTES + 1)
        if len(logs) > MAX_LOG_BYTES:
            raise ValueError("Process log size limit exceeded")
        png_data = None
        if screenshot.exists() and screenshot.is_file():
            with screenshot.open("rb") as f:
                png_data = f.read(MAX_PNG_BYTES + 1)
        report = summarize(logs.decode("utf-8-sig", errors="replace"),
                           args.exit_code, png_data)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    except (OSError, ValueError) as exc:
        parser.error(str(exc) if isinstance(exc, ValueError) else "Cannot load or write local probe evidence")
    print("WebView2 synthetic HTML and DOM rendering:", report["result"])
    print("Preview pixel verification:", report["screenshot_pixel_validation"])
    print("Stage:", report["failure_stage"])
    print("SOLIDWORKS compatibility: NOT_DEMONSTRATED")
    return 0 if report["result"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
