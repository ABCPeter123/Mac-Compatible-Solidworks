"""Tests for real PNG pixel decoding, Win32 diagnostic integrity, privacy."""
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
import zlib

from scripts.webview2_render_report import decode_samples, parse_markers, summarize


MARKERS = "\n".join([
    "SWCOMPAT_WV2_RENDER_SCHEMA=1",
    "SWCOMPAT_WV2_RENDER_ENVIRONMENT=READY",
    "SWCOMPAT_WV2_RENDER_CONTROLLER=READY",
    "SWCOMPAT_WV2_RENDER_NAVIGATION=PASS",
    "SWCOMPAT_WV2_RENDER_DOM=PASS",
    "SWCOMPAT_WV2_RENDER_CAPTURE_PREVIEW=PASS",
    "SWCOMPAT_WV2_RENDER_PREVIEW=CAPTURE_PREVIEW",
    "SWCOMPAT_WV2_RENDER_PROBE=PASS",
]) + "\n"


def chunk(name, data):
    return (struct.pack(">I", len(data)) + name + data
            + struct.pack(">I", zlib.crc32(name + data) & 0xffffffff))


def make_png(w=240, h=180, *, fg=(29, 205, 91), bg=(19, 83, 147),
             filter_type=0, alpha=False):
    bpp = 4 if alpha else 3
    rows = []
    previous = bytes(w * bpp)
    for y in range(h):
        row = bytearray()
        for x in range(w):
            color = fg if w // 4 <= x < w * 3 // 4 and h // 4 <= y < h * 3 // 4 else bg
            row.extend(color + ((255,) if alpha else ()))
        encoded = bytearray(row)
        for i in range(len(row)):
            left = row[i - bpp] if i >= bpp else 0
            up = previous[i]
            upper_left = previous[i - bpp] if i >= bpp else 0
            if filter_type == 1:
                prediction = left
            elif filter_type == 2:
                prediction = up
            elif filter_type == 3:
                prediction = (left + up) // 2
            elif filter_type == 4:
                p = left + up - upper_left
                distances = [abs(p - v) for v in (left, up, upper_left)]
                prediction = (left, up, upper_left)[distances.index(min(distances))]
            else:
                prediction = 0
            encoded[i] = (row[i] - prediction) & 255
        rows.append(bytes([filter_type]) + bytes(encoded))
        previous = bytes(row)
    header = struct.pack(">IIBBBBB", w, h, 8, 6 if alpha else 2, 0, 0, 0)
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", header)
            + chunk(b"IDAT", zlib.compress(b"".join(rows), 6))
            + chunk(b"IEND", b""))


class RenderReportTests(unittest.TestCase):
    def test_real_rgb_png_pixels_pass(self):
        png = make_png()
        report = summarize(MARKERS, 0, png)
        self.assertEqual(report["result"], "PASS")
        self.assertEqual(report["screenshot_width"], 240)
        self.assertEqual(report["screenshot_height"], 180)
        self.assertEqual(report["screenshot_pixel_validation"], "PASS")
        self.assertEqual(report["solidworks_compatibility"], "NOT_DEMONSTRATED")

    def test_cdp_fallback_can_validate_true_pixels_after_preview_timeout(self):
        markers = (MARKERS.replace("SWCOMPAT_WV2_RENDER_CAPTURE_PREVIEW=PASS",
                                   "SWCOMPAT_WV2_RENDER_CAPTURE_PREVIEW=TIMEOUT")
                   .replace("SWCOMPAT_WV2_RENDER_PREVIEW=CAPTURE_PREVIEW",
                            "SWCOMPAT_WV2_RENDER_PREVIEW=CDP_FALLBACK"))
        result = summarize(markers, 0, make_png())
        self.assertEqual(result["result"], "PASS")
        self.assertEqual(result["png_capture_method"], "CDP_FALLBACK")
        self.assertEqual(result["capture_preview_api"], "TIMEOUT")

    def test_cdp_fallback_will_not_mask_blank_pixels(self):
        markers = (MARKERS.replace("SWCOMPAT_WV2_RENDER_CAPTURE_PREVIEW=PASS",
                                   "SWCOMPAT_WV2_RENDER_CAPTURE_PREVIEW=TIMEOUT")
                   .replace("SWCOMPAT_WV2_RENDER_PREVIEW=CAPTURE_PREVIEW",
                            "SWCOMPAT_WV2_RENDER_PREVIEW=CDP_FALLBACK"))
        result = summarize(markers, 0, make_png(fg=(19, 83, 147)))
        self.assertEqual(result["result"], "FAIL")
        self.assertEqual(result["failure_stage"], "PIXEL_VALIDATION")

    def test_invalid_capture_method_and_result_pair_rejected(self):
        markers = MARKERS.replace("SWCOMPAT_WV2_RENDER_CAPTURE_PREVIEW=PASS",
                                  "SWCOMPAT_WV2_RENDER_CAPTURE_PREVIEW=TIMEOUT")
        self.assertEqual(summarize(markers, 0, make_png())["result"], "FAIL")
        markers = MARKERS.replace("SWCOMPAT_WV2_RENDER_PREVIEW=CAPTURE_PREVIEW",
                                  "SWCOMPAT_WV2_RENDER_PREVIEW=CDP_FALLBACK")
        self.assertEqual(summarize(markers, 0, make_png())["result"], "FAIL")

    def test_png_rgba_supported(self):
        self.assertEqual(summarize(MARKERS, 0, make_png(alpha=True))["result"], "PASS")

    def test_png_all_standard_row_filters(self):
        for method in (0, 1, 2, 3, 4):
            with self.subTest(method=method):
                png = make_png(filter_type=method)
                w, h, blue, green = decode_samples(png)
                self.assertEqual((w, h), (240, 180))
                self.assertEqual(blue, (19, 83, 147))
                self.assertEqual(green, (29, 205, 91))

    def test_blank_screenshot_fails_even_when_webview2_says_pass(self):
        result = summarize(MARKERS, 0, make_png(fg=(19, 83, 147)))
        self.assertEqual(result["result"], "FAIL")
        self.assertEqual(result["failure_stage"], "PIXEL_VALIDATION")

    def test_swapped_background_and_foreground_fails(self):
        png = make_png(bg=(29, 205, 91), fg=(19, 83, 147))
        self.assertEqual(summarize(MARKERS, 0, png)["result"], "FAIL")

    def test_png_crc_and_trailing_bytes_rejected(self):
        png = make_png()
        bad = bytearray(png)
        bad[29] ^= 1
        with self.assertRaises(ValueError):
            decode_samples(bad)
        with self.assertRaises(ValueError):
            decode_samples(png + b"secret")

    def test_invalid_png_or_missing_image_not_accepted(self):
        for data in (b"", b"not a png", None):
            with self.subTest(data=data):
                self.assertEqual(summarize(MARKERS, 0, data)["result"], "FAIL")

    def test_duplicate_marker_is_not_a_pass(self):
        marker = MARKERS + "SWCOMPAT_WV2_RENDER_PROBE=PASS\n"
        self.assertEqual(summarize(marker, 0, make_png())["result"], "FAIL")

    def test_process_exit_code_is_required(self):
        self.assertEqual(summarize(MARKERS, 1, make_png())["result"], "FAIL")

    def test_explicit_failure_stage_is_classified(self):
        log = ("SWCOMPAT_WV2_RENDER_STAGE=PREVIEW_CALLBACK\n"
               "SWCOMPAT_WV2_RENDER_HRESULT=0x80004005\n"
               "SWCOMPAT_WV2_RENDER_PROBE=FAIL\n")
        result = summarize(log, 1, None)
        self.assertEqual(result["result"], "FAIL")
        self.assertEqual(result["failure_stage"], "PREVIEW_CALLBACK")

    def test_injected_failure_stage_rejected(self):
        log = ("SWCOMPAT_WV2_RENDER_STAGE=/private/secret\n"
               "SWCOMPAT_WV2_RENDER_HRESULT=0xDEADBEEF\n"
               "SWCOMPAT_WV2_RENDER_PROBE=FAIL\n")
        self.assertEqual(summarize(log, 1, None)["failure_stage"], "UNKNOWN")

    def test_untrusted_log_never_reaches_json(self):
        text = MARKERS + "/home/PRIVATE_USER/my_license.key\nemail@example.com\n"
        result = json.dumps(summarize(text, 0, make_png()))
        self.assertNotIn("PRIVATE_USER", result)
        self.assertNotIn("my_license", result)
        self.assertNotIn("email@example.com", result)

    def test_unsupported_png_size_rejected(self):
        png = make_png()
        modified = (png[:16] + struct.pack(">I", 4096) + png[20:])
        with self.assertRaises(ValueError):
            decode_samples(modified)

    def test_cli_reports_only_synthetic_test_metadata(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "probe.log").write_text(MARKERS + "Secret user /home/PRIVATE\n")
            (root / "swcompat-webview2-preview.png").write_bytes(make_png())
            result = root / "report.json"
            cmd = [sys.executable, "-m", "scripts.webview2_render_report",
                   "--input", str(root / "probe.log"),
                   "--screenshot", str(root / "swcompat-webview2-preview.png"),
                   "--output", str(result), "--exit-code", "0"]
            p = subprocess.run(cmd, capture_output=True, text=True)
            self.assertEqual(p.returncode, 0, p.stderr)
            record = result.read_text()
            self.assertEqual(json.loads(record)["result"], "PASS")
            self.assertNotIn(str(root), record)
            self.assertNotIn("PRIVATE", record)

    def test_cli_bad_picture_is_nonzero_with_sanitized_output(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "probe.log").write_text(MARKERS)
            (root / "preview.png").write_bytes(b"PNG but not really")
            result = root / "result.json"
            p = subprocess.run([sys.executable, "-m", "scripts.webview2_render_report",
                                "--input", str(root / "probe.log"),
                                "--screenshot", str(root / "preview.png"),
                                "--output", str(result), "--exit-code", "0"],
                               capture_output=True, text=True)
            self.assertNotEqual(p.returncode, 0)
            self.assertEqual(json.loads(result.read_text())["result"], "FAIL")


if __name__ == "__main__":
    unittest.main()
