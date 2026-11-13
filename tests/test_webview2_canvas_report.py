"""Canvas 2D diagnostics must remain independent, complete and privacy-safe."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from scripts.webview2_canvas_report import summarize

COMPLETE = (
    "SWCOMPAT_WV2_CANVAS_2D=PASS\n"
    "SWCOMPAT_WV2_CANVAS_PNG=PASS\n"
    "SWCOMPAT_WV2_CANVAS_PROBE=COMPLETE\n"
)


class CanvasTests(unittest.TestCase):
    def test_complete(self):
        report = summarize(COMPLETE)
        self.assertEqual(report["result"], "COMPLETE")
        self.assertEqual(report["canvas_2d_expected_rgb"], "VERIFIED")
        self.assertEqual(report["canvas_to_data_url_png"], "PASS")
        self.assertEqual(report["window_compositor_pixels"], "NOT_TESTED_HERE")

    def test_both_missing(self):
        self.assertEqual(summarize("")["result"], "INCOMPLETE")

    def test_png_missing_rejects_complete(self):
        result = summarize(COMPLETE.replace("SWCOMPAT_WV2_CANVAS_PNG=PASS\n", ""))
        self.assertEqual(result["result"], "INCOMPLETE")
        self.assertEqual(result["canvas_to_data_url_png"], "NOT_VERIFIED")

    def test_pixel_missing_rejects_complete(self):
        result = summarize(COMPLETE.replace("SWCOMPAT_WV2_CANVAS_2D=PASS\n", ""))
        self.assertEqual(result["result"], "INCOMPLETE")
        self.assertEqual(result["canvas_2d_expected_rgb"], "NOT_VERIFIED")

    def test_probe_missing_rejects_complete(self):
        self.assertEqual(summarize(COMPLETE.replace("SWCOMPAT_WV2_CANVAS_PROBE=COMPLETE\n", ""))["result"], "INCOMPLETE")

    def test_duplicate_or_conflicting_marker_rejected(self):
        for field in ("2D=PASS", "PNG=PASS", "PROBE=COMPLETE"):
            with self.subTest(field=field):
                self.assertEqual(summarize(COMPLETE + "SWCOMPAT_WV2_CANVAS_" + field + "\n")["result"], "INCOMPLETE")

    def test_unrecognized_states_not_verification(self):
        for key in ("2D", "PNG", "PROBE"):
            with self.subTest(key=key):
                value = "COMPLETE" if key == "PROBE" else "PASS"
                self.assertEqual(summarize(COMPLETE.replace(f"CANVAS_{key}={value}", f"CANVAS_{key}=READY"))["result"], "INCOMPLETE")

    def test_no_private_content_or_version_in_json(self):
        raw = COMPLETE + (
            "C:\\Users\\PERSON\\SOLIDWORKS\\activation.txt\n"
            "SWCOMPAT_WV2_CANVAS_PRIVATE=Secret\n"
            "email@example.com\nVersion 137.2.31.1"
        )
        result = json.dumps(summarize(raw))
        for secret in ("PERSON", "activation", "Secret", "example.com", "137.2"):
            self.assertNotIn(secret, result)

    def test_success_markers_ignore_untrusted_messages(self):
        self.assertEqual(summarize("wine: noisy message\n" + COMPLETE)["result"], "COMPLETE")

    def test_exact_marker_case_required(self):
        self.assertEqual(summarize(COMPLETE.lower())["result"], "INCOMPLETE")

    def test_extra_equals_rejected(self):
        self.assertEqual(summarize(COMPLETE.replace("CANVAS_2D=PASS", "CANVAS_2D=PASS=YES"))["result"], "INCOMPLETE")

    @staticmethod
    def cli(folder: Path):
        return [
            sys.executable, "-m", "scripts.webview2_canvas_report",
            "--input", str(folder / "probe.log"), "--output", str(folder / "result.json"),
        ]

    def test_cli_complete(self):
        with tempfile.TemporaryDirectory() as t:
            folder = Path(t)
            (folder / "probe.log").write_text(COMPLETE)
            response = subprocess.run(self.cli(folder), capture_output=True, text=True)
            self.assertEqual(response.returncode, 0, response.stderr)
            self.assertEqual(json.loads((folder / "result.json").read_text())["result"], "COMPLETE")

    def test_cli_incomplete_is_failure(self):
        with tempfile.TemporaryDirectory() as t:
            folder = Path(t)
            (folder / "probe.log").write_text(COMPLETE.replace("CANVAS_PNG=PASS", "CANVAS_PNG=BAD"))
            response = subprocess.run(self.cli(folder), capture_output=True, text=True)
            self.assertNotEqual(response.returncode, 0)
            self.assertEqual(json.loads((folder / "result.json").read_text())["result"], "INCOMPLETE")

    def test_cli_oversized_log_fails_without_report(self):
        with tempfile.TemporaryDirectory() as t:
            folder = Path(t)
            (folder / "probe.log").write_bytes(b"x" * (512 * 1024 + 1))
            response = subprocess.run(self.cli(folder), capture_output=True)
            self.assertNotEqual(response.returncode, 0)
            self.assertFalse((folder / "result.json").exists())

    def test_cli_refuses_source_overwrite(self):
        with tempfile.TemporaryDirectory() as t:
            folder = Path(t)
            (folder / "probe.log").write_text(COMPLETE)
            args = self.cli(folder)
            args[-1] = str(folder / "probe.log")
            response = subprocess.run(args, capture_output=True)
            self.assertNotEqual(response.returncode, 0)
            self.assertEqual((folder / "probe.log").read_text(), COMPLETE)


if __name__ == "__main__":
    unittest.main()
