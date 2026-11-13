import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from scripts.webview2_layout_report import summarize

GOOD = (
    "SWCOMPAT_WV2_LAYOUT_CSS=PASS\n"
    "SWCOMPAT_WV2_LAYOUT_RAF=TICKED\n"
    "SWCOMPAT_WV2_LAYOUT_PROBE=COMPLETE\n"
)


class LayoutReportTests(unittest.TestCase):
    def test_layout_and_frame_tick(self):
        r = summarize(GOOD)
        self.assertEqual(r["diagnostic"], "COMPLETE")
        self.assertEqual(r["css_box_layout_hit_testing"], "PASS")
        self.assertEqual(r["request_animation_frame"], "TICKED")
        self.assertEqual(r["compositor_output"], "NOT_VERIFIED")

    def test_frame_stall_is_valid_negative_diagnostic(self):
        r = summarize(GOOD.replace("RAF=TICKED", "RAF=STALLED"))
        self.assertEqual(r["diagnostic"], "COMPLETE")
        self.assertEqual(r["request_animation_frame"], "STALLED")
        self.assertEqual(r["browser_window_pixels"], "NOT_TESTED_HERE")

    def test_script_failure_is_separate_diagnostic(self):
        r = summarize(GOOD.replace("RAF=TICKED", "RAF=SCRIPT_FAILED"))
        self.assertEqual(r["diagnostic"], "COMPLETE")
        self.assertEqual(r["request_animation_frame"], "SCRIPT_FAILED")

    def test_no_css_layout_is_incomplete(self):
        self.assertEqual(summarize(GOOD.replace("LAYOUT_CSS=PASS", "LAYOUT_CSS=BAD"))["diagnostic"], "INCOMPLETE")

    def test_missing_raf_is_incomplete(self):
        self.assertEqual(summarize(GOOD.replace("SWCOMPAT_WV2_LAYOUT_RAF=TICKED\n", ""))["diagnostic"], "INCOMPLETE")

    def test_missing_done_is_incomplete(self):
        self.assertEqual(summarize(GOOD.replace("SWCOMPAT_WV2_LAYOUT_PROBE=COMPLETE\n", ""))["diagnostic"], "INCOMPLETE")

    def test_duplicate_statuses_are_rejected(self):
        for marker in GOOD.splitlines():
            with self.subTest(marker=marker):
                self.assertEqual(summarize(GOOD + marker + "\n")["diagnostic"], "INCOMPLETE")

    def test_unauthorized_raf_value_is_rejected(self):
        self.assertEqual(summarize(GOOD.replace("RAF=TICKED", "RAF=SECRET"))["diagnostic"], "INCOMPLETE")

    def test_untrusted_log_text_is_not_in_report(self):
        log = GOOD + "C:\\Users\\PRIVATE\\license.key\nmy@example.com\n"
        log += "SWCOMPAT_WV2_LAYOUT_OTHER=Secret\n"
        text = json.dumps(summarize(log))
        for secret in ["PRIVATE", "license.key", "my@example", "Secret"]:
            self.assertNotIn(secret, text)

    def test_empty_input_fails_closed(self):
        self.assertEqual(summarize("")["diagnostic"], "INCOMPLETE")

    def test_cli_success(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "log.txt").write_text(GOOD)
            p = subprocess.run(
                [sys.executable, "-m", "scripts.webview2_layout_report",
                 "--input", str(root / "log.txt"), "--output", str(root / "out.json")],
                capture_output=True, text=True)
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertEqual(json.loads((root / "out.json").read_text())["diagnostic"], "COMPLETE")

    def test_cli_incomplete_is_failure(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "log.txt").write_text(GOOD.replace("CSS=PASS", "CSS=BAD"))
            p = subprocess.run(
                [sys.executable, "-m", "scripts.webview2_layout_report",
                 "--input", str(root / "log.txt"), "--output", str(root / "out.json")],
                capture_output=True)
            self.assertNotEqual(p.returncode, 0)

    def test_cli_oversize_fails(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "log.txt").write_bytes(b"x" * (512 * 1024 + 1))
            p = subprocess.run(
                [sys.executable, "-m", "scripts.webview2_layout_report",
                 "--input", str(root / "log.txt"), "--output", str(root / "out.json")],
                capture_output=True)
            self.assertNotEqual(p.returncode, 0)
            self.assertFalse((root / "out.json").exists())

    def test_cli_same_path_fails(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "log.txt").write_text(GOOD)
            p = subprocess.run(
                [sys.executable, "-m", "scripts.webview2_layout_report",
                 "--input", str(root / "log.txt"), "--output", str(root / "log.txt")],
                capture_output=True)
            self.assertNotEqual(p.returncode, 0)


if __name__ == "__main__":
    unittest.main()
