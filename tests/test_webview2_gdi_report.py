"""Strict framebuffer evidence tests, independent of browser screenshot APIs."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from scripts.webview2_gdi_report import summarize

LOG = "\n".join((
    "SWCOMPAT_WV2_GDI_SCHEMA=1",
    "SWCOMPAT_WV2_GDI_DOM=PASS",
    "SWCOMPAT_WV2_GDI_CLIENT=PIXELS_MATCH",
    "SWCOMPAT_WV2_GDI_DESKTOP=NO_MATCH",
    "SWCOMPAT_WV2_GDI_PROBE=COMPLETE",
)) + "\n"


class GdiReportTests(unittest.TestCase):
    def test_client_match(self):
        data = summarize(LOG)
        self.assertEqual(data["diagnostic"], "COMPLETE")
        self.assertEqual(data["gdi_pixel_evidence"], "VERIFIED")
        self.assertEqual(data["window_client_bitblt"], "PIXELS_MATCH")
        self.assertEqual(data["solidworks_compatibility"], "NOT_DEMONSTRATED")

    def test_desktop_match(self):
        log = LOG.replace("CLIENT=PIXELS_MATCH", "CLIENT=NO_MATCH").replace(
            "DESKTOP=NO_MATCH", "DESKTOP=PIXELS_MATCH")
        self.assertEqual(summarize(log)["gdi_pixel_evidence"], "VERIFIED")

    def test_both_no_match(self):
        log = LOG.replace("CLIENT=PIXELS_MATCH", "CLIENT=NO_MATCH")
        result = summarize(log)
        self.assertEqual(result["diagnostic"], "COMPLETE")
        self.assertEqual(result["gdi_pixel_evidence"], "NOT_VERIFIED")

    def test_both_api_failure(self):
        log = LOG.replace("CLIENT=PIXELS_MATCH", "CLIENT=API_FAILED").replace(
            "DESKTOP=NO_MATCH", "DESKTOP=API_FAILED")
        data = summarize(log)
        self.assertEqual(data["diagnostic"], "COMPLETE")
        self.assertEqual(data["gdi_pixel_evidence"], "NOT_VERIFIED")

    def test_api_fail_desktop_success(self):
        log = LOG.replace("CLIENT=PIXELS_MATCH", "CLIENT=API_FAILED").replace(
            "DESKTOP=NO_MATCH", "DESKTOP=PIXELS_MATCH")
        self.assertEqual(summarize(log)["gdi_pixel_evidence"], "VERIFIED")

    def test_duplicate_marker_is_fail_closed(self):
        result = summarize(LOG + "SWCOMPAT_WV2_GDI_CLIENT=PIXELS_MATCH\n")
        self.assertEqual(result["diagnostic"], "INCOMPLETE")
        self.assertEqual(result["gdi_pixel_evidence"], "UNKNOWN")

    def test_missing_dom_is_incomplete(self):
        log = LOG.replace("SWCOMPAT_WV2_GDI_DOM=PASS\n", "")
        self.assertEqual(summarize(log)["diagnostic"], "INCOMPLETE")

    def test_unknown_status_cannot_be_matched(self):
        log = LOG.replace("CLIENT=PIXELS_MATCH", "CLIENT=/PRIVATE/secret")
        self.assertEqual(summarize(log)["diagnostic"], "INCOMPLETE")

    def test_malformed_schema_and_end_marker_fail(self):
        self.assertEqual(summarize(LOG.replace("GDI_SCHEMA=1", "GDI_SCHEMA=2"))["diagnostic"],
                         "INCOMPLETE")
        self.assertEqual(summarize(LOG.replace("GDI_PROBE=COMPLETE", "GDI_PROBE=PASS"))["diagnostic"],
                         "INCOMPLETE")

    def test_untrusted_log_and_browser_version_excluded(self):
        log = LOG + (
            "C:\\Users\\PERSONAL\\SolidWorks\\license.dat\n"
            "secret@example.com\n"
            "SWCOMPAT_WV2_GDI_UNKNOWN=SECRET\n"
            "SWCOMPAT_WV2_GDI_STATUS=123.456\n"
        )
        result = json.dumps(summarize(log))
        for token in ["PERSONAL", "license.dat", "secret@example.com", "SECRET", "123.456"]:
            self.assertNotIn(token, result)

    def test_partial_log_cannot_look_like_pixel_success(self):
        self.assertEqual(summarize("SWCOMPAT_WV2_GDI_CLIENT=PIXELS_MATCH\n")["gdi_pixel_evidence"],
                         "UNKNOWN")

    def test_cli_can_report_completed_negative_without_require_pixels(self):
        with tempfile.TemporaryDirectory() as folder:
            src = Path(folder) / "synthetic.log"
            dest = Path(folder) / "report.json"
            src.write_text(LOG.replace("CLIENT=PIXELS_MATCH", "CLIENT=NO_MATCH"))
            proc = subprocess.run([sys.executable, "-m", "scripts.webview2_gdi_report",
                                   "--input", str(src), "--output", str(dest)],
                                  text=True, capture_output=True)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(json.loads(dest.read_text())["gdi_pixel_evidence"], "NOT_VERIFIED")

    def test_cli_require_pixels_refuses_negative(self):
        with tempfile.TemporaryDirectory() as folder:
            src = Path(folder) / "synthetic.log"
            dest = Path(folder) / "report.json"
            src.write_text(LOG.replace("CLIENT=PIXELS_MATCH", "CLIENT=NO_MATCH"))
            proc = subprocess.run([sys.executable, "-m", "scripts.webview2_gdi_report",
                                   "--input", str(src), "--output", str(dest),
                                   "--require-pixels"],
                                  text=True, capture_output=True)
            self.assertNotEqual(proc.returncode, 0)

    def test_cli_require_pixels_passes_actual_match(self):
        with tempfile.TemporaryDirectory() as folder:
            src = Path(folder) / "synthetic.log"
            dest = Path(folder) / "report.json"
            src.write_text(LOG)
            proc = subprocess.run([sys.executable, "-m", "scripts.webview2_gdi_report",
                                   "--input", str(src), "--output", str(dest),
                                   "--require-pixels"],
                                  text=True, capture_output=True)
            self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_cli_rejects_oversized_input(self):
        with tempfile.TemporaryDirectory() as folder:
            src = Path(folder) / "synthetic.log"
            dest = Path(folder) / "report.json"
            src.write_bytes(b"x" * (512 * 1024 + 1))
            proc = subprocess.run([sys.executable, "-m", "scripts.webview2_gdi_report",
                                   "--input", str(src), "--output", str(dest)],
                                  capture_output=True)
            self.assertNotEqual(proc.returncode, 0)
            self.assertFalse(dest.exists())

    def test_cli_input_equals_output_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            src = Path(folder) / "synthetic.log"
            src.write_text(LOG)
            proc = subprocess.run([sys.executable, "-m", "scripts.webview2_gdi_report",
                                   "--input", str(src), "--output", str(src)],
                                  capture_output=True)
            self.assertNotEqual(proc.returncode, 0)
            self.assertEqual(src.read_text(), LOG)


if __name__ == "__main__":
    unittest.main()
