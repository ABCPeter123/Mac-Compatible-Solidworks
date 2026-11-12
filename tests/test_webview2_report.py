import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from scripts.webview2_report import summarize


def lines(runtime="NOT_DISCOVERED", code="0x80070002"):
    return "\n".join([
        f"SWCOMPAT_WEBVIEW2_VERSION_QUERY_HRESULT={code}",
        f"SWCOMPAT_WEBVIEW2_RUNTIME={runtime}",
        "SWCOMPAT_WEBVIEW2_LOADER=PASS",
        "SWCOMPAT_WEBVIEW2_PROBE=COMPLETE",
    ]) + "\n"


class WebView2ReportTests(unittest.TestCase):
    def test_missing_runtime_is_not_loader_failure(self):
        report = summarize(lines(), 0)
        self.assertEqual(report["probe_result"], "COMPLETE")
        self.assertTrue(report["loader_callable"])
        self.assertEqual(report["runtime_discovery"], "NOT_DISCOVERED")
        self.assertEqual(report["runtime_controller_creation"], "NOT_TESTED")

    def test_present_runtime_is_discovery_only(self):
        report = summarize(lines("VERSION_FOUND", "0x00000000"), 0)
        self.assertEqual(report["probe_result"], "COMPLETE")
        self.assertEqual(report["runtime_discovery"], "VERSION_FOUND")
        self.assertEqual(report["solidworks_compatibility"], "NOT_DEMONSTRATED")

    def test_nonzero_exit_fails_even_if_markers_present(self):
        self.assertEqual(summarize(lines(), 1)["probe_result"], "FAILED_OR_INCOMPLETE")

    def test_duplicated_marker_fails(self):
        self.assertEqual(summarize(lines() + "SWCOMPAT_WEBVIEW2_LOADER=PASS\n", 0)["probe_result"],
                         "FAILED_OR_INCOMPLETE")

    def test_missing_marker_fails(self):
        self.assertEqual(summarize("SWCOMPAT_WEBVIEW2_PROBE=COMPLETE\n", 0)["probe_result"],
                         "FAILED_OR_INCOMPLETE")

    def test_bogus_success_code_fails(self):
        self.assertEqual(summarize(lines("NOT_DISCOVERED", "0x00000000"), 0)["probe_result"],
                         "FAILED_OR_INCOMPLETE")
        self.assertEqual(summarize(lines("VERSION_FOUND", "0x80070002"), 0)["probe_result"],
                         "FAILED_OR_INCOMPLETE")

    def test_rejects_arbitrary_codes_and_status(self):
        self.assertEqual(summarize(lines("TOP_SECRET", "private-code"), 0)["probe_result"],
                         "FAILED_OR_INCOMPLETE")

    def test_never_copies_private_log_lines(self):
        text = lines() + "C:\\Users\\PRIVATE_ACCOUNT\\serial-key.txt\nemail@example.com\n"
        result = json.dumps(summarize(text, 0))
        for s in ("PRIVATE_ACCOUNT", "serial-key", "email@example.com"):
            self.assertNotIn(s, result)

    def test_cli_output_contains_only_sanitized_metadata(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            src, dest = root / "private.txt", root / "result.json"
            src.write_text(lines() + "secret@example.com\n", encoding="utf-8")
            run = subprocess.run([sys.executable, "-m", "scripts.webview2_report",
                                  "--input", str(src), "--output", str(dest), "--exit-code", "0"],
                                 capture_output=True, text=True)
            self.assertEqual(run.returncode, 0, run.stderr)
            body = dest.read_text(encoding="utf-8")
            self.assertNotIn("secret@example.com", body)
            self.assertNotIn(str(root), body)
            self.assertEqual(json.loads(body)["probe_result"], "COMPLETE")

    def test_cli_rejects_oversized_log(self):
        with tempfile.TemporaryDirectory() as temp:
            src, dst = Path(temp) / "input.txt", Path(temp) / "out.json"
            src.write_bytes(b"A" * (512 * 1024 + 1))
            run = subprocess.run([sys.executable, "-m", "scripts.webview2_report",
                                  "--input", str(src), "--output", str(dst), "--exit-code", "0"],
                                 capture_output=True, text=True)
            self.assertNotEqual(run.returncode, 0)
            self.assertFalse(dst.exists())


if __name__ == "__main__":
    unittest.main()
