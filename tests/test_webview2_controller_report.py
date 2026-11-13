import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from scripts.webview2_controller_report import summarize


def log(*, runtime="VERSION_FOUND", runtime_hr="0x00000000",
        env="READY", env_hr="0x00000000",
        controller="READY", controller_hr="0x00000000"):
    lines = [
        "SWCOMPAT_WV2_SCHEMA=1",
        "SWCOMPAT_WV2_WINDOW=PASS",
        f"SWCOMPAT_WV2_RUNTIME={runtime}",
        f"SWCOMPAT_WV2_RUNTIME_HRESULT={runtime_hr}",
        f"SWCOMPAT_WV2_ENVIRONMENT={env}",
        f"SWCOMPAT_WV2_ENVIRONMENT_HRESULT={env_hr}",
        f"SWCOMPAT_WV2_CONTROLLER={controller}",
    ]
    if controller_hr is not None:
        lines.append(f"SWCOMPAT_WV2_CONTROLLER_HRESULT={controller_hr}")
    lines.append("SWCOMPAT_WV2_PROBE=COMPLETE")
    return "\n".join(lines) + "\n"


class WebView2ControllerReportTests(unittest.TestCase):
    def test_real_controller_ready(self):
        result = summarize(log(), 0)
        self.assertEqual(result["probe_result"], "COMPLETE")
        self.assertTrue(result["controller_created"])
        self.assertEqual(result["environment_creation"], "READY")
        self.assertEqual(result["controller_creation"], "READY")
        self.assertEqual(result["html_rendering"], "NOT_TESTED")

    def test_runtime_missing_environment_request_failed(self):
        text = log(runtime="NOT_DISCOVERED", runtime_hr="0x80070002",
                   env="REQUEST_FAILED", env_hr="0x80070002",
                   controller="NOT_REACHED", controller_hr=None)
        result = summarize(text, 0)
        self.assertEqual(result["probe_result"], "COMPLETE")
        self.assertEqual(result["runtime_discovery"], "NOT_DISCOVERED")
        self.assertFalse(result["controller_created"])
        self.assertEqual(result["controller_creation"], "NOT_REACHED")

    def test_runtime_missing_environment_callback_failed(self):
        text = log(runtime="NOT_DISCOVERED", runtime_hr="0x80070002",
                   env="CALLBACK_FAILED", env_hr="0x80004005",
                   controller="NOT_REACHED", controller_hr=None)
        self.assertEqual(summarize(text, 0)["probe_result"], "COMPLETE")

    def test_controller_failure_is_complete_but_not_working(self):
        text = log(controller="CALLBACK_FAILED", controller_hr="0x80004005")
        result = summarize(text, 0)
        self.assertEqual(result["probe_result"], "COMPLETE")
        self.assertFalse(result["controller_created"])
        self.assertEqual(result["environment_creation"], "READY")

    def test_environment_timeout_code(self):
        text = log(env="TIMEOUT", env_hr="0x800705B4",
                   controller="NOT_REACHED", controller_hr=None)
        result = summarize(text, 0)
        self.assertEqual(result["probe_result"], "COMPLETE")
        self.assertFalse(result["controller_created"])
        bad = log(env="TIMEOUT", env_hr="0x80004005",
                  controller="NOT_REACHED", controller_hr=None)
        self.assertEqual(summarize(bad, 0)["probe_result"], "FAILED_OR_INCOMPLETE")

    def test_controller_timeout_code(self):
        text = log(controller="TIMEOUT", controller_hr="0x800705B4")
        self.assertEqual(summarize(text, 0)["probe_result"], "COMPLETE")

    def test_controller_cannot_be_ready_without_environment(self):
        text = log(env="REQUEST_FAILED", env_hr="0x80070002")
        self.assertEqual(summarize(text, 0)["probe_result"], "FAILED_OR_INCOMPLETE")

    def test_missing_hresult_and_bad_status_fail(self):
        text = log(controller="NOT_REACHED", controller_hr=None)
        self.assertEqual(summarize(text, 0)["probe_result"], "FAILED_OR_INCOMPLETE")
        bad = log().replace("SWCOMPAT_WV2_CONTROLLER=READY",
                            "SWCOMPAT_WV2_CONTROLLER=SECRET")
        self.assertEqual(summarize(bad, 0)["probe_result"], "FAILED_OR_INCOMPLETE")

    def test_duplicate_marker_and_nonzero_exit_fail(self):
        text = log()
        self.assertEqual(summarize(text + "SWCOMPAT_WV2_PROBE=COMPLETE\n", 0)["probe_result"],
                         "FAILED_OR_INCOMPLETE")
        self.assertEqual(summarize(text, 3)["probe_result"], "FAILED_OR_INCOMPLETE")

    def test_corrupt_hresult_rejected(self):
        text = log(runtime_hr="0xDEADSECRET")
        self.assertEqual(summarize(text, 0)["probe_result"], "FAILED_OR_INCOMPLETE")
        text = log(runtime="NOT_DISCOVERED", runtime_hr="0x00000000")
        self.assertEqual(summarize(text, 0)["probe_result"], "FAILED_OR_INCOMPLETE")

    def test_no_paths_licenses_or_browser_version_exported(self):
        text = log() + (
            "C:\\Users\\PRIVATE_USER\\Secret\\license.dat\n"
            "john@example.com activation=SECRET\n"
            "SWCOMPAT_WV2_BROWSER_VERSION=private-token\n"
            "Version 124.0.5432.45\n"
        )
        result = json.dumps(summarize(text, 0))
        for secret in ("PRIVATE_USER", "license.dat", "john@example.com",
                       "private-token", "124.0.5432.45"):
            self.assertNotIn(secret, result)

    def test_cli_require_controller_is_strict(self):
        with tempfile.TemporaryDirectory() as d:
            src, dest = Path(d) / "source.log", Path(d) / "result.json"
            src.write_text(log(controller="INTERFACE_FAILED", controller_hr="0x80004003"),
                           encoding="utf-8")
            args = [sys.executable, "-m", "scripts.webview2_controller_report",
                    "--input", str(src), "--output", str(dest), "--exit-code", "0",
                    "--require-controller"]
            p = subprocess.run(args, text=True, capture_output=True)
            self.assertNotEqual(p.returncode, 0)
            self.assertEqual(json.loads(dest.read_text())["probe_result"], "COMPLETE")
            self.assertFalse(json.loads(dest.read_text())["controller_created"])

    def test_cli_rejects_input_overwrite(self):
        with tempfile.TemporaryDirectory() as d:
            src = Path(d) / "report.log"
            data = log()
            src.write_text(data, encoding="utf-8")
            p = subprocess.run([sys.executable, "-m", "scripts.webview2_controller_report",
                                "--input", str(src), "--output", str(src),
                                "--exit-code", "0"], capture_output=True)
            self.assertNotEqual(p.returncode, 0)
            self.assertEqual(src.read_text(encoding="utf-8"), data)

    def test_cli_rejects_oversized_data(self):
        with tempfile.TemporaryDirectory() as d:
            src, dest = Path(d) / "source.log", Path(d) / "out.json"
            src.write_bytes(b"z" * (512 * 1024 + 1))
            p = subprocess.run([sys.executable, "-m", "scripts.webview2_controller_report",
                                "--input", str(src), "--output", str(dest),
                                "--exit-code", "0"], capture_output=True)
            self.assertNotEqual(p.returncode, 0)
            self.assertFalse(dest.exists())


if __name__ == "__main__":
    unittest.main()
