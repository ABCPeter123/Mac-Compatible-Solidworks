import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from scripts.webview2_render_gate import classify


def fixtures():
    runtime = {
        "schema": 1, "solidworks_compatibility": "NOT_DEMONSTRATED",
        "installer_execution": "EXIT_ZERO",
        "runtime_installation_confirmed": True, "browser_controller_confirmed": True,
        "before": {"probe_result": "COMPLETE", "runtime_discovery": "NOT_DISCOVERED"},
        "after": {"probe_result": "COMPLETE", "runtime_discovery": "VERSION_FOUND",
                  "environment_creation": "READY", "controller_creation": "READY",
                  "controller_created": True},
    }
    render = {
        "schema": 1, "result": "FAIL",
        "screenshot_pixel_validation": "FAIL",
        "failure_stage": "CDP_TIMEOUT",
        "png_capture_method": "UNKNOWN",
        "capture_preview_api": "UNKNOWN",
        "solidworks_compatibility": "NOT_DEMONSTRATED",
    }
    gdi = {
        "schema": 1, "diagnostic": "COMPLETE",
        "dom_execution": "PASS", "window_client_bitblt": "NO_MATCH",
        "desktop_bitblt": "API_FAILED", "gdi_pixel_evidence": "NOT_VERIFIED",
        "solidworks_compatibility": "NOT_DEMONSTRATED",
    }
    return runtime, render, gdi


class RenderEvidenceGateTests(unittest.TestCase):
    def test_known_real_macos_result_is_a_blocker_not_a_pass(self):
        result = classify(*fixtures())
        self.assertEqual(result["result"], "KNOWN_CAPTURE_BLOCKER")
        self.assertTrue(result["diagnostic_complete"])
        self.assertEqual(result["browser_pixels"], "NOT_VERIFIED")
        self.assertEqual(result["macos_pixel_rendering"], "NOT_DEMONSTRATED")
        self.assertEqual(result["capture_blocker"], "CONFIRMED")

    def test_real_screenshot_pixels_verified(self):
        runtime, render, gdi = fixtures()
        render.update(result="PASS", screenshot_pixel_validation="PASS",
                      failure_stage="NONE", png_capture_method="CAPTURE_PREVIEW",
                      capture_preview_api="PASS")
        result = classify(runtime, render, gdi)
        self.assertEqual(result["result"], "SCREENSHOT_PIXELS_VERIFIED")
        self.assertEqual(result["browser_screenshot_api"], "VERIFIED")
        self.assertEqual(result["browser_pixels"], "VERIFIED")

    def test_valid_cdp_screenshot_can_prove_pixels(self):
        runtime, render, gdi = fixtures()
        render.update(result="PASS", screenshot_pixel_validation="PASS",
                      failure_stage="NONE", png_capture_method="CDP_FALLBACK")
        self.assertEqual(classify(runtime, render, gdi)["result"], "SCREENSHOT_PIXELS_VERIFIED")

    def test_gdi_pixel_proof_without_browser_screenshot(self):
        runtime, render, gdi = fixtures()
        gdi.update(window_client_bitblt="PIXELS_MATCH", gdi_pixel_evidence="VERIFIED")
        result = classify(runtime, render, gdi)
        self.assertEqual(result["result"], "GDI_PIXELS_VERIFIED")
        self.assertEqual(result["browser_screenshot_api"], "NOT_VERIFIED")
        self.assertEqual(result["browser_pixels"], "VERIFIED")

    def test_desktop_gdi_can_verify_pixels(self):
        runtime, render, gdi = fixtures()
        gdi.update(desktop_bitblt="PIXELS_MATCH", gdi_pixel_evidence="VERIFIED")
        self.assertEqual(classify(runtime, render, gdi)["result"], "GDI_PIXELS_VERIFIED")

    def test_blocker_only_when_cdp_timeout_exact(self):
        for failure in ("SCRIPT_DOM", "PREVIEW_TIMEOUT", "CDP_CALLBACK", "LOADER", "UNKNOWN", ""):
            runtime, render, gdi = fixtures()
            render["failure_stage"] = failure
            self.assertEqual(classify(runtime, render, gdi)["result"], "UNEXPECTED_FAILURE",
                             failure)

    def test_browser_controller_must_be_real(self):
        runtime, render, gdi = fixtures()
        runtime["browser_controller_confirmed"] = False
        self.assertEqual(classify(runtime, render, gdi)["result"], "UNEXPECTED_FAILURE")

    def test_installer_failure_is_not_allowed(self):
        runtime, render, gdi = fixtures()
        runtime["installer_execution"] = "EXIT_NONZERO"
        self.assertEqual(classify(runtime, render, gdi)["result"], "UNEXPECTED_FAILURE")

    def test_preexisting_runtime_not_misattributed(self):
        runtime, render, gdi = fixtures()
        runtime["before"]["runtime_discovery"] = "VERSION_FOUND"
        self.assertEqual(classify(runtime, render, gdi)["result"], "UNEXPECTED_FAILURE")

    def test_dom_missing_must_fail_even_if_screenshot_timeout_expected(self):
        runtime, render, gdi = fixtures()
        gdi["dom_execution"] = "UNKNOWN"
        self.assertEqual(classify(runtime, render, gdi)["result"], "UNEXPECTED_FAILURE")

    def test_gdi_readback_must_complete(self):
        runtime, render, gdi = fixtures()
        gdi["diagnostic"] = "INCOMPLETE"
        self.assertEqual(classify(runtime, render, gdi)["result"], "UNEXPECTED_FAILURE")

    def test_gdi_match_must_agree_with_proof_marker(self):
        runtime, render, gdi = fixtures()
        gdi["gdi_pixel_evidence"] = "VERIFIED"
        self.assertEqual(classify(runtime, render, gdi)["result"], "UNEXPECTED_FAILURE")

    def test_missing_schema_fails(self):
        for i in (0, 1, 2):
            records = fixtures()
            del records[i]["schema"]
            self.assertEqual(classify(*records)["result"], "UNEXPECTED_FAILURE")

    def test_untrusted_contents_cannot_leak(self):
        records = fixtures()
        records[0]["file"] = "/home/PRIVATE_USER/license.dat"
        records[1]["text"] = "john@example.com"
        records[2]["warning"] = "SECRET"
        text = json.dumps(classify(*records))
        for secret in ("PRIVATE_USER", "license.dat", "john@example.com", "SECRET"):
            self.assertNotIn(secret, text)

    @staticmethod
    def run_cli(folder: Path, *, require_pixels: bool = False):
        records = fixtures()
        for label, obj in zip(("runtime", "render", "gdi"), records):
            (folder / f"{label}.json").write_text(json.dumps(obj))
        cmd = [sys.executable, "-m", "scripts.webview2_render_gate",
               "--runtime", str(folder / "runtime.json"),
               "--render", str(folder / "render.json"),
               "--gdi", str(folder / "gdi.json"),
               "--output", str(folder / "out.json")]
        if require_pixels:
            cmd.append("--require-pixels")
        return subprocess.run(cmd, capture_output=True, text=True)

    def test_diagnostic_ci_allows_only_exact_known_blocker(self):
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)
            proc = self.run_cli(folder)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            result = json.loads((folder / "out.json").read_text())
            self.assertEqual(result["result"], "KNOWN_CAPTURE_BLOCKER")
            self.assertEqual(result["browser_pixels"], "NOT_VERIFIED")

    def test_strict_require_pixels_fails_known_blocker(self):
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)
            proc = self.run_cli(folder, require_pixels=True)
            self.assertNotEqual(proc.returncode, 0)
            self.assertEqual(json.loads((folder / "out.json").read_text())["result"],
                             "KNOWN_CAPTURE_BLOCKER")

    def test_strict_require_pixels_passes_verified_gdi(self):
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)
            self.run_cli(folder)
            gdi = json.loads((folder / "gdi.json").read_text())
            gdi["window_client_bitblt"] = "PIXELS_MATCH"
            gdi["gdi_pixel_evidence"] = "VERIFIED"
            (folder / "gdi.json").write_text(json.dumps(gdi))
            proc = subprocess.run(
                [sys.executable, "-m", "scripts.webview2_render_gate",
                 "--runtime", str(folder / "runtime.json"),
                 "--render", str(folder / "render.json"),
                 "--gdi", str(folder / "gdi.json"),
                 "--output", str(folder / "out.json"), "--require-pixels"],
                capture_output=True, text=True)
            self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_malformed_input_fails_before_output(self):
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)
            self.run_cli(folder)
            (folder / "render.json").write_text("{bad")
            proc = subprocess.run(
                [sys.executable, "-m", "scripts.webview2_render_gate",
                 "--runtime", str(folder / "runtime.json"),
                 "--render", str(folder / "render.json"),
                 "--gdi", str(folder / "gdi.json"),
                 "--output", str(folder / "bad-output.json")],
                capture_output=True)
            self.assertNotEqual(proc.returncode, 0)
            self.assertFalse((folder / "bad-output.json").exists())

    def test_oversized_input_fails(self):
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)
            self.run_cli(folder)
            (folder / "runtime.json").write_text("a" * 65537)
            proc = subprocess.run(
                [sys.executable, "-m", "scripts.webview2_render_gate",
                 "--runtime", str(folder / "runtime.json"),
                 "--render", str(folder / "render.json"),
                 "--gdi", str(folder / "gdi.json"),
                 "--output", str(folder / "bad-output.json")],
                capture_output=True)
            self.assertNotEqual(proc.returncode, 0)


if __name__ == "__main__":
    unittest.main()
