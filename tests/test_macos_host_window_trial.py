"""Host screenshot evidence must never be confused with Wine framebuffer evidence."""
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest import mock

from scripts import macos_host_window_trial as host
from scripts.live_cad_session_trial import EXPECTED


def record(mode="WINE", window="FOUND", capture="SUCCESS", pixel="PASS"):
    return (
        "SWCOMPAT_HOST_PIXELS_SCHEMA=1\n"
        f"SWCOMPAT_HOST_PIXELS_MODE={mode}\n"
        f"SWCOMPAT_HOST_PIXELS_WINDOW={window}\n"
        f"SWCOMPAT_HOST_PIXELS_CAPTURE={capture}\n"
        f"SWCOMPAT_HOST_PIXELS_PIXEL={pixel}\n"
    ).encode("ascii")


class HostScreenshotTests(unittest.TestCase):
    def test_native_and_wine_capture_are_distinct_and_bounded(self):
        self.assertEqual(host.parse_capture(record(), "WINE", 0), "PASS")
        self.assertEqual(host.parse_capture(record("NATIVE"), "NATIVE", 0), "PASS")
        self.assertEqual(host.parse_capture(record(pixel="MISMATCH"), "WINE", 0),
                         "PIXEL_MISMATCH")
        self.assertEqual(host.parse_capture(
            record(window="NOT_FOUND", capture="UNAVAILABLE", pixel="NOT_TESTED"), "WINE", 0
        ), "WINDOW_NOT_FOUND")
        self.assertEqual(host.parse_capture(
            record(capture="UNAVAILABLE", pixel="NOT_TESTED"), "WINE", 0
        ), "CAPTURE_UNAVAILABLE")

    def test_reject_proprietary_windows_paths_and_injected_claims(self):
        for raw, code, mode in (
            (record() + b"SWCOMPAT_HOST_PIXELS_PRIVATE=C:\\keys\n", 0, "WINE"),
            (record() + b"SWCOMPAT_HOST_PIXELS_PIXEL=PASS\n", 0, "WINE"),
            (record(), 1, "WINE"),
            (record(), 0, "NATIVE"),
            (record() + b"\x00", 0, "WINE"),
            (record() + b"x" * 1500, 0, "WINE"),
            (record(pixel="PASS", capture="UNAVAILABLE"), 0, "WINE"),
            (record(window="NOT_FOUND", capture="SUCCESS"), 0, "WINE"),
        ):
            with self.subTest(raw=raw[:32], mode=mode):
                self.assertEqual(host.parse_capture(raw, mode, code), "PROCESS_ERROR")

    def test_no_synthetic_result_can_claim_real_solidworks(self):
        report = {
            "schema": 1, "scope": "HOST_WINDOW_SCREENSHOT_NOT_SOLIDWORKS",
            "native_control": "PASS", "wine_host_pixels": "PASS",
            "windows_3d_session": "PASS", "saved_model": "EXACT",
            "independent_model_reopen": "PASS", "cleanup": "REMOVED",
            "host_window_visibility_proven": True,
            "native_solidworks_compatibility": "NOT_DEMONSTRATED",
        }
        self.assertTrue(host.validate(report))
        self.assertFalse(host.validate(dict(report, native_solidworks_compatibility="READY")))
        self.assertFalse(host.validate(dict(report, host_window_visibility_proven=False)))
        self.assertFalse(host.validate(dict(report, private_path="secret")))
        self.assertFalse(host.validate(dict(report, native_control="CAPTURE_UNAVAILABLE")))

    @unittest.skipIf(os.name == "nt", "Synthetic Mac and Wine prefix test uses POSIX files")
    def test_calibration_failure_does_not_become_compatibility_success(self):
        with TemporaryDirectory() as td:
            root = Path(td)
            prefix = root / "prefix"
            (prefix / "drive_c").mkdir(parents=True)
            (prefix / "system.reg").touch()
            (prefix / ".swcompat-netfx481-disposable").touch()
            wine = root / "wine"
            wine.write_bytes(b"self-authored test"); wine.chmod(0o700)
            app = root / "live_cad_viewport.exe"; app.write_bytes(b"self-authored")
            mac = root / "macos_host_window_capture"; mac.write_bytes(b"test")
            mac.chmod(0o700)
            doc = prefix / "drive_c" / host.DOCUMENT

            def gui(*args):
                doc.write_bytes(EXPECTED)
                return "PASS", "CAPTURE_UNAVAILABLE"
            with (mock.patch.object(host, "validate_mesa"),
                  mock.patch.object(host, "capture", return_value="CAPTURE_UNAVAILABLE"),
                  mock.patch.object(host, "run_gui", side_effect=gui),
                  mock.patch.object(host.subprocess, "run") as check):
                check.return_value.returncode = 0
                check.return_value.stdout = b"SWCOMPAT_LIVE_INDEPENDENT_REOPEN=PASS\n"
                report = host.trial(wine, prefix, app, mac)
            self.assertEqual(report["windows_3d_session"], "PASS")
            self.assertEqual(report["wine_host_pixels"], "CAPTURE_UNAVAILABLE")
            self.assertFalse(report["host_window_visibility_proven"])
            self.assertEqual(report["independent_model_reopen"], "PASS")
            self.assertTrue(host.validate(report))
            self.assertFalse(doc.exists())

    @unittest.skipIf(os.name == "nt", "Synthetic Mac and Wine prefix test uses POSIX files")
    def test_never_touch_preexisting_synthetic_model(self):
        with TemporaryDirectory() as td:
            root = Path(td)
            prefix = root / "prefix"
            (prefix / "drive_c").mkdir(parents=True)
            (prefix / "system.reg").touch()
            (prefix / ".swcompat-netfx481-disposable").touch()
            wine = root / "wine"; wine.write_bytes(b"test"); wine.chmod(0o700)
            app = root / "live_cad_viewport.exe"; app.write_bytes(b"test")
            mac = root / "host_window_capture"; mac.write_bytes(b"test"); mac.chmod(0o700)
            doc = prefix / "drive_c" / host.DOCUMENT
            doc.write_bytes(b"do-not-touch")
            with (mock.patch.object(host, "validate_mesa"),
                  mock.patch.object(host, "run_gui") as gui):
                with self.assertRaises(ValueError):
                    host.trial(wine, prefix, app, mac)
                gui.assert_not_called()
            self.assertEqual(doc.read_bytes(), b"do-not-touch")


if __name__ == "__main__":
    unittest.main()
