"""Control tests for the genuine Winetricks msxml3 prerequisite experiment."""
from pathlib import Path
from tempfile import TemporaryDirectory
import subprocess
import unittest
from unittest import mock

from scripts import netfx40_msxml3_prerequisite as pre


class Msxml3PrerequisiteTests(unittest.TestCase):
    def _fixture(self, root: Path):
        wine = root / "wine"
        wine.write_bytes(b"synthetic wine")
        wine.chmod(0o755)
        tricks = root / "winetricks"
        tricks.write_bytes(b"synthetic winetricks")
        tricks.chmod(0o755)
        prefix = root / "prefix"
        (prefix / "drive_c" / "windows" / "syswow64").mkdir(parents=True)
        (prefix / "drive_c" / "windows" / "system32").mkdir()
        return wine, prefix, tricks

    def test_real_success_requires_private_process_zero_and_no_stdout(self):
        with TemporaryDirectory() as td:
            wine, prefix, tricks = self._fixture(Path(td))
            dll = prefix / "drive_c" / "windows" / "syswow64" / "msxml3.dll"

            def fake_run(cmd, **kwargs):
                self.assertEqual(cmd, [str(tricks), "-q", "msxml3"])
                self.assertIs(kwargs["stdout"], subprocess.DEVNULL)
                self.assertIs(kwargs["stderr"], subprocess.DEVNULL)
                self.assertEqual(kwargs["env"]["WINEPREFIX"], str(prefix))
                self.assertEqual(kwargs["env"]["WINE"], str(wine))
                self.assertEqual(kwargs["env"]["WINEARCH"], "win64")
                self.assertEqual(kwargs["env"]["PATH"].split(__import__("os").pathsep)[0], str(wine.parent))
                dll.write_bytes(b"MZ" + b"original fixture" * 350)
                return mock.Mock(returncode=0)

            with (mock.patch.object(pre, "_is_wine_host", return_value=True),
                  mock.patch.object(pre, "validate_prefix"),
                  mock.patch.object(pre.subprocess, "run", side_effect=fake_run)):
                report = pre.inspect(wine, prefix, tricks, timeout=100)
            self.assertEqual(report, {"status": "VERB_SUCCEEDED",
                                      "x86_dll_changed": True,
                                      "x64_dll_changed": False})
            self.assertTrue(pre.validate(report))
            self.assertNotIn(td, str(report))

    def test_nonzero_and_timeout_never_claim_native_msxml3(self):
        for return_value, expected in [
            (mock.Mock(returncode=67), "VERB_FAILED"),
            (subprocess.TimeoutExpired("msxml3", 60), "VERB_TIMED_OUT"),
            (OSError("synthetic"), "VERB_START_FAILED"),
        ]:
            with self.subTest(expected=expected), TemporaryDirectory() as td:
                wine, prefix, tricks = self._fixture(Path(td))
                callback = ({"side_effect": return_value} if isinstance(return_value, Exception)
                            else {"return_value": return_value})
                with (mock.patch.object(pre, "_is_wine_host", return_value=True),
                      mock.patch.object(pre, "validate_prefix"),
                      mock.patch.object(pre.subprocess, "run", **callback)):
                    report = pre.inspect(wine, prefix, tricks)
                self.assertTrue(pre.validate(report))
                self.assertEqual(report["status"], expected)
                self.assertFalse(report["x86_dll_changed"])
                self.assertFalse(report["x64_dll_changed"])

    def test_baseline_existing_builtin_dll_does_not_count_as_new_install(self):
        with TemporaryDirectory() as td:
            wine, prefix, tricks = self._fixture(Path(td))
            dll = prefix / "drive_c" / "windows" / "syswow64" / "msxml3.dll"
            dll.write_bytes(b"MZ" + b"existing fixture" * 350)
            with (mock.patch.object(pre, "_is_wine_host", return_value=True),
                  mock.patch.object(pre, "validate_prefix"),
                  mock.patch.object(pre.subprocess, "run", return_value=mock.Mock(returncode=0))):
                report = pre.inspect(wine, prefix, tricks)
            self.assertEqual(report["status"], "VERB_SUCCEEDED")
            self.assertFalse(report["x86_dll_changed"])
            self.assertTrue(pre.validate(report))

    def test_windows_refusal_and_invalid_bounds(self):
        with TemporaryDirectory() as td:
            wine, prefix, tricks = self._fixture(Path(td))
            with mock.patch.object(pre, "_is_wine_host", return_value=False):
                with self.assertRaises(ValueError):
                    pre.inspect(wine, prefix, tricks)
            with mock.patch.object(pre, "_is_wine_host", return_value=True):
                with self.assertRaises(ValueError):
                    pre.inspect(wine, prefix, tricks, timeout=500)

    def test_strict_sanitized_report_validation(self):
        report = pre.blank("VERB_FAILED")
        self.assertTrue(pre.validate(report))
        self.assertFalse(pre.validate(dict(report, original_action="PRIVATE")))
        self.assertFalse(pre.validate(dict(report, x86_dll_changed=True)))
        self.assertFalse(pre.validate(dict(report, status="SPOOFED_INSTALLED")))
        self.assertFalse(pre.validate(dict(report, x64_dll_changed=1)))


if __name__ == "__main__":
    unittest.main()
