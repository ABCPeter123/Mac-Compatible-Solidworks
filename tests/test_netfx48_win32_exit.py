"""Synthetic Windows process evidence for the original Microsoft 4.8 fixture."""
from pathlib import Path
import tempfile
from unittest import TestCase, mock

from scripts import netfx48_win32_exit as monitor


class NetFx48Win32Tests(TestCase):
    def test_parses_exact_full_windows_reboot_code_and_does_not_leak_paths(self):
        payload = ("SWCOMPAT_WIN32_SETUP_SCHEMA=1\n"
                   "SWCOMPAT_WIN32_SETUP_STATUS=EXIT\n"
                   "SWCOMPAT_WIN32_SETUP_EXIT_HEX=00000BC2\n"
                   "SWCOMPAT_WIN32_SETUP_CHILD_SEEN=NOT_OBSERVED\n"
                   "SWCOMPAT_WIN32_SETUP_CHILD_LIFECYCLE=NOT_OBSERVED\n"
                   "SWCOMPAT_WIN32_SETUP_CHILD_EXIT=NOT_VERIFIED\n").encode("ascii")
        parsed = monitor.parse(payload, 0)
        self.assertEqual(parsed["status"], "EXIT_CAPTURED")
        self.assertEqual(parsed["category"], "REBOOT_REQUIRED")
        self.assertEqual(monitor.termination(parsed), ("EXIT_NONZERO", 3010))
        self.assertNotIn("PRIVATE_USER", str(parsed))

        bad = payload + b"SWCOMPAT_WIN32_SETUP_PRIVATE_PATH=PRIVATE_USER\n"
        self.assertEqual(monitor.parse(bad, 0)["status"], "BAD_REPORT")

    def test_only_accepts_verified_original_installer_and_fixture_names(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            fixture = root / "netfx48_win32_launch.exe"
            installer = root / "NDP48-x86-x64-AllOS-ENU.exe"
            fixture.write_bytes(b"our original test")
            installer.write_bytes(b"synthetic original installer")
            with mock.patch("scripts.netfx481_trial.validate_prefix"):
                with mock.patch("swcompat.wine_paths.windows_media_path",
                                return_value=r"C:\temp\NDP48-x86-x64-AllOS-ENU.exe"):
                    with mock.patch.object(monitor.subprocess, "run", side_effect=OSError):
                        r = monitor.launch(root / "wine", root, installer, fixture)
                        self.assertEqual(r["status"], "PROCESS_FAILED")
                    unexpected = root / "bad-installer.exe"
                    unexpected.write_bytes(b"wrong")
                    with self.assertRaisesRegex(ValueError, "Unexpected original"):
                        monitor.launch(root / "wine", root, unexpected, fixture)
                    with self.assertRaisesRegex(ValueError, "Expected .NET 4.8-specific"):
                        monitor.launch(root / "wine", root, installer,
                                       root / "wrong-launcher.exe")

    def test_selftest_no_output_is_not_mistaken_for_original_setup_failure(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            fixture = root / "netfx48_win32_launch.exe"
            fixture.write_bytes(b"fixture")
            class Silent:
                returncode = 1
            with mock.patch("scripts.netfx481_trial.validate_prefix"):
                with mock.patch.object(monitor.subprocess, "run", return_value=Silent()):
                    self.assertEqual(monitor.selftest(root / "wine", root, fixture),
                                     "NO_OUTPUT")

    def test_start_failed_process_reports_are_complete_and_safe(self):
        payload = ("SWCOMPAT_WIN32_SETUP_SCHEMA=1\n"
                   "SWCOMPAT_WIN32_SETUP_STATUS=START_FAILED\n"
                   "SWCOMPAT_WIN32_SETUP_EXIT_HEX=FFFFFFFF\n"
                   "SWCOMPAT_WIN32_SETUP_CHILD_SEEN=UNKNOWN\n"
                   "SWCOMPAT_WIN32_SETUP_CHILD_LIFECYCLE=UNKNOWN\n"
                   "SWCOMPAT_WIN32_SETUP_CHILD_EXIT=NOT_VERIFIED\n").encode()
        result = monitor.parse(payload, 1)
        from scripts.netfx481_win32_exit import validate
        self.assertEqual(result["status"], "START_FAILED")
        self.assertTrue(validate(result))
        self.assertEqual(monitor.termination(result), ("START_FAILED", None))


    def test_relative_fixture_not_resolved_against_changed_wine_cwd(self):
        # GitHub Actions supplies build/foo.exe paths, not absolute paths.
        # When the subprocess changes cwd to build/, those inputs must first
        # be canonicalized to avoid attempting build/build/foo.exe.
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            root = Path(temp)
            fixture = root / "netfx48_win32_launch.exe"
            original = root / "NDP48-x86-x64-AllOS-ENU.exe"
            fixture.write_bytes(b"synthetic x64 fixture")
            original.write_bytes(b"synthetic installer")
            relative_fixture = fixture.relative_to(Path.cwd())
            relative_original = original.relative_to(Path.cwd())
            class Silent:
                returncode = 1
            with mock.patch("scripts.netfx481_trial.validate_prefix"):
                with mock.patch.object(monitor.subprocess, "run", return_value=Silent()) as run:
                    self.assertEqual(monitor.selftest(root / "wine", root, relative_fixture),
                                     "NO_OUTPUT")
                    self.assertEqual(Path(run.call_args.args[0][1]), fixture)
                    self.assertEqual(Path(run.call_args.kwargs["cwd"]), root)
                with mock.patch("swcompat.wine_paths.windows_media_path",
                                return_value=r"Z:\installer\NDP48-x86-x64-AllOS-ENU.exe") as winepath:
                    with mock.patch.object(monitor.subprocess, "run",
                                           return_value=Silent()) as run:
                        self.assertEqual(monitor.launch(root / "wine", root,
                                                        relative_original,
                                                        relative_fixture)["status"], "BAD_REPORT")
                        self.assertEqual(Path(run.call_args.args[0][1]), fixture)
                        self.assertEqual(Path(run.call_args.kwargs["cwd"]), root)
                        self.assertEqual(winepath.call_args.args[2], original)
