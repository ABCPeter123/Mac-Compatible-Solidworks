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
