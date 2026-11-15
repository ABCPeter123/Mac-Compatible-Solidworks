"""The .NET 4.0 outer timeout must reach the native Win32 launcher.

Regression for the original 210-second hard limit inadvertently surviving
when the surrounding experiment requested 330 seconds.
"""
from pathlib import Path
import os
from tempfile import TemporaryDirectory
import unittest
from unittest import mock

from scripts import netfx40_legacy as legacy
from scripts.netfx481_payload_audit import ITEMS


class Netfx40Win32WaitTests(unittest.TestCase):
    @unittest.skipIf(os.name == "nt", "Original setup may only run under Wine")
    def test_extended_and_baseline_pass_distinct_strict_launcher_arguments(self):
        for extended, expected in (
            (False, [r"Z:\safe\dotNetFx40_Full_x86_x64.exe"]),
            (True, [r"Z:\safe\dotNetFx40_Full_x86_x64.exe",
                    "--extended-wait-330"]),
        ):
            with self.subTest(extended=extended), TemporaryDirectory() as td:
                root = Path(td)
                prefix = root / "prefix"
                (prefix / "drive_c").mkdir(parents=True)
                (prefix / "system.reg").touch()
                (prefix / ".swcompat-netfx481-disposable").touch()
                wine = root / "wine"
                wine.write_bytes(b"fixture")
                wine.chmod(0o700)
                names = ("dotNetFx40_Full_x86_x64.exe", "netfx40_win32_launch.exe",
                         "netfx481_clr_load.exe", "netfx481_runtime_probe.exe")
                paths = [root / name for name in names]
                for p in paths:
                    p.write_bytes(b"self-authored test file")
                preflight = {
                    "status": "EXIT_CAPTURED", "category": "REBOOT_REQUIRED",
                    "exit_hex": "00000BC2",
                    "child_seen": "NOT_OBSERVED",
                    "child_lifecycle": "NOT_OBSERVED",
                    "child_exit": "NOT_VERIFIED",
                }
                installer = {
                    "status": "TIMEOUT", "category": "NOT_AVAILABLE",
                    "exit_hex": "NOT_VERIFIED",
                    "child_seen": "NOT_VERIFIED",
                    "child_lifecycle": "NOT_VERIFIED",
                    "child_exit": "NOT_VERIFIED",
                }
                absent = {key: ("ABSENT", None) for key in ITEMS}
                with (
                    mock.patch.object(legacy, "verify_media"),
                    mock.patch.object(legacy, "snapshot", return_value=absent),
                    mock.patch.object(legacy, "set_legacy_winver", return_value="APPLIED"),
                    mock.patch.object(legacy, "clear_unbacked_release", return_value="NOT_NEEDED"),
                    mock.patch.object(legacy, "inventory", return_value=()),
                    mock.patch.object(legacy, "windows_media_path",
                                      return_value=r"Z:\safe\dotNetFx40_Full_x86_x64.exe"),
                    mock.patch.object(legacy, "_run",
                                      side_effect=[preflight, installer]) as runner,
                    mock.patch.object(legacy, "probe", return_value={
                        "clr_family": "UNKNOWN", "managed": "FAIL"}),
                    mock.patch.object(legacy, "clr_load", return_value="NOT_FOUND"),
                ):
                    result = legacy.inspect(wine, prefix, *paths, timeout=330,
                                            enable_extended_setup_wait=extended)
                self.assertTrue(legacy.validate(result))
                self.assertFalse(result["candidate_native40"])
                self.assertEqual(result["installer_status"], "TIMEOUT")
                self.assertEqual(runner.call_args_list[1].args[3], expected)
                self.assertTrue(runner.call_args_list[1].kwargs["setup"])
                self.assertEqual(runner.call_args_list[1].kwargs["timeout"], 370)
                self.assertEqual(runner.call_args_list[0].args[3], ["--selftest-3010"])

    @unittest.skipIf(os.name == "nt", "Original setup may only run under Wine")
    def test_extended_wait_rejected_when_outer_timeout_is_shorter(self):
        with self.assertRaises(ValueError):
            legacy.inspect(
                *(Path("/original/fixture") for _ in range(6)),
                timeout=210, enable_extended_setup_wait=True)


if __name__ == "__main__":
    unittest.main()
