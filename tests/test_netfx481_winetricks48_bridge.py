"""Reject fake Microsoft .NET 4.8.1 from Winetricks recipe exit codes."""
import unittest
import os
import subprocess
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock
from scripts import netfx481_winetricks48_bridge as bridge
from scripts.netfx481_winetricks48_bridge import blank, validate, classify_release_48


class Native48BridgeTests(unittest.TestCase):
    def test_failed_winetricks_is_not_481(self):
        for s in ("VERB_FAILED", "VERB_TIMED_OUT", "VERB_START_FAILED",
                  "PREREQUISITE_NOT_READY"):
            with self.subTest(status=s):
                r = blank(s)
                if s == "PREREQUISITE_NOT_READY":
                    r["winetricks48_exit"] = "ZERO"
                self.assertTrue(validate(r))
                self.assertFalse(r["native481_confirmed"])

    def test_3010_no_new_clr_and_no_registration_never_passes(self):
        r = blank("MEASURED")
        r["winetricks48_exit"] = "ZERO"
        r["native48_candidate"] = True
        r["native48_release"] = "AT_LEAST_48"
        r["clr64_before481"] = "PE_AMD64"
        r["clr64_after481"] = "PE_AMD64"
        r["clr64_change"] = "UNCHANGED"
        r["native_loader"] = "LOADED"
        r["native_only_managed"] = "PASS"
        r["runtime_family"] = "MICROSOFT_CLR_CANDIDATE"
        r["framework481_registry"] = "NOT_FOUND"
        r["restart"] = "COMPLETED"
        r["setup"] = {
            "status": "EXIT_CAPTURED", "category": "REBOOT_REQUIRED",
            "exit_hex": "00000BC2", "child_seen": "OBSERVED",
            "child_lifecycle": "ALL_EXITED", "child_exit": "REBOOT_REQUIRED",
        }
        self.assertTrue(validate(r))
        self.assertFalse(r["native481_confirmed"])
        self.assertFalse(validate(dict(r, native481_confirmed=True)))
        self.assertFalse(validate(dict(r, private_microsoft_path="SECRET")))

    def test_false_positive_on_nonzero_installer_rejected(self):
        r = blank("MEASURED")
        r.update(winetricks48_exit="ZERO", native48_candidate=True,
                 native48_release="AT_LEAST_48",
                 clr64_before481="PE_AMD64", clr64_after481="PE_AMD64",
                 clr64_change="CHANGED", native_loader="LOADED",
                 native_only_managed="PASS", runtime_family="MICROSOFT_CLR_CANDIDATE",
                 framework481_registry="AT_LEAST_481", restart="NOT_RUN")
        r["setup"] = {"status": "EXIT_CAPTURED", "category": "OTHER",
                      "exit_hex": "000013EC", "child_seen": "OBSERVED",
                      "child_lifecycle": "ALL_EXITED", "child_exit": "NONZERO"}
        self.assertTrue(validate(r))
        self.assertFalse(r["native481_confirmed"])
        self.assertFalse(validate(dict(r, native481_confirmed=True)))


    def test_original_netfx48_release_is_required(self):
        valid = b"    Release    REG_DWORD    0x80f11\n"
        self.assertEqual(classify_release_48(valid, 0), "AT_LEAST_48")
        self.assertEqual(classify_release_48(b"    Release    REG_DWORD    0x80000\n", 0), "BELOW_48")
        self.assertEqual(classify_release_48(valid, 1), "NOT_VERIFIED")
        self.assertEqual(classify_release_48(valid + valid, 0), "NOT_VERIFIED")
        self.assertEqual(classify_release_48(b"some other private key\n", 0), "NOT_FOUND")

    @unittest.skipIf(os.name == "nt", "Wine executable only runs on POSIX")
    def test_timeout_checks_actual_clr_and_release_before_declaring_failure(self):
        with TemporaryDirectory() as td:
            root = Path(td)
            prefix = root / "prefix"
            prefix.mkdir()
            names = ["wine", "winetricks", "NDP481-x86-x64-AllOS-ENU.exe",
                     "netfx481.sha256", "netfx481_win32_launch.exe",
                     "netfx481_clr_load.exe", "netfx481_runtime_probe.exe"]
            paths = [root / x for x in names]
            for p in paths:
                p.write_bytes(b"fixture")
            for p in paths[:2]:
                p.chmod(0o755)
            with (mock.patch.object(bridge, "validate_prefix"),
                  mock.patch.object(bridge, "verify_media"),
                  mock.patch.object(bridge.subprocess, "run",
                                    side_effect=subprocess.TimeoutExpired("dotnet48", 600)),
                  mock.patch.object(bridge, "wineboot_restart",
                                    return_value="COMPLETED") as reboot,
                  mock.patch.object(bridge, "snapshot", return_value={
                      "CLR64": ("PE_AMD64", "synthetic"),
                      "MSCORLIB64": ("PE_AMD64", "synthetic")}),
                  mock.patch.object(bridge, "probe", return_value={
                      "clr_family": "MICROSOFT_CLR_CANDIDATE", "managed": "PASS"}),
                  mock.patch.object(bridge, "load_clr", return_value="LOADED"),
                  mock.patch.object(bridge, "probe_release_48",
                                    return_value="BELOW_48"),
                  mock.patch.object(bridge, "launch") as launch):
                r = bridge.inspect(paths[0], prefix, paths[1],
                                   *paths[2:], timeout=600)
            reboot.assert_called_once()
            launch.assert_not_called()
            self.assertEqual(r["status"], "PREREQUISITE_NOT_READY")
            self.assertEqual(r["winetricks48_exit"], "TIMEOUT")
            self.assertEqual(r["clr64_before481"], "PE_AMD64")
            self.assertEqual(r["native48_release"], "BELOW_48")
            self.assertEqual(r["native_loader"], "LOADED")
            self.assertTrue(validate(r))
            self.assertFalse(r["native481_confirmed"])



if __name__ == "__main__":
    unittest.main()
