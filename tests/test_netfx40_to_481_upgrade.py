"""Safety regressions for authentic .NET 4.0 -> 4.8.1 upgrade."""
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest import mock

from scripts import netfx40_to_481_upgrade as upgrade
from scripts.netfx481_payload_audit import ITEMS


class NativeUpgradeTests(unittest.TestCase):
    @staticmethod
    def _disk(clr_hash):
        return {
            key: ("PE_AMD64" if key in {"CLR64", "MSCORLIB64"}
                  else "PE_I386", clr_hash)
            for key in ITEMS
        }

    @staticmethod
    def _setup():
        return {"status": "EXIT_CAPTURED", "category": "REBOOT_REQUIRED",
                "exit_hex": "00000BC2", "child_seen": "OBSERVED",
                "child_lifecycle": "ALL_EXITED", "child_exit": "REBOOT_REQUIRED"}

    def _fixture(self, root):
        prefix = root / "prefix"
        prefix.mkdir()
        wine = root / "wine"
        wine.write_bytes(b"wine")
        wine.chmod(0o700)
        names = ["NDP481-x86-x64-AllOS-ENU.exe", "netfx481.sha256",
                 "netfx481_win32_launch.exe", "netfx481_clr_load.exe",
                 "netfx481_runtime_probe.exe"]
        paths = [root / name for name in names]
        for p in paths:
            p.write_bytes(b"synthetic")
        return (wine, prefix, *paths)

    def test_real_3010_and_changed_native_clr_with_managed_execution_confirm_upgrade(self):
        with TemporaryDirectory() as td:
            args = self._fixture(Path(td))
            with (mock.patch.object(upgrade, "_wine_host", return_value=True),
                  mock.patch.object(upgrade, "validate_prefix"),
                  mock.patch.object(upgrade, "verify_media"),
                  mock.patch.object(upgrade, "validate_native40", return_value=True),
                  mock.patch.object(upgrade, "snapshot",
                                    side_effect=[self._disk("before"), self._disk("after")]),
                  mock.patch.object(upgrade, "probe", return_value={
                      "clr_family": "MICROSOFT_CLR_CANDIDATE",
                      "managed": "PASS", "registry": "AT_LEAST_481"}),
                  mock.patch.object(upgrade, "load_clr", return_value="LOADED"),
                  mock.patch.object(upgrade, "launch", return_value=self._setup()) as launch,
                  mock.patch.object(upgrade, "wineboot_restart", return_value="COMPLETED")):
                result = upgrade.inspect(*args, {"persistent_native_managed": True})
            self.assertTrue(upgrade.validate(result))
            self.assertEqual(result["status"], "MEASURED")
            self.assertTrue(result["framework481_confirmed"])
            self.assertEqual(result["clr64_change"], "CHANGED")
            self.assertEqual(result["solidworks_compatibility"], "NOT_DEMONSTRATED")
            self.assertTrue(launch.call_args.kwargs["fusion_builtin"])
            self.assertNotIn(td, str(result))

    def test_original_clr_not_replaced_cannot_claim_481(self):
        with TemporaryDirectory() as td:
            args = self._fixture(Path(td))
            with (mock.patch.object(upgrade, "_wine_host", return_value=True),
                  mock.patch.object(upgrade, "validate_prefix"),
                  mock.patch.object(upgrade, "verify_media"),
                  mock.patch.object(upgrade, "validate_native40", return_value=True),
                  mock.patch.object(upgrade, "snapshot",
                                    side_effect=[self._disk("same"), self._disk("same")]),
                  mock.patch.object(upgrade, "probe", return_value={
                      "clr_family": "MICROSOFT_CLR_CANDIDATE",
                      "managed": "PASS", "registry": "AT_LEAST_481"}),
                  mock.patch.object(upgrade, "load_clr", return_value="LOADED"),
                  mock.patch.object(upgrade, "launch", return_value=self._setup()),
                  mock.patch.object(upgrade, "wineboot_restart", return_value="COMPLETED")):
                result = upgrade.inspect(*args, {"persistent_native_managed": True})
            self.assertFalse(result["native_upgrade_candidate"])
            self.assertFalse(result["framework481_confirmed"])
            self.assertTrue(upgrade.validate(result))

    def test_old_native_clr_gate_prevents_starting_481(self):
        with TemporaryDirectory() as td:
            args = self._fixture(Path(td))
            with (mock.patch.object(upgrade, "_wine_host", return_value=True),
                  mock.patch.object(upgrade, "validate_prefix"),
                  mock.patch.object(upgrade, "verify_media"),
                  mock.patch.object(upgrade, "validate_native40", return_value=True),
                  mock.patch.object(upgrade, "launch") as launch):
                result = upgrade.inspect(*args, {"persistent_native_managed": False})
            self.assertEqual(result, upgrade.blank())
            launch.assert_not_called()

    def test_3010_without_reboot_does_not_confirm_installation(self):
        with TemporaryDirectory() as td:
            args = self._fixture(Path(td))
            with (mock.patch.object(upgrade, "_wine_host", return_value=True),
                  mock.patch.object(upgrade, "validate_prefix"),
                  mock.patch.object(upgrade, "verify_media"),
                  mock.patch.object(upgrade, "validate_native40", return_value=True),
                  mock.patch.object(upgrade, "snapshot",
                                    side_effect=[self._disk("before"), self._disk("after")]),
                  mock.patch.object(upgrade, "probe", return_value={
                      "clr_family": "MICROSOFT_CLR_CANDIDATE",
                      "managed": "PASS", "registry": "AT_LEAST_481"}),
                  mock.patch.object(upgrade, "load_clr", return_value="LOADED"),
                  mock.patch.object(upgrade, "launch", return_value={
                      **self._setup(), "child_lifecycle": "STILL_ACTIVE",
                      "child_exit": "NOT_VERIFIED"}),
                  mock.patch.object(upgrade, "wineboot_restart") as reboot):
                result = upgrade.inspect(*args, {"persistent_native_managed": True})
            self.assertTrue(result["native_upgrade_candidate"])
            self.assertFalse(result["framework481_confirmed"])
            self.assertEqual(result["restart"], "SKIPPED_CHILD_UNVERIFIED")
            self.assertTrue(upgrade.validate(result))
            reboot.assert_not_called()

    def test_refuses_windows_and_proprietary_or_forged_result_keys(self):
        with TemporaryDirectory() as td:
            args = self._fixture(Path(td))
            with mock.patch.object(upgrade, "_wine_host", return_value=False):
                with self.assertRaises(ValueError):
                    upgrade.inspect(*args, {"persistent_native_managed": True})
        self.assertFalse(upgrade.validate(dict(upgrade.blank(), native_upgrade_candidate=True)))
        self.assertFalse(upgrade.validate(dict(upgrade.blank(), original_action="PRIVATE")))
        self.assertFalse(upgrade.validate(dict(upgrade.blank(), framework481_confirmed=True)))


if __name__ == "__main__":
    unittest.main()
