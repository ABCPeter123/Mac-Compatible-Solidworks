"""Regression tests for native Microsoft CLR persistence after Wine restart."""
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest import mock

from scripts import netfx40_msxml3_restart as restart


class Msxml3RestartTests(unittest.TestCase):
    @staticmethod
    def original():
        return {"installer_status": "TIMEOUT", "clr64_after": "PE_AMD64",
                "mscorlib64_after": "PE_AMD64", "native_loader": "LOADED",
                "managed_functionality": "PASS"}

    def fixture(self, home):
        wine = home / "wine"
        wine.write_bytes(b"wine fixture")
        wine.chmod(0o755)
        loader = home / "netfx481_clr_load.exe"
        loader.write_bytes(b"loader")
        managed = home / "netfx481_runtime_probe.exe"
        managed.write_bytes(b"managed")
        prefix = home / "prefix"
        prefix.mkdir()
        return wine, prefix, loader, managed

    def test_persistent_clr_requires_managed_native_only_after_real_restart(self):
        with TemporaryDirectory() as td:
            wine, prefix, loader, managed = self.fixture(Path(td))
            with (mock.patch.object(restart, "_is_wine_host", return_value=True),
                  mock.patch.object(restart, "validate_prefix"),
                  mock.patch.object(restart, "validate_original", return_value=True),
                  mock.patch.object(restart, "wineboot_restart", return_value="COMPLETED") as boot,
                  mock.patch.object(restart, "snapshot",
                                    return_value={"CLR64": ("PE_AMD64", None),
                                                  "MSCORLIB64": ("PE_AMD64", None)}),
                  mock.patch.object(restart, "clr_load", return_value="LOADED"),
                  mock.patch.object(restart, "probe", return_value={
                      "clr_family": "MICROSOFT_CLR_CANDIDATE", "managed": "PASS"}) as probe):
                r = restart.inspect(wine, prefix, loader, managed, self.original())
            self.assertTrue(restart.validate(r))
            self.assertTrue(r["persistent_native_managed"])
            self.assertEqual(r["status"], "RESTART_COMPLETED")
            self.assertEqual(r["native_only_managed"], "PASS")
            boot.assert_called_once()
            self.assertEqual(probe.call_count, 2)
            self.assertEqual(probe.call_args.kwargs["override"], "native_only")
            self.assertNotIn(td, str(r))

    def test_native_only_failure_cannot_claim_persistent_clr(self):
        with TemporaryDirectory() as td:
            wine, prefix, loader, managed = self.fixture(Path(td))
            with (mock.patch.object(restart, "_is_wine_host", return_value=True),
                  mock.patch.object(restart, "validate_prefix"),
                  mock.patch.object(restart, "validate_original", return_value=True),
                  mock.patch.object(restart, "wineboot_restart", return_value="COMPLETED"),
                  mock.patch.object(restart, "snapshot",
                                    return_value={"CLR64": ("PE_AMD64", None),
                                                  "MSCORLIB64": ("PE_AMD64", None)}),
                  mock.patch.object(restart, "clr_load", return_value="LOADED"),
                  mock.patch.object(restart, "probe", side_effect=[
                      {"clr_family": "MICROSOFT_CLR_CANDIDATE", "managed": "PASS"},
                      {"clr_family": "UNKNOWN", "managed": "FAIL"}])):
                r = restart.inspect(wine, prefix, loader, managed, self.original())
            self.assertFalse(r["persistent_native_managed"])
            self.assertTrue(restart.validate(r))

    def test_restart_failure_exits_before_any_runtime_probes(self):
        with TemporaryDirectory() as td:
            wine, prefix, loader, managed = self.fixture(Path(td))
            with (mock.patch.object(restart, "_is_wine_host", return_value=True),
                  mock.patch.object(restart, "validate_prefix"),
                  mock.patch.object(restart, "validate_original", return_value=True),
                  mock.patch.object(restart, "wineboot_restart", return_value="TIMED_OUT"),
                  mock.patch.object(restart, "probe") as probe):
                r = restart.inspect(wine, prefix, loader, managed, self.original())
            self.assertEqual(r["status"], "RESTART_FAILED")
            self.assertEqual(r["restart"], "TIMED_OUT")
            self.assertFalse(r["persistent_native_managed"])
            self.assertTrue(restart.validate(r))
            probe.assert_not_called()

    def test_ineligible_original_msi_result_cannot_be_promoted(self):
        with TemporaryDirectory() as td:
            wine, prefix, loader, managed = self.fixture(Path(td))
            bad = dict(self.original(), native_loader="NOT_FOUND")
            with (mock.patch.object(restart, "_is_wine_host", return_value=True),
                  mock.patch.object(restart, "validate_prefix"),
                  mock.patch.object(restart, "validate_original", return_value=True),
                  mock.patch.object(restart, "wineboot_restart") as boot):
                r = restart.inspect(wine, prefix, loader, managed, bad)
            self.assertEqual(r, restart.blank())
            boot.assert_not_called()

    def test_no_native_windows_execution_or_private_report_keys(self):
        with TemporaryDirectory() as td:
            wine, prefix, loader, managed = self.fixture(Path(td))
            with mock.patch.object(restart, "_is_wine_host", return_value=False):
                with self.assertRaises(ValueError):
                    restart.inspect(wine, prefix, loader, managed, self.original())
            self.assertFalse(restart.validate(dict(restart.blank(), action="PRIVATE")))
            self.assertFalse(restart.validate(dict(restart.blank(), persistent_native_managed=True)))


if __name__ == "__main__":
    unittest.main()
