"""A Wine restart alone never establishes a working SCM service."""
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest import mock

from scripts import msi_service_restart_refresh as refresh
from scripts import msi_service_registry_observation as registry


class WineServiceRestartTests(unittest.TestCase):
    @unittest.skipIf(os.name == "nt", "Only original disposable Wine prefix")
    def test_genuine_registry_visible_only_after_supported_wine_restart(self):
        with TemporaryDirectory() as td:
            root = Path(td)
            (root / "drive_c").mkdir()
            (root / "system.reg").touch()
            (root / ".swcompat-netfx481-disposable").touch()
            wine = root / "wine"; wine.write_bytes(b"x"); wine.chmod(0o700)
            exe = root / "service_smoke.exe"; exe.write_bytes(b"x")
            prior = root / "prior.json"
            evidence = {
                "schema": 1, "scope": registry.SCOPE,
                "service_registry": "PRESENT", "independent_scm": "ABSENT",
                "difference": "REGISTRY_PRESENT_SCM_ABSENT",
                "installer_status": "ZERO", "file_status": "PRESENT_MATCH",
                "native_dotnet_compatibility": False,
                "solidworks_compatibility": "NOT_DEMONSTRATED",
            }
            self.assertTrue(registry.validate(evidence))
            prior.write_text(json.dumps(evidence))
            with (
                mock.patch.object(refresh, "wineboot_restart", return_value="COMPLETED") as boot,
                mock.patch.object(refresh, "service_registry", return_value="PRESENT"),
                mock.patch.object(refresh, "query_service", return_value="STOPPED"),
            ):
                r = refresh.inspect(wine, root, exe, prior)
                boot.assert_called_once()
            self.assertTrue(refresh.validate(r))
            self.assertTrue(r["service_visibility_recovered"])
            self.assertEqual(r["scm_before"], "ABSENT")
            self.assertEqual(r["scm_after"], "STOPPED")
            self.assertNotIn(str(root), str(r))
            for bad in (
                dict(r, restart="TIMED_OUT"),
                dict(r, registry_after="ABSENT"),
                dict(r, scm_after="ABSENT"),
                dict(r, native_microsoft_clr=True),
                dict(r, private_log="secret"),
            ):
                self.assertFalse(refresh.validate(bad))
            with (
                mock.patch.object(refresh, "wineboot_restart", return_value="COMPLETED"),
                mock.patch.object(refresh, "service_registry", return_value="PRESENT"),
                mock.patch.object(refresh, "query_service", return_value="ABSENT"),
            ):
                still_absent = refresh.inspect(wine, root, exe, prior)
            self.assertTrue(refresh.validate(still_absent))
            self.assertFalse(still_absent["service_visibility_recovered"])

    def test_not_applicable_cannot_claim_success(self):
        report = {
            "schema": 1, "scope": refresh.SCOPE, "trial": "NOT_APPLICABLE",
            "restart": "NOT_RUN", "registry_before": "ABSENT",
            "scm_before": "ABSENT", "registry_after": "UNAVAILABLE",
            "scm_after": "UNKNOWN", "service_visibility_recovered": False,
            "native_microsoft_clr": False,
            "solidworks_compatibility": "NOT_DEMONSTRATED",
        }
        self.assertTrue(refresh.validate(report))
        self.assertFalse(refresh.validate(dict(report, restart="COMPLETED")))
        self.assertFalse(refresh.validate(dict(report, service_visibility_recovered=True)))

    @unittest.skipIf(os.name == "nt", "Only original disposable Wine prefix")
    def test_unmarked_prefix_refused_before_restart(self):
        with TemporaryDirectory() as td:
            root = Path(td)
            (root / "drive_c").mkdir()
            (root / "system.reg").touch()
            with mock.patch.object(refresh, "wineboot_restart") as boot:
                with self.assertRaises(ValueError):
                    refresh.inspect(root / "wine", root, root / "service_smoke.exe",
                                    root / "prior.json")
                boot.assert_not_called()


if __name__ == "__main__":
    unittest.main()
