"""Safe evidence tests for the isolated MSI-created SCM service repair differential."""
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest import mock

from scripts import msi_service_scm_api_reconcile as api
from scripts import msi_service_restart_refresh as prior


def markers(phase, error="0", state="0", check="PASS"):
    return (f"SWCOMPAT_SERVICE_PHASE={phase}\n"
            f"SWCOMPAT_SERVICE_ERROR={error}\n"
            f"SWCOMPAT_SERVICE_STATE={state}\n"
            f"SWCOMPAT_SERVICE_CHECK={check}\n").encode("ascii")


class ScmReconciliationTests(unittest.TestCase):
    def test_error_decoder_observes_real_win32_registration_result(self):
        self.assertEqual(api.parse_operation(markers("install"), 0, "install"), "CREATED")
        self.assertEqual(api.parse_operation(markers("install", "1073", check="FAIL"), 1, "install"), "ALREADY_EXISTS")
        self.assertEqual(api.parse_operation(markers("install", "5", check="FAIL"), 1, "install"), "ACCESS_DENIED")
        self.assertEqual(api.parse_operation(markers("install", "1055", check="FAIL"), 1, "install"), "DATABASE_LOCKED")
        self.assertEqual(api.parse_operation(markers("install", "1722", check="FAIL"), 1, "install"), "RPC_UNAVAILABLE")
        self.assertEqual(api.parse_operation(markers("install", "1234", check="FAIL"), 1, "install"), "OTHER_FAILURE")
        self.assertEqual(api.parse_operation(markers("start", "0", state="4"), 0, "start"), "STARTED")
        self.assertEqual(api.parse_operation(markers("start", "1053", check="FAIL"), 1, "start"), "TIMEOUT")
        self.assertEqual(api.parse_operation(markers("start", "1055", check="FAIL"), 1, "start"), "DATABASE_LOCKED")
        for payload, code in (
            (markers("install") + b"SWCOMPAT_SERVICE_ERROR=0\n", 0),
            (markers("install") + b"SWCOMPAT_SERVICE_SECRET=private\n", 0),
            (markers("install"), 3),
            (markers("install", state="4"), 0),
            (markers("install").replace(b"PHASE=install", b"PHASE=start"), 0),
            (markers("install") + b"\x00", 0),
            (b"S" * 2049, 0),
            (markers("install", check="FAIL"), 0),
        ):
            self.assertEqual(api.parse_operation(payload, code, "install"), "INVALID_OUTPUT")

    @unittest.skipIf(os.name == "nt", "Original Wine-only test")
    def test_reconcile_recovers_only_from_verified_original_api_sequence(self):
        with TemporaryDirectory() as td:
            root = Path(td)
            (root / "drive_c").mkdir()
            (root / "system.reg").touch()
            (root / ".swcompat-netfx481-disposable").touch()
            wine = root / "wine"; wine.write_bytes(b"x"); wine.chmod(0o700)
            exe = root / "service_smoke.exe"; exe.write_bytes(b"x")
            evidence = {
                "schema": 1, "scope": prior.SCOPE, "trial": "MEASURED",
                "restart": "COMPLETED", "registry_before": "PRESENT",
                "scm_before": "ABSENT", "registry_after": "PRESENT",
                "scm_after": "UNKNOWN", "service_visibility_recovered": False,
                "native_microsoft_clr": False, "solidworks_compatibility": "NOT_DEMONSTRATED",
            }
            self.assertTrue(prior.validate(evidence))
            path = root / "prior.json"; path.write_text(json.dumps(evidence))
            states = ["ABSENT", "STOPPED", "RUNNING"]
            with (
                mock.patch.object(api, "binary_state", return_value="PRESENT_MATCH"),
                mock.patch.object(api, "service_registry", return_value="PRESENT"),
                mock.patch.object(api, "query_service", side_effect=states),
                mock.patch.object(api, "installed_binary", return_value=exe),
                mock.patch.object(api, "windows_media_path", return_value="C:\\\\safe\\\\service_smoke.exe"),
                mock.patch.object(api, "operation", side_effect=["CREATED", "STARTED"]) as ops,
            ):
                report = api.inspect(wine, root, exe, path)
                self.assertEqual(ops.call_count, 2)
            self.assertTrue(api.validate(report))
            self.assertTrue(report["registration_visibility_recovered"])
            self.assertTrue(report["service_running_verified"])
            self.assertEqual(report["scm_final"], "RUNNING")
            self.assertNotIn(str(root), str(report))
            self.assertFalse(api.validate(dict(report, native_microsoft_clr=True)))
            self.assertFalse(api.validate(dict(report, api_register="NOT_RUN")))
            self.assertFalse(api.validate(dict(report, api_start="NOT_RUN")))
            self.assertFalse(api.validate(dict(report, private_path=str(root))))

    @unittest.skipIf(os.name == "nt", "Original Wine-only test")
    def test_existing_registry_cannot_be_claimed_as_repaired_by_api(self):
        with TemporaryDirectory() as td:
            root = Path(td)
            (root / "drive_c").mkdir()
            (root / "system.reg").touch()
            (root / ".swcompat-netfx481-disposable").touch()
            wine = root / "wine"; wine.write_bytes(b"x"); wine.chmod(0o700)
            exe = root / "service_smoke.exe"; exe.write_bytes(b"x")
            evidence = {
                "schema": 1, "scope": prior.SCOPE, "trial": "MEASURED",
                "restart": "COMPLETED", "registry_before": "PRESENT",
                "scm_before": "ABSENT", "registry_after": "PRESENT",
                "scm_after": "ABSENT", "service_visibility_recovered": False,
                "native_microsoft_clr": False, "solidworks_compatibility": "NOT_DEMONSTRATED",
            }
            path = root / "prior.json"; path.write_text(json.dumps(evidence))
            with (
                mock.patch.object(api, "binary_state", return_value="PRESENT_MATCH"),
                mock.patch.object(api, "service_registry", return_value="PRESENT"),
                mock.patch.object(api, "query_service", side_effect=["ABSENT", "ABSENT", "ABSENT"]),
                mock.patch.object(api, "installed_binary", return_value=exe),
                mock.patch.object(api, "windows_media_path", return_value="C:\\\\safe.exe"),
                mock.patch.object(api, "operation", return_value="ALREADY_EXISTS") as ops,
            ):
                report = api.inspect(wine, root, exe, path)
                ops.assert_called_once()
            self.assertTrue(api.validate(report))
            self.assertFalse(report["registration_visibility_recovered"])
            self.assertFalse(report["service_running_verified"])
            self.assertEqual(report["api_register"], "ALREADY_EXISTS")

    @unittest.skipIf(os.name == "nt", "Original Wine-only test")
    def test_unmarked_prefix_refused_before_registry_or_scm_mutation(self):
        with TemporaryDirectory() as td:
            root = Path(td)
            (root / "drive_c").mkdir()
            (root / "system.reg").touch()
            with mock.patch.object(api, "operation") as op:
                with self.assertRaises(ValueError):
                    api.inspect(root / "wine", root, root / "service_smoke.exe", root / "prior.json")
                op.assert_not_called()

    def test_not_applicable_is_strictly_inert(self):
        report = {
            "schema": 1, "scope": api.SCOPE, "trial": "NOT_APPLICABLE",
            "installed_binary": "NOT_RUN", "scm_before": "UNKNOWN",
            "registry_before": "UNAVAILABLE", "api_register": "NOT_RUN",
            "scm_after_register": "UNKNOWN", "api_start": "NOT_RUN",
            "scm_final": "UNKNOWN", "registry_final": "UNAVAILABLE",
            "registration_visibility_recovered": False,
            "service_running_verified": False,
            "native_microsoft_clr": False, "solidworks_compatibility": "NOT_DEMONSTRATED",
        }
        self.assertTrue(api.validate(report))
        self.assertFalse(api.validate(dict(report, api_register="CREATED")))


if __name__ == "__main__":
    unittest.main()
