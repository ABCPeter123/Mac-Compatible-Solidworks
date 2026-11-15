"""Fixed service registry and cross-process SCM evidence must remain private."""
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest import mock

from scripts import msi_service_registry_observation as obs
from scripts import msi_service_action_trial as baseline


class RegistryVsScmTests(unittest.TestCase):
    def test_exact_original_service_key_and_fixed_registry_states(self):
        self.assertEqual(
            obs.FIXED_KEY,
            r"HKLM\SYSTEM\CurrentControlSet\Services\SWCompatOriginalServiceTest"
        )
        with TemporaryDirectory() as td:
            prefix = Path(td)
            (prefix / "drive_c").mkdir()
            (prefix / "system.reg").touch()
            (prefix / ".swcompat-netfx481-disposable").touch()
            wine = prefix / "wine"
            wine.write_bytes(b"original test")
            wine.chmod(0o700)
            with mock.patch.object(obs.subprocess, "run") as run:
                for code, expected in ((0, "PRESENT"), (1, "ABSENT"), (2, "UNAVAILABLE")):
                    run.return_value.returncode = code
                    self.assertEqual(obs.service_registry(wine, prefix), expected)
                    self.assertEqual(run.call_args.args[0][2:], ["query", obs.FIXED_KEY])
            with mock.patch.object(obs.subprocess, "run", side_effect=OSError):
                self.assertEqual(obs.service_registry(wine, prefix), "UNAVAILABLE")

    def test_true_registration_with_unobservable_scm_is_not_ready(self):
        with TemporaryDirectory() as td:
            prefix = Path(td)
            (prefix / "drive_c").mkdir()
            (prefix / "system.reg").touch()
            (prefix / ".swcompat-netfx481-disposable").touch()
            wine = prefix / "wine"; wine.write_bytes(b"x"); wine.chmod(0o700)
            prior = prefix / "prior.json"
            r = {
                "schema": 1, "scope": baseline.SCOPE, "status": "MEASURED",
                "winver": "APPLIED", "service_before": "ABSENT",
                "binary_before": "ABSENT", "msi_process": "ZERO",
                "unix_exit": 0, "binary_after": "PRESENT_MATCH",
                "service_after": "ABSENT", "msi_service_start_candidate": False,
                "dotnet_compatibility": False,
                "solidworks_compatibility": "NOT_DEMONSTRATED",
            }
            self.assertTrue(baseline.validate(r))
            prior.write_text(json.dumps(r))
            with mock.patch.object(obs, "service_registry", return_value="PRESENT"):
                result = obs.inspect(wine, prefix, prior)
            self.assertTrue(obs.validate(result))
            self.assertEqual(result["difference"], "REGISTRY_PRESENT_SCM_ABSENT")
            self.assertEqual(result["service_registry"], "PRESENT")
            self.assertNotIn(str(prefix), str(result))
            self.assertFalse(obs.validate(dict(result, difference="SCM_AND_REGISTRY_PRESENT")))
            self.assertFalse(obs.validate(dict(result, private_registry="sensitive")))
            self.assertFalse(obs.validate(dict(result, native_dotnet_compatibility=True)))

    def test_unmarked_prefix_never_runs_registry_query(self):
        with TemporaryDirectory() as td:
            prefix = Path(td); (prefix / "drive_c").mkdir(); (prefix / "system.reg").touch()
            with mock.patch.object(obs.subprocess, "run") as run:
                with self.assertRaises(ValueError):
                    obs.service_registry(prefix / "wine", prefix)
                run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
