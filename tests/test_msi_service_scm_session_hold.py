"""Finite, independent SCM connection lifetime experiment tests."""
import json
import os
import subprocess
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest import mock

from scripts import msi_service_scm_session_hold as trial
from scripts import msi_service_scm_coherence as previous


class SCMHolderTests(unittest.TestCase):
    def test_holder_marker_is_strict_and_finite(self):
        self.assertEqual(trial.parse_holder(b"SWCOMPAT_SCM_HOLDER=SERVICE_OPEN\n"), "SERVICE_OPEN")
        self.assertEqual(trial.parse_holder(b"SWCOMPAT_SCM_HOLDER=MANAGER_ONLY\n"), "MANAGER_ONLY")
        for bad in (b"SWCOMPAT_SCM_HOLDER=NOT_REAL\n",
                    b"SWCOMPAT_SCM_HOLDER=SERVICE_OPEN\nSWCOMPAT_SCM_HOLDER=SERVICE_OPEN\n",
                    b"SWCOMPAT_SCM_HOLDER=SERVICE_OPEN\x00",
                    b"x" * 1025, b"UNTRUSTED=SERVICE_OPEN"):
            self.assertEqual(trial.parse_holder(bad), "NO_MARKER")

    def test_only_real_cross_process_visibility_counts(self):
        self.assertEqual(trial.classify("ABSENT", "SERVICE_OPEN", "STOPPED", "ABSENT"),
                         "VISIBLE_ONLY_WITH_HOLDER")
        self.assertEqual(trial.classify("ABSENT", "SERVICE_OPEN", "RUNNING", "ABSENT"),
                         "VISIBLE_ONLY_WITH_HOLDER")
        self.assertEqual(trial.classify("ABSENT", "SERVICE_OPEN", "ABSENT", "ABSENT"),
                         "STILL_ABSENT_WITH_HOLDER")
        self.assertEqual(trial.classify("ABSENT", "MANAGER_ONLY", "STOPPED", "ABSENT"),
                         "UNRESOLVED")
        self.assertEqual(trial.classify("UNKNOWN", "SERVICE_OPEN", "RUNNING", "UNKNOWN"),
                         "UNRESOLVED")

    @unittest.skipIf(os.name == "nt", "Runs only in marked Wine prefix")
    def test_eligible_original_fixture_measures_independent_process(self):
        with TemporaryDirectory() as td:
            root = Path(td)
            (root / "drive_c").mkdir()
            (root / "system.reg").touch()
            (root / ".swcompat-netfx481-disposable").touch()
            wine = root / "wine"; wine.write_bytes(b"x"); wine.chmod(0o700)
            exe = root / "service_smoke.exe"; exe.write_bytes(b"x")
            earlier = {
                "schema": 1, "scope": previous.SCOPE, "trial": "MEASURED",
                "first_lookup": "PRESENT", "create": "NOT_RUN",
                "second_lookup": "PRESENT", "registry_after": "PRESENT",
                "outcome": "CROSS_PROCESS_DISAGREEMENT", "native_microsoft_clr": False,
                "solidworks_compatibility": "NOT_DEMONSTRATED",
            }
            self.assertTrue(previous.validate(earlier))
            prior = root / "prior.json"; prior.write_text(json.dumps(earlier))
            with (
                mock.patch.object(trial, "binary_state", return_value="PRESENT_MATCH"),
                mock.patch.object(trial, "service_registry", return_value="PRESENT"),
                mock.patch.object(trial, "query_with_diagnostic",
                                  side_effect=[("ABSENT", "PARSED"), ("ABSENT", "PARSED")]),
                mock.patch.object(trial, "during_holder",
                                  return_value=("SERVICE_OPEN", "STOPPED", "PARSED")) as held,
            ):
                result = trial.inspect(wine, root, exe, prior)
                held.assert_called_once()
            self.assertTrue(trial.validate(result))
            self.assertEqual(result["outcome"], "VISIBLE_ONLY_WITH_HOLDER")
            self.assertEqual(result["diagnostic_while_held"], "PARSED")
            self.assertFalse(trial.validate(dict(result, diagnostic_while_held="NO_PROTOCOL")))
            self.assertFalse(result["native_microsoft_clr"])
            self.assertNotIn(str(root), str(result))
            self.assertFalse(trial.validate(dict(result, native_microsoft_clr=True)))
            self.assertFalse(trial.validate(dict(result, outcome="STILL_ABSENT_WITH_HOLDER")))
            self.assertFalse(trial.validate(dict(result, proprietary="secret")))

    @unittest.skipIf(os.name == "nt", "Runs only in marked Wine prefix")
    def test_unmarked_prefix_refused_before_process_creation(self):
        with TemporaryDirectory() as td:
            root = Path(td)
            (root / "drive_c").mkdir()
            (root / "system.reg").touch()
            wine = root / "wine"; wine.write_bytes(b"x"); wine.chmod(0o700)
            exe = root / "service_smoke.exe"; exe.write_bytes(b"x")
            prior = root / "prior.json"; prior.write_text("{}")
            with mock.patch.object(trial.subprocess, "Popen") as spawn:
                with self.assertRaises(ValueError):
                    trial.inspect(wine, root, exe, prior)
                spawn.assert_not_called()

    def test_distinguishes_unknown_process_exit_from_missing_protocol(self):
        with TemporaryDirectory() as td:
            root = Path(td)
            wine = root / "wine"; wine.write_bytes(b"x")
            exe = root / "service_smoke.exe"; exe.write_bytes(b"x")
            class Completed:
                def __init__(self, code):
                    self.returncode = code
            def mock_run(*args, **kwargs):
                kwargs["stdout"].write(
                    b"SWCOMPAT_SERVICE_PHASE=status\n"
                    b"SWCOMPAT_SERVICE_ERROR=1060\n"
                    b"SWCOMPAT_SERVICE_STATE=0\n"
                    b"SWCOMPAT_SERVICE_CHECK=FAIL\n"
                )
                return Completed(1)
            with mock.patch.object(trial.subprocess, "run", side_effect=mock_run):
                self.assertEqual(trial.query_with_diagnostic(wine, root, exe),
                                 ("ABSENT", "PARSED"))
            with mock.patch.object(trial.subprocess, "run", return_value=Completed(7)):
                self.assertEqual(trial.query_with_diagnostic(wine, root, exe),
                                 ("UNKNOWN", "BAD_EXIT"))
            with mock.patch.object(trial.subprocess, "run", return_value=Completed(0)):
                self.assertEqual(trial.query_with_diagnostic(wine, root, exe),
                                 ("UNKNOWN", "NO_PROTOCOL"))
            with mock.patch.object(trial.subprocess, "run", side_effect=subprocess.TimeoutExpired("wine", 25)):
                self.assertEqual(trial.query_with_diagnostic(wine, root, exe),
                                 ("UNKNOWN", "TIMED_OUT"))
            with mock.patch.object(trial.subprocess, "run", side_effect=OSError):
                self.assertEqual(trial.query_with_diagnostic(wine, root, exe),
                                 ("UNKNOWN", "LAUNCH_FAILED"))

    def test_false_success_for_not_applicable_fails_closed(self):
        r = {
            "schema": 1, "scope": trial.SCOPE, "trial": "NOT_APPLICABLE",
            "binary": "NOT_RUN", "registry": "UNAVAILABLE",
            "scm_before": "UNKNOWN", "holder": "NOT_RUN",
            "scm_while_held": "UNKNOWN", "scm_after": "UNKNOWN",
            "diagnostic_before": "NOT_RUN", "diagnostic_while_held": "NOT_RUN",
            "diagnostic_after": "NOT_RUN",
            "outcome": "NOT_APPLICABLE", "native_microsoft_clr": False,
            "solidworks_compatibility": "NOT_DEMONSTRATED",
        }
        self.assertTrue(trial.validate(r))
        self.assertFalse(trial.validate(dict(r, outcome="VISIBLE_ONLY_WITH_HOLDER")))


if __name__ == "__main__":
    unittest.main()
