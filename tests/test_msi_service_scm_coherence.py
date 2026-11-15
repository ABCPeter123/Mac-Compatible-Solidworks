"""Regression tests for original MSI SCM intra-process coherence evidence."""
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest import mock

from scripts import msi_service_scm_coherence as probe
from scripts import msi_service_scm_api_reconcile as previous


def frame(first="ABSENT", create="ALREADY_EXISTS", second="ABSENT"):
    return (f"SWCOMPAT_COHERENCE_BEFORE={first}\n"
            f"SWCOMPAT_COHERENCE_CREATE={create}\n"
            f"SWCOMPAT_COHERENCE_AFTER={second}\n"
            "SWCOMPAT_COHERENCE_COMPLETE=YES\n").encode()


class SameHandleTests(unittest.TestCase):
    def test_exact_four_marker_protocol(self):
        r = probe.parse(frame(), 0)
        self.assertEqual(r["CREATE"], "ALREADY_EXISTS")
        self.assertIsNone(probe.parse(frame() + b"SWCOMPAT_COHERENCE_BEFORE=OTHER\n", 0))
        self.assertIsNone(probe.parse(frame() + b"SWCOMPAT_COHERENCE_PRIVATE=secret\n", 0))
        self.assertIsNone(probe.parse(frame() + b"\0", 0))
        self.assertIsNone(probe.parse(frame(), 1))
        self.assertIsNone(probe.parse(b"x" * 2049, 0))
        self.assertIsNone(probe.parse(frame().replace(b"AFTER=ABSENT", b"AFTER=UNKNOWN"), 0))

    def test_outcomes_never_infer_native_runtime(self):
        self.assertEqual(probe.verdict("ABSENT", "ALREADY_EXISTS", "ABSENT"),
                         "EXISTS_BUT_INVISIBLE")
        self.assertEqual(probe.verdict("PRESENT", "NOT_RUN", "PRESENT"),
                         "CROSS_PROCESS_DISAGREEMENT")
        self.assertEqual(probe.verdict("ABSENT", "CREATED", "PRESENT"),
                         "NEW_REGISTRATION_VISIBLE")
        self.assertEqual(probe.verdict("ABSENT", "ACCESS_DENIED", "ABSENT"),
                         "UNRESOLVED")

    @unittest.skipIf(os.name == "nt", "Runs only on isolated Wine")
    def test_same_scm_connection_is_reported_only_with_real_protocol(self):
        with TemporaryDirectory() as td:
            root = Path(td)
            (root / "drive_c").mkdir()
            (root / "system.reg").touch()
            (root / ".swcompat-netfx481-disposable").touch()
            wine = root / "wine"; wine.write_bytes(b"x"); wine.chmod(0o700)
            exe = root / "service_smoke.exe"; exe.write_bytes(b"x")
            evidence = {
                "schema": 1, "scope": previous.SCOPE,
                "trial": "MEASURED", "installed_binary": "PRESENT_MATCH",
                "scm_before": "ABSENT", "registry_before": "PRESENT",
                "api_register": "ALREADY_EXISTS", "scm_after_register": "ABSENT",
                "api_start": "NOT_RUN", "scm_final": "UNKNOWN",
                "registry_final": "PRESENT",
                "registration_visibility_recovered": False,
                "service_running_verified": False,
                "native_microsoft_clr": False,
                "solidworks_compatibility": "NOT_DEMONSTRATED",
            }
            self.assertTrue(previous.validate(evidence))
            prior = root / "prior.json"; prior.write_text(json.dumps(evidence))
            class Done:
                returncode = 0
            def fake_run(*a, **kw):
                kw["stdout"].write(frame())
                return Done()
            with (
                mock.patch.object(probe, "binary_state", return_value="PRESENT_MATCH"),
                mock.patch.object(probe, "service_registry", return_value="PRESENT"),
                mock.patch.object(probe, "installed_binary", return_value=exe),
                mock.patch.object(probe, "windows_media_path", return_value="C:\\\\fixture.exe"),
                mock.patch.object(probe.subprocess, "run", side_effect=fake_run) as runner,
            ):
                r = probe.inspect(wine, root, exe, prior)
                runner.assert_called_once()
                # The real Apple Silicon run also returned CREATED with no
                # independently verified SCM view. That must still be measured.
                evidence["api_register"] = "CREATED"
                evidence["scm_after_register"] = "UNKNOWN"
                self.assertTrue(previous.validate(evidence))
                prior.write_text(json.dumps(evidence))
                r2 = probe.inspect(wine, root, exe, prior)
            self.assertTrue(probe.validate(r2))
            self.assertEqual(r2["trial"], "MEASURED")
            self.assertTrue(probe.validate(r))
            self.assertEqual(r["outcome"], "EXISTS_BUT_INVISIBLE")
            self.assertNotIn(str(root), str(r))
            self.assertFalse(probe.validate(dict(r, native_microsoft_clr=True)))
            self.assertFalse(probe.validate(dict(r, outcome="CROSS_PROCESS_DISAGREEMENT")))
            self.assertFalse(probe.validate(dict(r, private="secret")))

    def test_inert_not_applicable_report(self):
        r = {
            "schema": 1, "scope": probe.SCOPE, "trial": "NOT_APPLICABLE",
            "first_lookup": "NOT_RUN", "create": "NOT_RUN", "second_lookup": "NOT_RUN",
            "registry_after": "UNAVAILABLE", "outcome": "NOT_APPLICABLE",
            "native_microsoft_clr": False, "solidworks_compatibility": "NOT_DEMONSTRATED",
        }
        self.assertTrue(probe.validate(r))
        self.assertFalse(probe.validate(dict(r, outcome="EXISTS_BUT_INVISIBLE")))

    @unittest.skipIf(os.name == "nt", "Runs only on isolated Wine")
    def test_unmarked_prefix_rejected_before_execution(self):
        with TemporaryDirectory() as td:
            root = Path(td)
            (root / "drive_c").mkdir()
            (root / "system.reg").touch()
            wine = root / "wine"; wine.write_bytes(b"x"); wine.chmod(0o700)
            exe = root / "service_smoke.exe"; exe.write_bytes(b"x")
            prior = root / "prior.json"; prior.write_text("{}")
            with mock.patch.object(probe.subprocess, "run") as runner:
                with self.assertRaises(ValueError):
                    probe.inspect(wine, root, exe, prior)
                runner.assert_not_called()


if __name__ == "__main__":
    unittest.main()
