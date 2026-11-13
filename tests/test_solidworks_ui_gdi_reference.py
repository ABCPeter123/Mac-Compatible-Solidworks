"""Synthetic-only Apple Silicon Wine GDI control, privacy and failure semantics."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from scripts.solidworks_bootstrap_trial import SENTINEL
from scripts.solidworks_ui_gdi_reference import run_reference, STATES


def isolated_prefix(root: Path) -> Path:
    prefix = root / "wine"
    (prefix / "drive_c").mkdir(parents=True)
    (prefix / "system.reg").write_text("Wine registry")
    (prefix / SENTINEL).touch()
    return prefix


@unittest.skipIf(os.name == "nt", "Synthetic Wine reference cannot execute on native Windows")
class ReferenceTests(unittest.TestCase):
    def run_case(self, returncode: int, output: bytes):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            prefix = isolated_prefix(root)
            probe = root / "test.exe"
            probe.write_bytes(b"MZ synthetic")
            with patch("scripts.solidworks_ui_gdi_reference.subprocess.run") as run:
                run.return_value = subprocess.CompletedProcess(
                    args=[], returncode=returncode, stdout=output, stderr=b"")
                report = run_reference(Path("/usr/bin/python3") if Path("/usr/bin/python3").is_file()
                                       else Path(__import__("sys").executable), prefix, probe)
                self.assertIn(report["reference"], STATES)
                self.assertTrue(report["synthetic_only"])
                self.assertEqual(report["original_solidworks_installer"], "NOT_USED")
                self.assertEqual(report["macos_onscreen_pixels"], "NOT_VERIFIED")
                self.assertNotIn(str(prefix), json.dumps(report))
                self.assertEqual(run.call_args.args[0][-1], "--self-test")
                self.assertEqual(run.call_args.kwargs["stderr"], subprocess.DEVNULL)
                self.assertEqual(run.call_args.kwargs["timeout"], 40)
                return report

    def test_reference_pass(self):
        self.assertEqual(self.run_case(0, b"SWCOMPAT_SW_UI_SELF_TEST=PASS\n")["reference"],
                         "REFERENCE_PASS")

    def test_reference_fail(self):
        self.assertEqual(self.run_case(1, b"SWCOMPAT_SW_UI_SELF_TEST=FAIL\n")["reference"],
                         "REFERENCE_FAILED")

    def test_nonzero_pass_claim_rejected(self):
        self.assertEqual(self.run_case(1, b"SWCOMPAT_SW_UI_SELF_TEST=PASS\n")["reference"],
                         "REFERENCE_UNEXPECTED")

    def test_zero_fail_claim_rejected(self):
        self.assertEqual(self.run_case(0, b"SWCOMPAT_SW_UI_SELF_TEST=FAIL\n")["reference"],
                         "REFERENCE_UNEXPECTED")

    def test_unrecognized_stdout_never_exported(self):
        self.assertEqual(self.run_case(0, b"serial=confidential\n")["reference"],
                         "REFERENCE_UNEXPECTED")

    def test_large_unrecognized_stdout(self):
        self.assertEqual(self.run_case(0, b"secret" * 1000)["reference"],
                         "REFERENCE_UNEXPECTED")

    def test_timeout_does_not_claim_pass(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            prefix = isolated_prefix(root)
            probe = root / "test.exe"
            probe.write_bytes(b"MZ")
            with patch("scripts.solidworks_ui_gdi_reference.subprocess.run",
                       side_effect=subprocess.TimeoutExpired("wine", 40)):
                result = run_reference(Path(__import__("sys").executable), prefix, probe)
            self.assertEqual(result["reference"], "REFERENCE_TIMEOUT")

    def test_uninitialized_prefix_refused(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(ValueError):
                run_reference(Path(__import__("sys").executable), Path(d), Path(d) / "test.exe")

    def test_missing_probe_refused(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            with self.assertRaises(ValueError):
                run_reference(Path(__import__("sys").executable), isolated_prefix(root),
                              root / "missing.exe")


if __name__ == "__main__":
    unittest.main()
