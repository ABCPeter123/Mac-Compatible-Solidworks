"""Synthetic privacy and status gates for signed Windows-versus-Wine shim comparison."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock
from scripts import netfx48_windows_shim_only as t


class WindowsSignedShimTests(unittest.TestCase):
    def test_bounded_privacy_schema(self):
        x = t.blank()
        self.assertTrue(t.valid(x))
        for bad in (
            dict(x, raw_original_path="C:\\private\\mscoreei.dll"),
            dict(x, original_runtime_installed=True),
            dict(x, schema=True),
            dict(x, source="STAGED"),
            dict(x, source="NO_MATCH", native_shim="ORIGINAL_SHIM_ONLY_LOADED"),
            dict(x, source="STAGED", native_shim="ORIGINAL_SHIM_ONLY_LOADED",
                 process="TIMEOUT"),
        ):
            self.assertFalse(t.valid(bad))
        self.assertTrue(t.valid(dict(x, source="STAGED",
                                     native_shim="ORIGINAL_SHIM_INIT_FAILED",
                                     process="EXIT_ZERO")))

    def test_rejects_invalid_original_digest_before_execution(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            original = root / "NDP48-x86-x64-AllOS-ENU.exe"
            original.write_bytes(b"synthetic")
            seven = root / "7z.exe"
            seven.write_bytes(b"synthetic")
            fixture = root / "netfx48_host_activation.exe"
            fixture.write_bytes(b"synthetic")
            with mock.patch.object(t, "stage") as stage:
                with self.assertRaises(ValueError):
                    t.evaluate(original, "1" * 64, seven, fixture)
                stage.assert_not_called()

    def test_no_original_shim_cannot_claim_runtime_loaded(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            seven = root / "7z.exe"
            seven.write_bytes(b"synthetic")
            fixture = root / "netfx48_host_activation.exe"
            fixture.write_bytes(b"synthetic")
            original = root / "NDP48-x86-x64-AllOS-ENU.exe"
            original.write_bytes(b"synthetic")
            staged = {
                "status": "NO_MZZ_MATCH", "missing_requested": 1,
                "located": 0, "staged": 0,
                "families": {k: {"located": 0, "staged": 0} for k in t.stage_blank()["families"]},
                "original_runtime_installed": False,
            }
            with mock.patch.object(t, "verify_original"), \
                 mock.patch.object(t, "stage", return_value=staged), \
                 mock.patch.object(t.subprocess, "run",
                                   return_value=mock.Mock(returncode=0)) as run:
                report = t.evaluate(original, "1" * 64, seven, fixture)
            self.assertEqual(report["source"], "NO_MATCH")
            self.assertEqual(report["native_shim"], "NOT_RUN")
            self.assertTrue(t.valid(report))
            self.assertEqual(run.call_count, 1)
            self.assertNotIn("NDP48", json.dumps(report))


if __name__ == "__main__":
    unittest.main()
