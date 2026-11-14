"""Safety and real-file acceptance tests for a harmless self-authored MSI."""
from pathlib import Path
import json
import os
from tempfile import TemporaryDirectory
import unittest
from unittest import mock

from scripts import msi_transaction_trial as trial


class SelfAuthoredMSITests(unittest.TestCase):
    def test_verifies_sha256_and_never_accepts_wrong_media(self):
        with TemporaryDirectory() as td:
            root = Path(td)
            msi = root / trial.MSI_NAME
            digest = root / "msi.sha256"
            msi.write_bytes(b"self-authored MSI placeholder" * 100)
            import hashlib
            digest.write_text(hashlib.sha256(msi.read_bytes()).hexdigest())
            trial.verify_msi(msi, digest)
            digest.write_text("f" * 64)
            with self.assertRaises(ValueError):
                trial.verify_msi(msi, digest)

    def test_sanitized_report_cannot_fake_dotnet_or_msi_success(self):
        r = {
            "schema": 1, "scope": "SELF_AUTHORED_MSI_WINE_TRANSACTION",
            "status": "MEASURED", "winver": "APPLIED",
            "msi_process": "NONZERO", "unix_exit": 2,
            "marker_before": "ABSENT", "marker_after": "ABSENT",
            "transaction_candidate": False, "dotnet_compatibility": False,
            "solidworks_compatibility": "NOT_DEMONSTRATED",
        }
        self.assertTrue(trial.validate(r))
        for field, value in [
            ("transaction_candidate", True), ("dotnet_compatibility", True),
            ("marker_after", "C:\\Users\\Private"),
            ("solidworks_compatibility", "READY"),
            ("unix_exit", 999999), ("msi_process", "EXECUTED_USER_EXE"),
        ]:
            bad = dict(r)
            bad[field] = value
            self.assertFalse(trial.validate(bad), field)
        self.assertNotIn("C:\\", json.dumps(r))

    @unittest.skipIf(os.name == "nt", "Wine test intentionally cannot run on Windows")
    def test_self_authored_payload_must_really_appear_after_zero_exit(self):
        with TemporaryDirectory() as td:
            root = Path(td)
            prefix = root / "prefix"
            (prefix / "drive_c").mkdir(parents=True)
            (prefix / "system.reg").touch()
            (prefix / ".swcompat-netfx481-disposable").touch()
            wine = root / "wine"
            wine.write_bytes(b"runner")
            wine.chmod(0o700)
            msi = root / trial.MSI_NAME
            manifest = root / "msi.sha256"
            msi.write_bytes(b"safe" * 400)
            manifest.write_text("0" * 64)
            with (
                mock.patch.object(trial, "verify_msi"),
                mock.patch.object(trial, "set_legacy_winver", return_value="APPLIED"),
                mock.patch.object(trial, "install", return_value=("ZERO", 0)),
            ):
                r = trial.inspect(wine, prefix, msi, manifest)
                self.assertTrue(trial.validate(r))
                self.assertFalse(r["transaction_candidate"])
                self.assertEqual(r["marker_after"], "ABSENT")
                target = trial.marker_path(prefix)
                target.parent.mkdir(parents=True)
                target.write_bytes(trial.MARKER)
                # Already-existing proof can never be reused as a new success.
                r = trial.inspect(wine, prefix, msi, manifest)
                self.assertEqual(r["status"], "ALREADY_MARKED")
                self.assertFalse(r["transaction_candidate"])
                target.unlink()
                def perform(w, p, m, timeout):
                    target.write_bytes(trial.MARKER)
                    return "ZERO", 0
                with mock.patch.object(trial, "install", side_effect=perform):
                    r = trial.inspect(wine, prefix, msi, manifest)
                    self.assertTrue(trial.validate(r))
                    self.assertTrue(r["transaction_candidate"])
                    self.assertFalse(r["dotnet_compatibility"])

    def test_rejects_unmarked_prefix_without_msi_execution(self):
        with TemporaryDirectory() as td:
            root = Path(td)
            with mock.patch.object(trial, "install") as install:
                with self.assertRaises(ValueError):
                    trial.inspect(root / "wine", root / "prefix", root / "msi", root / "sha")
                install.assert_not_called()


if __name__ == "__main__":
    unittest.main()
