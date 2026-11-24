"""Synthetic tests for one genuine original CLR4 MSI 1603 fresh-prefix retry."""
import os
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase, mock, skipIf

from scripts import netfx40_fresh_prefix_retry as p


class OriginalMSIFreshPrefixRetryTests(TestCase):
    @staticmethod
    def failed():
        return {
            "installer_status": "EXIT_CAPTURED",
            "installer_exit": "MSI_FATAL_ERROR",
            "installer_exit_hex": "00000643",
            "installer_child_lifecycle": "ALL_EXITED",
            "candidate_native40": False,
            "clr64_after": "ABSENT",
            "clr32_after": "ABSENT",
            "mscorlib64_after": "ABSENT",
        }

    @staticmethod
    def invalid_restart():
        return {
            "status": "NOT_ELIGIBLE",
            "persistent_native_managed": False,
            "native_only_managed": "NOT_VERIFIED",
        }

    def test_only_exact_original_1603_with_no_clr_is_eligible(self):
        with (mock.patch.object(p, "valid_original", return_value=True),
              mock.patch.object(p, "valid_restart", return_value=True)):
            self.assertEqual(
                p.decision(self.failed(), self.invalid_restart()),
                "RETRY_ELIGIBLE")
            for field, wrong in (
                ("installer_exit", "SUCCESS"),
                ("installer_exit_hex", "00000642"),
                ("installer_child_lifecycle", "UNKNOWN"),
                ("clr64_after", "PE_AMD64"),
                ("clr32_after", "PE_I386"),
                ("mscorlib64_after", "PE_AMD64"),
                ("candidate_native40", True),
                ("installer_status", "TIMEOUT"),
            ):
                with self.subTest(field=field):
                    self.assertEqual(
                        p.decision({**self.failed(), field: wrong},
                                   self.invalid_restart()), "DENIED")
            self.assertEqual(
                p.decision(self.failed(), {**self.invalid_restart(),
                           "status": "RESTART_FAILED"}), "DENIED")
        self.assertEqual(
            p.decision(self.failed(), self.invalid_restart()), "DENIED")

    def test_real_native40_pass_is_never_reinstalled(self):
        valid = {**self.failed(), "candidate_native40": True}
        ready = {
            **self.invalid_restart(),
            "status": "RESTART_COMPLETED",
            "persistent_native_managed": True,
            "native_only_managed": "PASS",
        }
        with (mock.patch.object(p, "valid_original", return_value=True),
              mock.patch.object(p, "valid_restart", return_value=True),
              mock.patch.object(p, "_terminate_private_setup_wineserver")
              as stop):
            self.assertEqual(p.decision(valid, ready), "ALREADY_VERIFIED")
            self.assertEqual(
                p.prepare(Path("wine"), Path("prefix"), valid, ready),
                "ALREADY_VERIFIED")
            stop.assert_not_called()

    @skipIf(os.name == "nt", "Clean Wine prefix retry is POSIX-only")
    def test_rename_only_an_exact_marked_ephemeral_prefix_after_server_shutdown(self):
        with TemporaryDirectory() as td:
            root = Path(td)
            wine = root / "wine"
            wine.write_text("self-authored")
            prefix = root / p.CANONICAL
            prefix.mkdir()
            (prefix / p.MARKER).write_text("")
            (prefix / "system.reg").write_text("synthetic")
            with (mock.patch.dict(os.environ, {"RUNNER_TEMP": str(root)}),
                  mock.patch.object(p, "valid_original", return_value=True),
                  mock.patch.object(p, "valid_restart", return_value=True),
                  mock.patch.object(p, "_terminate_private_setup_wineserver",
                                    return_value=True) as stop):
                self.assertEqual(
                    p.prepare(wine, prefix, self.failed(),
                              self.invalid_restart(), agreed=True),
                    "FRESH_PREFIX_REQUIRED")
                stop.assert_called_once_with(wine, prefix)
                self.assertFalse(prefix.exists())
                archive = root / p.ARCHIVE
                self.assertEqual((archive / "system.reg").read_text(),
                                 "synthetic")
                self.assertEqual(
                    p.prepare(wine, prefix, self.failed(),
                              self.invalid_restart(), agreed=True),
                    "DENIED")

    @skipIf(os.name == "nt", "Clean Wine prefix retry is POSIX-only")
    def test_refuse_unmarked_symlinked_existing_archive_or_failed_cleanup(self):
        with TemporaryDirectory() as td:
            root = Path(td)
            prefix = root / p.CANONICAL
            prefix.mkdir()
            wine = root / "wine"
            wine.write_text("fixture")
            marker = prefix / p.MARKER
            marker.touch()
            with (mock.patch.dict(os.environ, {"RUNNER_TEMP": str(root)}),
                  mock.patch.object(p, "valid_original", return_value=True),
                  mock.patch.object(p, "valid_restart", return_value=True),
                  mock.patch.object(p, "_terminate_private_setup_wineserver",
                                    return_value=False) as stop):
                self.assertEqual(
                    p.prepare(wine, prefix, self.failed(),
                              self.invalid_restart(), agreed=True),
                    "DENIED")
                self.assertEqual(
                    p.prepare(wine, prefix, self.failed(),
                              self.invalid_restart(), agreed=False),
                    "DENIED")
                stop.assert_called_once()
                (root / p.ARCHIVE).mkdir()
                self.assertEqual(
                    p.prepare(wine, prefix, self.failed(),
                              self.invalid_restart(), agreed=True),
                    "DENIED")
                (root / p.ARCHIVE).rmdir()
                marker.unlink()
                marker.symlink_to(root / "outside")
                self.assertEqual(
                    p.prepare(wine, prefix, self.failed(),
                              self.invalid_restart(), agreed=True),
                    "DENIED")
                self.assertTrue(prefix.exists())
