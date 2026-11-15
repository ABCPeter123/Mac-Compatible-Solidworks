"""Original Microsoft .NET MSI presence inventory is bounded and never leaks paths."""
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest import mock

from scripts import netfx40_msi_inventory as inv


class OriginalMsiCensusTests(unittest.TestCase):
    def test_empty_prefix_and_original_named_candidates(self):
        with TemporaryDirectory() as td:
            root = Path(td)
            with mock.patch.object(inv, "validate_prefix"):
                none = inv.scan(root)
                self.assertEqual(none["status"], "ABSENT")
                self.assertTrue(inv.validate(none))
                folder = root / "drive_c" / "users" / "PrivateUser" / "Temp"
                folder.mkdir(parents=True)
                (folder / "netfx_core_x64.msi").write_bytes(b"own" * 2000)
                (folder / "OTHER-package.msi").write_bytes(b"own" * 2000)
                (folder / "netfx_invalid.txt").write_text("not an MSI")
                result = inv.scan(root)
            self.assertEqual(result["status"], "CANDIDATE_PRESENT")
            self.assertEqual(result["msi_candidates"], 2)
            self.assertEqual(result["netfx_named_candidates"], 1)
            self.assertTrue(inv.validate(result))
            for secret in ("PrivateUser", "netfx_core_x64.msi", "OTHER-package.msi"):
                self.assertNotIn(secret, str(result))

    def test_rejects_undersized_or_oversized_untrusted_packages(self):
        with TemporaryDirectory() as td:
            root = Path(td)
            folder = root / "drive_c" / "Temp"
            folder.mkdir(parents=True)
            (folder / "netfx_tiny.msi").write_bytes(b"tiny")
            (folder / "nameé.msi").write_bytes(b"own" * 2000)
            with mock.patch.object(inv, "validate_prefix"):
                result = inv.scan(root)
            self.assertEqual(result["status"], "ABSENT")
            self.assertEqual(result["msi_candidates"], 0)

    def test_symlinked_roots_are_never_followed(self):
        with TemporaryDirectory() as td:
            root = Path(td)
            outside = root / "outside"
            outside.mkdir()
            (outside / "netfx_private.msi").write_bytes(b"fake" * 2000)
            win = root / "drive_c" / "windows"
            win.mkdir(parents=True)
            (win / "temp").symlink_to(outside, target_is_directory=True)
            with mock.patch.object(inv, "validate_prefix"):
                report = inv.scan(root)
            self.assertEqual(report["msi_candidates"], 0)
            self.assertEqual(report["status"], "INVALID_ROOT")
            self.assertTrue(inv.validate(report))

    def test_bounded_drive_root_hash_extraction_folders(self):
        with TemporaryDirectory() as td:
            prefix = Path(td)
            drive = prefix / "drive_c"
            valid = drive / "a1b2c3d4e5f60718"
            valid.mkdir(parents=True)
            (valid / "netfx_Core_x64.msi").write_bytes(b"test" * 1800)
            ignored = drive / "arbitrary-extracted-folder"
            ignored.mkdir()
            (ignored / "netfx_ignored.msi").write_bytes(b"test" * 1800)
            with mock.patch.object(inv, "validate_prefix"):
                r = inv.scan(prefix)
            self.assertTrue(inv.validate(r))
            self.assertEqual(r["status"], "CANDIDATE_PRESENT")
            self.assertEqual(r["msi_candidates"], 1)
            self.assertEqual(r["netfx_named_candidates"], 1)
            self.assertNotIn("netfx_Core_x64", str(r))

    def test_drive_root_hash_symlink_not_followed(self):
        with TemporaryDirectory() as td:
            prefix = Path(td)
            drive = prefix / "drive_c"
            drive.mkdir()
            external = prefix / "external"
            external.mkdir()
            (external / "netfx_private.msi").write_bytes(b"test" * 1800)
            (drive / "abcdef0123456789").symlink_to(
                external, target_is_directory=True)
            with mock.patch.object(inv, "validate_prefix"):
                r = inv.scan(prefix)
            self.assertTrue(inv.validate(r))
            self.assertEqual(r["status"], "ABSENT")
            self.assertEqual(r["msi_candidates"], 0)

    def test_more_than_twelve_hash_roots_is_partial(self):
        with TemporaryDirectory() as td:
            prefix = Path(td)
            drive = prefix / "drive_c"
            drive.mkdir()
            for i in range(inv.MAX_ROOT_HASH_DIRS + 2):
                (drive / f"deadbeef{i:010x}").mkdir()
            with mock.patch.object(inv, "validate_prefix"):
                r = inv.scan(prefix)
            self.assertTrue(inv.validate(r))
            self.assertEqual(r["status"], "PARTIAL_SCAN")
            self.assertLessEqual(r["directories_checked"], inv.MAX_DIRS)

    def test_limit_and_status_schema_fail_closed(self):
        with TemporaryDirectory() as td:
            root = Path(td)
            folder = root / "drive_c" / "Temp"
            folder.mkdir(parents=True)
            for i in range(inv.MAX_MATCHES + 3):
                (folder / f"netfx_{i:03d}.msi").write_bytes(b"own" * 2000)
            with mock.patch.object(inv, "validate_prefix"):
                report = inv.scan(root)
            self.assertEqual(report["status"], "PARTIAL_SCAN")
            self.assertEqual(report["msi_candidates"], inv.MAX_MATCHES)
            self.assertTrue(inv.validate(report))
            self.assertFalse(inv.validate(dict(report, filenames=["secret"])))
            self.assertFalse(inv.validate(dict(report, status="INSTALLED_CLR")))
            self.assertFalse(inv.validate(dict(report, msi_candidates=999)))
            self.assertTrue(inv.validate(inv.empty()))


if __name__ == "__main__":
    unittest.main()
