"""Privacy, negative-gate and original MSI metadata control tests."""
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest import mock

from scripts import netfx40_private_action as private
from scripts import netfx40_original_msi_table as original
from scripts.netfx40_offline_extract import EXTRACT_FOLDER, OLE_SIGNATURE


class OriginalMsiMetadataTests(unittest.TestCase):
    def _setup(self, base):
        prefix = base / "prefix"
        (prefix / "drive_c").mkdir(parents=True)
        root = prefix / "drive_c" / EXTRACT_FOLDER
        root.mkdir()
        wine = base / "wine"
        wine.write_bytes(b"wine")
        helper = base / "msi_custom_action_table_probe.exe"
        helper.write_bytes(b"helper")
        installer = base / "dotNetFx40_Full_x86_x64.exe"
        installer.write_bytes(b"original media mocked for synthetic test")
        return prefix, root, wine, helper, installer

    def _msi(self, root, name="netfx_Core_x64.msi"):
        f = root / name
        f.write_bytes(OLE_SIGNATURE + b"a" * 8000)
        return f

    def test_private_identifier_single_use_and_no_metadata_leak(self):
        with TemporaryDirectory() as td:
            p = Path(td)
            (p / "drive_c").mkdir()
            with mock.patch.object(private, "validate_prefix"):
                self.assertTrue(private.store(p, b"ServiceOriginal_42"))
                self.assertFalse(private.store(p, b"Other Name"))
                with self.assertRaises(ValueError):
                    private.store(p, b"ConflictingName")
                self.assertEqual(private.consume(p), "ServiceOriginal_42")
                self.assertIsNone(private.consume(p))
            self.assertFalse((p / "drive_c" / private.FILENAME).exists())

    def test_rejects_pathlike_or_nonascii_names(self):
        with TemporaryDirectory() as td:
            p = Path(td)
            (p / "drive_c").mkdir()
            with mock.patch.object(private, "validate_prefix"):
                for action in (b"X/secret", b"../../../x", b"x\ny", b"X" * 150,
                               b"\xff", b"x y"):
                    self.assertFalse(private.store(p, action))
                self.assertIsNone(private.consume(p))

    def test_matched_original_action_maps_only_base_type(self):
        with TemporaryDirectory() as td:
            p = Path(td)
            prefix, root, wine, helper, installer = self._setup(p)
            self._msi(root)
            with (mock.patch.object(private, "validate_prefix"),
                  mock.patch.object(original, "validate_prefix"),
                  mock.patch.object(original, "verify_media"),
                  mock.patch.object(original, "query",
                                    return_value={"status": "ACTION_FOUND",
                                                  "base_type": 1,
                                                  "family": "DLL_BINARY",
                                                  "stage": "ROW_FETCHED"}) as query):
                private.store(prefix, b"PrivateOriginalAction")
                result = original.inspect(wine, prefix, helper, installer)
            self.assertEqual(result["status"], "ACTION_FOUND")
            self.assertEqual(result["family"], "DLL_BINARY")
            self.assertEqual(result["base_type"], 1)
            self.assertTrue(original.validate(result))
            self.assertNotIn("PrivateOriginalAction", str(result))
            self.assertFalse((prefix / "drive_c" / private.FILENAME).exists())
            self.assertTrue(query.call_args.kwargs["allow_original_action"])

    def test_missing_private_identifier_does_not_query(self):
        with TemporaryDirectory() as td:
            p = Path(td)
            prefix, root, wine, helper, installer = self._setup(p)
            self._msi(root)
            with (mock.patch.object(private, "validate_prefix"),
                  mock.patch.object(original, "validate_prefix"),
                  mock.patch.object(original, "verify_media"),
                  mock.patch.object(original, "query") as query):
                result = original.inspect(wine, prefix, helper, installer)
            self.assertEqual(result["status"], "ACTION_NOT_CAPTURED")
            query.assert_not_called()
            self.assertTrue(original.validate(result))

    def test_two_matching_msi_files_cannot_claim_unique_type(self):
        with TemporaryDirectory() as td:
            p = Path(td)
            prefix, root, wine, helper, installer = self._setup(p)
            self._msi(root)
            self._msi(root, "netfx_Core_x86.msi")
            with (mock.patch.object(private, "validate_prefix"),
                  mock.patch.object(original, "validate_prefix"),
                  mock.patch.object(original, "verify_media"),
                  mock.patch.object(original, "query",
                                    return_value={"status": "ACTION_FOUND",
                                                  "base_type": 1,
                                                  "family": "DLL_BINARY",
                                                  "stage": "ROW_FETCHED"})):
                private.store(prefix, b"PrivateOriginalAction")
                result = original.inspect(wine, prefix, helper, installer)
            self.assertEqual(result["status"], "MULTIPLE_MATCHES")
            self.assertEqual(result["action_matches"], 2)
            self.assertIsNone(result["base_type"])
            self.assertTrue(original.validate(result))

    def test_partial_scan_positive_is_not_globally_unique(self):
        with TemporaryDirectory() as td:
            p = Path(td)
            prefix, root, wine, helper, installer = self._setup(p)
            self._msi(root)
            for i in range(18):
                (root / f"dir_{i:02d}").mkdir()
            with (mock.patch.object(private, "validate_prefix"),
                  mock.patch.object(original, "validate_prefix"),
                  mock.patch.object(original, "verify_media"),
                  mock.patch.object(original, "query",
                                    return_value={"status": "ACTION_FOUND",
                                                  "base_type": 2,
                                                  "family": "EXE_BINARY",
                                                  "stage": "ROW_FETCHED"})):
                private.store(prefix, b"PrivateOriginalAction")
                result = original.inspect(wine, prefix, helper, installer)
            self.assertEqual(result["status"], "ACTION_FOUND_PARTIAL")
            self.assertEqual(result["base_type"], 2)
            self.assertTrue(original.validate(result))

    def test_unmatched_and_corrupt_packages_do_not_claim_success(self):
        with TemporaryDirectory() as td:
            p = Path(td)
            prefix, root, wine, helper, installer = self._setup(p)
            self._msi(root)
            (root / "invalid.msi").write_bytes(b"z" * 9000)
            with (mock.patch.object(private, "validate_prefix"),
                  mock.patch.object(original, "validate_prefix"),
                  mock.patch.object(original, "verify_media"),
                  mock.patch.object(original, "query",
                                    return_value={"status": "ACTION_ABSENT",
                                                  "base_type": None,
                                                  "family": "NOT_VERIFIED",
                                                  "stage": "VIEW_EXECUTED"})):
                private.store(prefix, b"PrivateOriginalAction")
                result = original.inspect(wine, prefix, helper, installer)
            self.assertEqual(result["status"], "NOT_FOUND_IN_SCANNED_PACKAGES")
            self.assertEqual(result["msis_queried"], 1)
            self.assertTrue(original.validate(result))


if __name__ == "__main__":
    unittest.main()
