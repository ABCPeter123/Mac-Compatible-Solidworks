"""Synthetic no-vendor-data regression tests for original Microsoft MZZ diagnostics."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from scripts import netfx4x_mzz_evidence as mzz


class MzzEvidenceTests(unittest.TestCase):
    def test_original_member_patterns_and_strict_privacy(self):
        private = (
            b"Path = C:\\Users\\private\\archive.mzz\n"
            b"Type = 7z\n"
            b"----------\n"
            b"Path = clr_amd64.dll\n"
            b"Path = mscorlib_amd64.dll\n"
            b"Path = System_Xaml_amd64.dll\n"
            b"Path = PresentationFramework_x86.dll\n"
            b"Path = servicing.mum\n"
            b"Path = C:\\Users\\private\\secret-MY-DATA.bin\n"
        )
        result = mzz.classify_listing(private)
        self.assertEqual(result["entries"], 6)
        self.assertEqual(result["types"]["DLL"], 4)
        self.assertEqual(result["types"]["MUM"], 1)
        self.assertTrue(all(result["signals"].values()))
        for secret in ("Users", "private", "archive.mzz", "MY-DATA",
                       "System_Xaml_amd64.dll"):
            self.assertNotIn(secret, json.dumps(result))

    def test_untrusted_listing_fails_closed(self):
        self.assertIsNone(mzz.classify_listing(b"Path = clr_amd64.dll\n"))
        self.assertIsNone(mzz.classify_listing(b"----------\nPath = ..\n"))
        self.assertIsNone(mzz.classify_listing(b"\x00\x01"))
        self.assertIsNone(mzz.classify_listing(b"x" * (mzz.MAX_LIST_BYTES + 1)))
        self.assertIsNone(mzz.classify_listing(b"----------\nPath = \xff\n"))
        self.assertIsNone(mzz.classify_listing(b"----------\n"))
        self.assertIsNone(mzz.classify_listing(
            b"----------\n" + b"Path = x.dll\n" * (mzz.MAX_ENTRIES + 1)))

    def test_strict_schema_rejects_forgery(self):
        self.assertTrue(mzz.validate(mzz.empty()))
        d = mzz.empty("SCANNED")
        d["mzz_found"] = 1
        d["mzz_listed"] = 1
        d["entries"] = 1
        d["types"]["DLL"] = 1
        self.assertTrue(mzz.validate(d))
        self.assertFalse(mzz.validate(dict(d, raw_path="C:\\Secret")))
        self.assertFalse(mzz.validate(dict(d, runtime_installation_proven=True)))
        self.assertFalse(mzz.validate(dict(d, entries=True)))
        self.assertFalse(mzz.validate(dict(d, types=dict(d["types"], DLL=2))))
        self.assertFalse(mzz.validate(dict(d, signals=dict(d["signals"], CLR_LIKE="SECRET"))))

    def test_no_archives_and_failure_not_counted_as_install(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            directory = root / "private"
            directory.mkdir()
            reader = root / "7z.exe"
            reader.write_bytes(b"fixture")
            empty = mzz.scan(directory, reader)
            self.assertEqual(empty, mzz.empty())
            archive = directory / "private-name.mzz"
            archive.write_bytes(b"X" * 256)
            with mock.patch.object(mzz.subprocess, "run", return_value=mock.Mock(returncode=2)):
                result = mzz.scan(directory, reader)
            self.assertEqual(result["status"], "PARTIAL")
            self.assertEqual(result["mzz_found"], 1)
            self.assertEqual(result["mzz_listed"], 0)
            self.assertFalse(result["runtime_installation_proven"])
            self.assertNotIn("private-name", json.dumps(result))

    def test_symlink_cannot_escape_disposable_directory(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            directory = root / "private"
            directory.mkdir()
            reader = root / "7z.exe"
            reader.write_bytes(b"fixture")
            link = directory / "secret.mzz"
            try:
                link.symlink_to(reader)
            except (OSError, NotImplementedError):
                self.skipTest("No symlink permissions")
            with self.assertRaises(ValueError):
                mzz.scan(directory, reader)


if __name__ == "__main__":
    unittest.main()
