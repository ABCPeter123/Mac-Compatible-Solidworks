"""Synthetic signed-MZZ dependency staging tests. No vendor binaries or paths."""
from __future__ import annotations

import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest import mock

from scripts import netfx48_signed_mzz_dependency_staging as stage
from scripts import netfx48_isolated_loader_trial as trial


def synthetic_amd64() -> bytes:
    raw = bytearray(1024)
    raw[:2] = b"MZ"
    struct.pack_into("<I", raw, 0x3c, 0x80)
    raw[0x80:0x84] = b"PE\x00\x00"
    struct.pack_into("<H", raw, 0x84, 0x8664)
    struct.pack_into("<H", raw, 0x94, 0xF0)
    struct.pack_into("<H", raw, 0x98, 0x20B)
    return bytes(raw)


class OriginalMzzDependencyStage(unittest.TestCase):
    def test_only_bounded_original_member_variants(self):
        self.assertIn("vcruntime140_dll_amd64",
                      stage.candidates("vcruntime140.dll"))
        self.assertIn("vcruntime140.dll", stage.candidates("vcruntime140.dll"))
        self.assertEqual(stage.candidates("private.dll"), stage.candidates("private.dll"))
        for unsafe in ("../file.dll", "C:/Windows/f.dll", "some.dll\x00", "FOO.DLL",
                       "nosuffix", "name with spaces.dll"):
            with self.subTest(unsafe=unsafe):
                with self.assertRaises(ValueError):
                    stage.candidates(unsafe)

    def test_dotted_framework_assembly_resolves_real_mzz_amd64_names(self):
        variants = stage.candidates("system.core.dll")
        self.assertIn("system_core_amd64.dll", variants)
        self.assertIn("system_core_dll_amd64", variants)
        self.assertLess(variants.index("system_core_amd64.dll"),
                        variants.index("system.core.dll"))
        self.assertEqual(len(variants), len(set(variants)))
        self.assertIn("system_xaml_amd64.dll",
                      stage.candidates("system.xaml.dll"))

    def test_private_7zip_listing_never_leaks_member_names(self):
        raw = (b"Path = C:\\private\\sensitive-file.mzz\n"
               b"Type = 7z\n----------\n"
               b"Path = Folder\\vcruntime140_dll_amd64\n"
               b"Path = secret-microsoft-name.dll\n")
        parsed = stage.mzz_members(raw)
        self.assertIn("vcruntime140_dll_amd64", parsed)
        self.assertNotIn("C:\\private\\sensitive-file.mzz", json.dumps(stage.blank()))
        self.assertEqual(stage.mzz_members(b"Path = SECRET\n"), {})
        self.assertEqual(stage.mzz_members(b"\x00"), {})
        self.assertEqual(stage.mzz_members(b"x" * (stage.MAX_LIST + 1)), {})

    def test_strict_report_schema_prevents_original_data(self):
        d = stage.blank()
        self.assertTrue(stage.valid(d))
        self.assertFalse(stage.valid(dict(d, original_path="secret")))
        self.assertFalse(stage.valid(dict(d, original_runtime_installed=True)))
        self.assertFalse(stage.valid(dict(d, located=True)))
        self.assertFalse(stage.valid(dict(d, status="STAGED")))
        self.assertFalse(stage.valid(dict(d, status="MYSTERY")))
        self.assertFalse(stage.valid(dict(d, families=dict(d["families"], SECRET={}))))
        report = trial.blank()
        self.assertTrue(trial.valid(report))
        self.assertFalse(trial.valid(dict(report, signed_mzz_staging=dict(d, private_file="secret"))))

    def test_stages_only_matching_real_x64_pe_and_never_installs(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            private = root / "private"
            archives = private / "archives"
            archives.mkdir(parents=True)
            archive = archives / "original.mzz"
            archive.write_bytes(b"synthetic")
            reader = root / "7z.exe"
            reader.write_bytes(b"synthetic")
            def invoke(argv, **kwargs):
                if "l" in argv:
                    kwargs["stdout"].write(
                        b"----------\nPath = vcruntime140_dll_amd64\n"
                        b"Path = harmless-opaque-original-member\n")
                else:
                    self.assertIn("vcruntime140_dll_amd64", argv)
                    kwargs["stdout"].write(synthetic_amd64())
                return mock.Mock(returncode=0)
            with mock.patch.object(stage.subprocess, "run", side_effect=invoke):
                report = stage.stage(private, reader,
                                     ["vcruntime140.dll", "secret-missing.dll"])
            self.assertTrue(stage.valid(report))
            self.assertEqual(report["status"], "STAGED")
            self.assertEqual(report["missing_requested"], 2)
            self.assertEqual(report["located"], 1)
            self.assertEqual(report["staged"], 1)
            self.assertEqual(report["families"]["VCRUNTIME"]["staged"], 1)
            self.assertEqual(report["families"]["OTHER"]["staged"], 0)
            self.assertEqual((private / "vcruntime140.dll").read_bytes(), synthetic_amd64())
            self.assertFalse((private / "secret-missing.dll").exists())
            for forbidden in ("vcruntime140.dll", "secret-missing.dll", str(private),
                              "harmless-opaque-original-member"):
                self.assertNotIn(forbidden, json.dumps(report))
            self.assertFalse(report["original_runtime_installed"])

    def test_no_matching_mzz_cannot_claim_staged_or_loader_ready(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            private = root / "private"
            (private / "archives").mkdir(parents=True)
            (private / "archives" / "original.mzz").write_bytes(b"synthetic")
            reader = root / "7z.exe"
            reader.write_bytes(b"fixture")
            def fake(argv, **kwargs):
                kwargs["stdout"].write(b"----------\nPath = no-matching-file\n")
                return mock.Mock(returncode=0)
            with mock.patch.object(stage.subprocess, "run", side_effect=fake):
                r = stage.stage(private, reader, ["vcruntime140.dll"])
            self.assertTrue(stage.valid(r))
            self.assertEqual(r["status"], "NO_MZZ_MATCH")
            self.assertEqual(r["located"], 0)
            self.assertEqual(r["staged"], 0)


if __name__ == "__main__":
    unittest.main()
