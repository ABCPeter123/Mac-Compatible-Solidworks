"""Synthetic original-MZZ runtime coherence, privacy and boundedness tests."""
from pathlib import Path
import json
import struct
import tempfile
import unittest
from unittest import mock

from scripts import netfx48_full_framework_staging as t
from scripts import netfx48_core_host_trial as core


def fixture(path: Path) -> tuple[Path, Path, Path]:
    root = path / "prefix" / core.FRAMEWORK
    root.mkdir(parents=True)
    private = path / "private"
    (private / "archives").mkdir(parents=True)
    (private / "archives" / "original.mzz").write_text("synthetic archive")
    sevenzip = path / "7zz"
    sevenzip.write_text("synthetic reader")
    return root, private, sevenzip


def listing(*names: str) -> bytes:
    return ("7-Zip\n----------\n" +
            "".join("Path = " + name + "\n" for name in names)).encode()


class CoherentRuntimeTests(unittest.TestCase):
    def test_case_preserving_matches_and_private_source_names(self):
        with tempfile.TemporaryDirectory() as td:
            root, private, reader = fixture(Path(td))
            (root / "System.Core.dll").write_bytes(b"old")
            (root / "clr.dll").write_bytes(b"old")
            (root / "unrelated.dll").write_bytes(b"old")
            listing_data = listing("System_Core_dll_amd64", "clr_dll_amd64",
                                   "unrelated_dll_x86")
            def fake(argv, **kwargs):
                kwargs["stdout"].write(listing_data)
                return mock.Mock(returncode=0)
            with mock.patch.object(t.subprocess, "run", side_effect=fake):
                matches = t.matching(root, private, reader)
            self.assertEqual(matches, {
                "system.core.dll": "System.Core.dll",
                "clr.dll": "clr.dll",
            })
            self.assertNotIn("System_Core", json.dumps(t.blank()))
            self.assertTrue(t.valid(t.blank()))

    def test_batched_staging_with_previous_authenticated_files(self):
        with tempfile.TemporaryDirectory() as td:
            root, private, reader = fixture(Path(td))
            for i in range(19):
                (root / ("System" + str(i) + ".dll")).write_bytes(b"old")
            (private / "system0.dll").write_bytes(b"previous verified member")
            matches = {"system" + str(i) + ".dll": "System" + str(i) + ".dll"
                       for i in range(19)}
            requested = []
            def staged(private_dir, sevenzip, names):
                requested.extend(names)
                for name in names:
                    (private_dir / name).write_bytes(b"synthetic source")
                return {"status": "STAGED", "staged": len(names)}
            with mock.patch.object(t, "matching", return_value=matches), \
                 mock.patch.object(t, "stage", side_effect=staged), \
                 mock.patch.object(t, "valid_batch", return_value=True):
                result, mapping = t.stage_matching(root, private, reader)
            self.assertEqual(result["status"], "STAGED")
            self.assertEqual(result["candidates"], 19)
            self.assertEqual(result["additional"], 18)
            self.assertEqual(result["staged"], 18)
            self.assertEqual(len(requested), 18)
            self.assertEqual(len(mapping), 19)
            self.assertTrue(t.valid(result))
            self.assertNotIn("System", json.dumps(result))

    def test_bounded_and_partial_are_not_success(self):
        with tempfile.TemporaryDirectory() as td:
            root, private, reader = fixture(Path(td))
            with mock.patch.object(t, "matching", return_value=None):
                report, names = t.stage_matching(root, private, reader)
            self.assertEqual(report["status"], "BOUNDED")
            self.assertEqual(names, {})
            with mock.patch.object(t, "matching", return_value={"system.dll": "System.dll"}), \
                 mock.patch.object(t, "stage", return_value={"staged": 0}), \
                 mock.patch.object(t, "valid_batch", return_value=True):
                report, names = t.stage_matching(root, private, reader)
            self.assertEqual(report["status"], "INCOMPLETE")
            self.assertEqual(report["staged"], 0)
            self.assertTrue(t.valid(report))
            self.assertFalse(t.valid(dict(report, framework48_installed=True)))
            self.assertFalse(t.valid(dict(report, path="Z:\\private")))

    def test_reject_symlink_source_and_alias_collision(self):
        with tempfile.TemporaryDirectory() as td:
            root, private, reader = fixture(Path(td))
            (root / "System.dll").write_bytes(b"old")
            (root / "system.dll").write_bytes(b"old")
            if len(list(root.iterdir())) == 1:
                self.skipTest("Host filesystem is case-insensitive")
            data = listing("system_dll_amd64")
            def fake(argv, **kwargs):
                kwargs["stdout"].write(data)
                return mock.Mock(returncode=0)
            with mock.patch.object(t.subprocess, "run", side_effect=fake):
                self.assertIsNone(t.matching(root, private, reader))
            (root / "system.dll").unlink()
            (root / "System.dll").unlink()
            (root / "System.dll").symlink_to(private / "archives" / "original.mzz")
            with mock.patch.object(t.subprocess, "run", side_effect=fake):
                self.assertIsNone(t.matching(root, private, reader))

    def test_reversible_framework_handles_existing_mixed_case(self):
        # The original .NET Framework has System.dll and System.Core.dll,
        # while MZZ extraction normalizes archive names to lowercase.
        with tempfile.TemporaryDirectory() as td:
            root, private, reader = fixture(Path(td))
            (root / "System.Core.dll").write_bytes(b"original 4.0")
            source = private / "system.core.dll"
            data = bytearray(8192)
            data[:2] = b"MZ"
            struct.pack_into("<I", data, 0x3c, 0x80)
            data[0x80:0x84] = b"PE\x00\x00"
            struct.pack_into("<H", data, 0x84, 0x8664)
            struct.pack_into("<H", data, 0x94, 240)
            struct.pack_into("<H", data, 0x98, 0x20b)
            source.write_bytes(data)
            before = (root / "System.Core.dll").read_bytes()
            swap = core.ReversibleFramework(root, private)
            swap.replace(source, "System.Core.dll")
            self.assertEqual((root / "System.Core.dll").read_bytes(), bytes(data))
            swap.restore()
            self.assertEqual((root / "System.Core.dll").read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
