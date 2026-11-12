import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

from scripts.installer_media_preflight import analyze_pe, inventory


def synthetic_pe(path, *, machine=0x8664,
                 imported=("KERNEL32.dll", "OLE32.dll", "CUSTOM-SENSITIVE.dll")):
    """Generate PE import metadata for tests. This is not an executable installer."""
    data = bytearray(2048)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\x00\x00"
    struct.pack_into("<H", data, 0x84, machine)
    struct.pack_into("<H", data, 0x86, 1)
    struct.pack_into("<H", data, 0x94, 240)
    struct.pack_into("<H", data, 0x98, 0x20B)
    struct.pack_into("<I", data, 0x98 + 108, 16)
    struct.pack_into("<II", data, 0x98 + 112 + 8,
                     0x1000, (len(imported) + 1) * 20)
    section = 0x98 + 240
    struct.pack_into("<IIII", data, section + 8, 0x400, 0x1000, 0x400, 0x400)
    for index, name in enumerate(imported):
        name_rva = 0x1000 + 0x150 + index * 40
        struct.pack_into("<I", data, 0x400 + index * 20 + 12, name_rva)
        pos = 0x400 + 0x150 + index * 40
        data[pos:pos + len(name)] = name.encode("ascii")
    path.write_bytes(data)


class InstallerMediaPreflightTests(unittest.TestCase):
    def test_pe_architecture_and_import_families_redacted(self):
        with tempfile.TemporaryDirectory() as temp:
            file = Path(temp) / "setup.exe"
            synthetic_pe(file)
            result = analyze_pe(file)
            self.assertEqual(result["format"], "pe")
            self.assertEqual(result["architecture"], "x64")
            self.assertEqual(result["api_families"],
                             ["base_windows_api", "com_automation"])
            self.assertEqual(result["other_imported_dll_count"], 1)
            self.assertNotIn("CUSTOM-SENSITIVE", json.dumps(result))
            synthetic_pe(file, machine=0x14C)
            self.assertEqual(analyze_pe(file)["architecture"], "x86")

    def test_identifies_published_files_but_not_unknown_user_files(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "media"
            root.mkdir()
            synthetic_pe(root / "setup.exe")
            (root / "vc_redist.x64.exe").write_bytes(b"test")
            (root / "Private Name Serial 123.dll").write_bytes(b"secret")
            result = inventory(root)
            self.assertTrue(result["entrypoints"]["root_setup_observed"])
            self.assertTrue(result["package_indicators"]["vcredist_x64"]["observed"])
            self.assertFalse(result["package_indicators"]["vcredist_x86"]["observed"])
            self.assertNotIn(str(root), json.dumps(result))
            self.assertNotIn("Private Name", json.dumps(result))
            self.assertEqual(result["files_examined"], 3)

    def test_single_bootstrapper_distinct_from_full_media(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "SolidworksSetup.exe"
            synthetic_pe(path)
            result = inventory(path)
            self.assertEqual(result["input_kind"], "single_file")
            self.assertTrue(result["entrypoints"]["bootstrapper_observed"])
            self.assertFalse(result["entrypoints"]["root_setup_observed"])

    def test_scan_limit_explicitly_indicates_incomplete(self):
        with tempfile.TemporaryDirectory() as temp:
            for index in range(5):
                (Path(temp) / f"part{index}.cab").write_bytes(b"x")
            result = inventory(Path(temp), max_files=2)
            self.assertEqual(result["files_examined"], 2)
            self.assertTrue(result["scan_incomplete"])

    def test_symlinks_ignored(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "media"
            root.mkdir()
            (Path(temp) / "vc_redist.x64.exe").write_bytes(b"x")
            try:
                (root / "vc_redist.x64.exe").symlink_to(
                    Path(temp) / "vc_redist.x64.exe")
            except (OSError, NotImplementedError):
                self.skipTest("Symlink creation unavailable on this runner")
            result = inventory(root)
            self.assertFalse(result["package_indicators"]["vcredist_x64"]["observed"])
            self.assertEqual(result["symlinks_skipped"], 1)

    def test_refuses_to_write_report_into_media(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "media"
            root.mkdir()
            output = root / "report.json"
            command = [sys.executable, "-m", "scripts.installer_media_preflight",
                       "--media", str(root), "--output", str(output)]
            completed = subprocess.run(command, capture_output=True, text=True)
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("outside", completed.stderr)
            self.assertFalse(output.exists())

    def test_malformed_pe_gracefully_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            file = Path(temp) / "setup.exe"
            file.write_bytes(b"MZ" + b"\x00" * 20)
            self.assertEqual(analyze_pe(file)["format"], "not_pe")
            file.write_bytes(b"MZ" + b"\x00" * 62)
            self.assertEqual(analyze_pe(file)["format"], "unrecognized_pe")

    def test_reject_zero_file_limit(self):
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaises(ValueError):
                inventory(Path(temp), max_files=0)


if __name__ == "__main__":
    unittest.main()
