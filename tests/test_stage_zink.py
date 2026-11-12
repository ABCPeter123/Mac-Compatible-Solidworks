import hashlib
from pathlib import Path
import struct
import tempfile
import unittest

from scripts.stage_zink import AMD64, pe_machine, select_dlls, stage


def fake_pe(path, machine):
    content = bytearray(128)
    content[:2] = b"MZ"
    struct.pack_into("<I", content, 0x3C, 64)
    content[64:68] = bytes([80, 69, 0, 0])
    struct.pack_into("<H", content, 68, machine)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)


class StagingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "archive"
        self.dest = self.root / "windows" / "system32"
        self.dest.mkdir(parents=True)

    def test_machine_header(self):
        x64 = self.source / "x64/opengl32.dll"
        x86 = self.source / "x86/opengl32.dll"
        fake_pe(x64, AMD64)
        fake_pe(x86, 0x14C)
        self.assertEqual(pe_machine(x64), AMD64)
        self.assertEqual(pe_machine(x86), 0x14C)
        self.assertIsNone(pe_machine(self.dest / "missing.dll"))

    def test_stages_only_x64_dlls(self):
        for machine, arch in [(0x14C, "x86"), (AMD64, "x64")]:
            for name in ("opengl32.dll", "libgallium_wgl.dll", "libglapi.dll"):
                fake_pe(self.source / arch / name, machine)
        selected = select_dlls(self.source)
        self.assertEqual(len(selected), 3)
        self.assertTrue(all("x64" in path.parts for path in selected.values()))
        result = stage(self.source, self.dest)
        self.assertEqual(len(result["dlls"]), 3)
        self.assertTrue(all((self.dest / item["name"]).exists() for item in result["dlls"]))
        for item in result["dlls"]:
            self.assertEqual(item["sha256"], hashlib.sha256(
                (self.dest / item["name"]).read_bytes()).hexdigest())

    def test_reject_missing_required_dll(self):
        fake_pe(self.source / "x64/opengl32.dll", AMD64)
        with self.assertRaisesRegex(ValueError, "Missing x64"):
            select_dlls(self.source)

    def test_staging_requires_explicit_existing_directory(self):
        for name in ("opengl32.dll", "libgallium_wgl.dll"):
            fake_pe(self.source / "x64" / name, AMD64)
        with self.assertRaises(ValueError):
            stage(self.source, self.root / "does_not_exist")


if __name__ == "__main__":
    unittest.main()
