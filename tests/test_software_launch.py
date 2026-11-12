import os
from pathlib import Path
import struct
import tempfile
import unittest

from scripts.software_launch import DLLS, environment, validate_prefix


def create_x64_pe(path: Path, machine: int = 0x8664) -> None:
    data = bytearray(128)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 64)
    data[64:68] = bytes([80, 69, 0, 0])
    struct.pack_into("<H", data, 68, machine)
    path.write_bytes(data)


class SoftwareLauncherTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.prefix = Path(self.tmp.name) / "wine"
        self.sys32 = self.prefix / "drive_c/windows/system32"
        self.sys32.mkdir(parents=True)
        (self.prefix / "system.reg").write_text("Wine registry")

    def test_graphics_environment(self):
        env = environment(self.prefix, {"PATH": "/usr/bin", "GALLIUM_DRIVER": "zink"})
        self.assertEqual(env["PATH"], "/usr/bin")
        self.assertEqual(env["GALLIUM_DRIVER"], "llvmpipe")
        self.assertEqual(env["MESA_LOADER_DRIVER_OVERRIDE"], "llvmpipe")
        self.assertEqual(env["LIBGL_ALWAYS_SOFTWARE"], "1")
        self.assertEqual(env["WINEDLLOVERRIDES"], "opengl32,libgallium_wgl,libglapi=n,b")
        self.assertEqual(env["WINEPREFIX"], str(self.prefix))
        self.assertEqual(env["WINEARCH"], "win64")

    def test_missing_mesa_dll_rejected(self):
        create_x64_pe(self.sys32 / "opengl32.dll")
        with self.assertRaisesRegex(ValueError, "libgallium_wgl.dll"):
            validate_prefix(self.prefix)

    def test_x86_mesa_dll_rejected(self):
        for name in DLLS:
            create_x64_pe(self.sys32 / name)
        create_x64_pe(self.sys32 / "opengl32.dll", 0x14C)
        with self.assertRaisesRegex(ValueError, "opengl32.dll"):
            validate_prefix(self.prefix)

    def test_valid_x64_mesa_dlls(self):
        for name in DLLS:
            create_x64_pe(self.sys32 / name)
        self.assertEqual(validate_prefix(self.prefix), self.sys32)

    def test_uninitialized_prefix_rejected(self):
        for name in DLLS:
            create_x64_pe(self.sys32 / name)
        (self.prefix / "system.reg").unlink()
        with self.assertRaisesRegex(ValueError, "incomplete Wine prefix"):
            validate_prefix(self.prefix)


if __name__ == "__main__":
    unittest.main()
