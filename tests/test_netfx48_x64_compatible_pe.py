"""Only x64-native or proven PE32 AnyCPU signed framework images are eligible."""
import struct
import unittest

from scripts.netfx48_x64_compatible_pe import compatible_x64


def image(*, machine=0x14c, cli=True, flags=1, magic=0x10b):
    data = bytearray(4096)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3c, 0x80)
    data[0x80:0x84] = b"PE\x00\x00"
    struct.pack_into("<H", data, 0x84, machine)
    struct.pack_into("<H", data, 0x86, 1)
    optsz = 240 if magic == 0x20b else 224
    struct.pack_into("<H", data, 0x94, optsz)
    struct.pack_into("<H", data, 0x98, magic)
    opt = 0x98
    struct.pack_into("<I", data, opt + (108 if magic == 0x20b else 92), 16)
    section = opt + optsz
    struct.pack_into("<IIII", data, section + 8, 0x200, 0x1000, 0x200, 0x400)
    if cli:
        entry = opt + (112 if magic == 0x20b else 96) + 14 * 8
        struct.pack_into("<II", data, entry, 0x1000, 0x48)
        struct.pack_into("<I", data, 0x400, 0x48)
        struct.pack_into("<I", data, 0x410, flags)
    return bytes(data)


class OriginalAnyCpuTests(unittest.TestCase):
    def test_native_amd64_accepted_independent_of_anycpu_flag(self):
        self.assertTrue(compatible_x64(image(
            machine=0x8664, magic=0x20b)))
        self.assertTrue(compatible_x64(image(
            machine=0x8664, magic=0x20b), allow_anycpu=True))

    def test_genuine_managed_anycpu_requires_opt_in(self):
        original = image()
        self.assertFalse(compatible_x64(original))
        self.assertTrue(compatible_x64(original, allow_anycpu=True))

    def test_reject_native_x86_and_32bit_required_or_preferred(self):
        for data in (
            image(cli=False),
            image(flags=0),
            image(flags=0x3),
            image(flags=0x20001),
            image(flags=0x20002),
            image(flags=0xffffffff),
            b"MZ" + b"\0" * 200,
            b"not a PE",
        ):
            with self.subTest(first_bytes=data[:3]):
                self.assertFalse(compatible_x64(data, allow_anycpu=True))

    def test_reject_corrupt_cli_and_unsupported_section_metadata(self):
        bad = bytearray(image())
        struct.pack_into("<II", bad, 0x98 + 96 + 14 * 8, 0x40000000, 0x48)
        self.assertFalse(compatible_x64(bytes(bad), allow_anycpu=True))
        bad = bytearray(image())
        struct.pack_into("<I", bad, 0x400, 8)
        self.assertFalse(compatible_x64(bytes(bad), allow_anycpu=True))
        bad = bytearray(image())
        struct.pack_into("<I", bad, 0x98 + 92, 0)
        self.assertFalse(compatible_x64(bytes(bad), allow_anycpu=True))


if __name__ == "__main__":
    unittest.main()
