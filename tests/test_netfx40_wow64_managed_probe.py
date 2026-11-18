"""Original .NET x86 managed proof must reject x64/Wine Mono and malformed PE."""
from pathlib import Path
import struct
from tempfile import TemporaryDirectory
from unittest import TestCase, mock

from scripts import netfx40_wow64_managed_probe as x86


def image(machine=0x14c, cli=True) -> bytes:
    data = bytearray(8192)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3c, 0x80)
    data[0x80:0x84] = b"PE\x00\x00"
    struct.pack_into("<H", data, 0x84, machine)
    struct.pack_into("<H", data, 0x98, 0x10b)
    struct.pack_into("<I", data, 0x98 + 92, 16 if cli else 0)
    if cli:
        struct.pack_into("<II", data, 0x98 + 96 + 14*8, 0x2000, 0x48)
    return bytes(data)


class NativeWow64ManagedTests(TestCase):
    def test_x86_cli_architecture_only(self):
        with TemporaryDirectory() as td:
            fixture = Path(td) / x86.FIXTURE_NAME
            for machine, cli, expected in (
                (0x14c, True, True),
                (0x8664, True, False),
                (0x14c, False, False),
                (0xaa64, True, False),
            ):
                with self.subTest(machine=machine, cli=cli):
                    fixture.write_bytes(image(machine, cli))
                    self.assertEqual(x86.is_original_x86_cli_image(fixture), expected)
            fixture.write_bytes(b"not a real PE" * 600)
            self.assertFalse(x86.is_original_x86_cli_image(fixture))
            target = Path(td) / "outside.exe"
            target.write_bytes(image())
            fixture.unlink()
            fixture.symlink_to(target)
            self.assertFalse(x86.is_original_x86_cli_image(fixture))

    def test_native_only_x86_managed_pass_and_mono_rejection(self):
        with TemporaryDirectory() as td:
            root = Path(td)
            prefix = root / "prefix"
            prefix.mkdir()
            wine = root / "wine"
            wine.write_bytes(b"wine")
            fixture = root / x86.FIXTURE_NAME
            fixture.write_bytes(image())
            with (mock.patch.object(x86, "validate_prefix"),
                  mock.patch.object(x86, "probe", return_value={
                      "clr_family": "MICROSOFT_CLR_CANDIDATE",
                      "managed": "PASS",
                  }) as executed):
                result = x86.inspect(wine, prefix, fixture)
            self.assertEqual(result["status"], "MANAGED_X86_PASS")
            self.assertTrue(x86.valid(result))
            self.assertEqual(executed.call_args.kwargs["override"], "native_only")
            for family, managed in (("MONO", "PASS"),
                                    ("MICROSOFT_CLR_CANDIDATE", "FAIL"),
                                    ("NOT_VERIFIED", "NOT_VERIFIED")):
                with (mock.patch.object(x86, "validate_prefix"),
                      mock.patch.object(x86, "probe", return_value={
                          "clr_family": family, "managed": managed,
                      })):
                    result = x86.inspect(wine, prefix, fixture)
                self.assertEqual(result["status"], "MANAGED_X86_FAIL")
                self.assertTrue(x86.valid(result))

    def test_strict_fail_closed_report(self):
        self.assertTrue(x86.valid(x86.blank()))
        valid = {"status": "MANAGED_X86_PASS",
                 "family": "MICROSOFT_CLR_CANDIDATE", "managed": "PASS"}
        self.assertTrue(x86.valid(valid))
        self.assertFalse(x86.valid({**valid, "path": "secret"}))
        self.assertFalse(x86.valid({**valid, "status": "MANAGED_X86_FAIL"}))
        self.assertFalse(x86.valid({**valid, "status": []}))
        self.assertFalse(x86.valid({**valid, "family": "MONO"}))
        self.assertFalse(x86.valid({**x86.blank(), "managed": "PASS"}))
