"""Safe and synthetic original .NET CLR PE proof tests, no vendor binaries."""
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest import mock
from scripts import netfx4x_mzz_pe_evidence as p


def pe_header(machine: int, magic: int) -> bytes:
    header = bytearray(1024)
    header[0:2] = b"MZ"
    struct.pack_into("<I", header, 0x3c, 0x80)
    header[0x80:0x84] = b"PE\x00\x00"
    struct.pack_into("<H", header, 0x84, machine)
    struct.pack_into("<H", header, 0x80 + 20, 0xF0)
    struct.pack_into("<H", header, 0x80 + 24, magic)
    return bytes(header)


class OriginalPeTests(unittest.TestCase):
    def test_only_whitelisted_members_classified(self):
        raw = (
            b"Path = C:\\Users\\secret\\vendor\n"
            b"----------\n"
            b"Path = clr_amd64.dll\n"
            b"Path = mscorlib_amd64.dll\n"
            b"Path = secret.dll\n"
            b"Path = PresentationNative_v0400_amd64.dll\n")
        self.assertEqual(p.matching_names(raw), set(p.TARGETS.values()))
        self.assertFalse(p.matching_names(b"Path = clr_amd64.dll\n"))
        self.assertEqual(p.matching_names(b"----------\nPath = secret.dll\n"), set())
        self.assertNotIn("secret", json.dumps(p.empty()))

    def test_honest_pe_classifier_and_absence(self):
        self.assertTrue(p.validate(p.empty()))
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            private = root / "mzz"
            private.mkdir()
            seven = root / "7z.exe"
            seven.write_bytes(b"fixture")
            self.assertEqual(p.scan(private, seven), p.empty())
            source = private / "original.mzz"
            source.write_bytes(b"fixture")
            list_bytes = (
                b"----------\nPath = clr_amd64.dll\n"
                b"Path = mscorlib_amd64.dll\n")
            def fake_run(argv, **kwargs):
                if "l" in argv:
                    kwargs["stdout"].write(list_bytes)
                else:
                    kwargs["stdout"].write(pe_header(0x8664, 0x20b))
                return mock.Mock(returncode=0)
            with mock.patch.object(p.subprocess, "run", side_effect=fake_run):
                report = p.scan(private, seven)
            self.assertEqual(report["status"], "MEASURED")
            self.assertEqual(report["members"]["CLR_AMD64"], "PE_AMD64")
            self.assertEqual(report["members"]["MSCORLIB_AMD64"], "PE_AMD64")
            self.assertEqual(report["members"]["WPF_NATIVE_AMD64"], "NOT_FOUND")
            self.assertFalse(report["executed_original_code"])
            self.assertTrue(p.validate(report))
            self.assertFalse(p.validate(dict(report, private_path="secret")))
            self.assertFalse(p.validate(dict(report, executed_original_code=True)))

    def test_failed_extraction_is_never_counted_as_pe(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            private = root / "mzz"
            private.mkdir()
            (private / "only.mzz").write_bytes(b"test")
            seven = root / "7z.exe"
            seven.write_bytes(b"fixture")
            def fake_run(argv, **kwargs):
                if "l" in argv:
                    kwargs["stdout"].write(b"----------\nPath = clr_amd64.dll\n")
                    return mock.Mock(returncode=0)
                return mock.Mock(returncode=2)
            with mock.patch.object(p.subprocess, "run", side_effect=fake_run):
                report = p.scan(private, seven)
            self.assertEqual(report["status"], "PARTIAL")
            self.assertEqual(report["members"]["CLR_AMD64"], "EXTRACT_FAILED")
            self.assertFalse(report["executed_original_code"])


if __name__ == "__main__":
    unittest.main()
