"""Synthetic import tables only. No Microsoft or SOLIDWORKS binaries."""
from __future__ import annotations
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest import mock

from scripts import netfx4x_mzz_import_evidence as evidence


def fixture(imports=("kernel32.dll", "mscoree.dll", "completelyprivate.dll"),
            delayed=("ole32.dll",), clr=True) -> bytes:
    """Build a self-contained synthetic PE32+ with direct/delay descriptors."""
    data = bytearray(0x2000)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3c, 0x80)
    data[0x80:0x84] = b"PE\x00\x00"
    struct.pack_into("<H", data, 0x84, 0x8664)
    struct.pack_into("<H", data, 0x86, 1)
    struct.pack_into("<H", data, 0x94, 240)
    opt = 0x98
    struct.pack_into("<H", data, opt, 0x20B)
    struct.pack_into("<I", data, opt + 60, 0x400)
    struct.pack_into("<I", data, opt + 108, 16)
    sec = opt + 240
    data[sec:sec + 8] = b".idata\x00\x00"
    struct.pack_into("<IIII", data, sec + 8, 0x1000, 0x1000, 0x1000, 0x400)
    if imports:
        assert len(imports) < 10
        struct.pack_into("<II", data, opt + 112 + 8, 0x1000, 20 * (len(imports) + 1))
        for i, name in enumerate(imports):
            struct.pack_into("<I", data, 0x400 + 20 * i + 12, 0x1400 + 100 * i)
            enc = name.encode("ascii") + b"\x00"
            data[0x800 + 100 * i:0x800 + 100 * i + len(enc)] = enc
    if delayed:
        assert len(delayed) < 4
        struct.pack_into("<II", data, opt + 112 + 13 * 8,
                         0x1100, 32 * (len(delayed) + 1))
        for i, name in enumerate(delayed):
            struct.pack_into("<II", data, 0x500 + 32 * i, 1, 0x1700 + i * 100)
            enc = name.encode("ascii") + b"\x00"
            data[0xb00 + i * 100:0xb00 + i * 100 + len(enc)] = enc
    if clr:
        struct.pack_into("<II", data, opt + 112 + 14 * 8, 0x1900, 72)
    return bytes(data)


class PeImportSafetyTests(unittest.TestCase):
    def test_direct_delay_imports_are_finite_families_only(self):
        result = evidence.parse_pe(fixture())
        self.assertEqual(result["pe"], "PE_AMD64")
        self.assertEqual(result["import_table"], "READABLE")
        self.assertEqual(result["delay_import_table"], "READABLE")
        self.assertEqual(result["import_count"], 3)
        self.assertEqual(result["delay_import_count"], 1)
        self.assertEqual(result["import_families"]["KERNEL32"], 1)
        self.assertEqual(result["import_families"]["MSCOREE"], 1)
        self.assertEqual(result["import_families"]["OTHER"], 1)
        self.assertEqual(result["delay_families"]["OLE32"], 1)
        self.assertTrue(result["cli_metadata_directory"])
        self.assertNotIn("completelyprivate", json.dumps(result))
        self.assertFalse(result["native_loader_tested"])

    def test_none_and_unsafe_pe_do_not_claim_success(self):
        result = evidence.parse_pe(fixture(imports=(), delayed=(), clr=False))
        self.assertEqual(result["pe"], "PE_AMD64")
        self.assertEqual(result["import_table"], "NONE")
        self.assertEqual(result["delay_import_table"], "NONE")
        self.assertEqual(result["import_count"], 0)
        self.assertFalse(result["cli_metadata_directory"])
        self.assertEqual(evidence.parse_pe(b"abc")["pe"], "NOT_PE")
        damaged = bytearray(fixture())
        damaged[0x400 + 12:0x400 + 16] = b"\xff\xff\xff\xff"
        self.assertEqual(evidence.parse_pe(bytes(damaged))["pe"], "INVALID_IMPORT_TABLE")

    def test_reject_unterminated_import_descriptor_and_delay_wrong_mode(self):
        broken = bytearray(fixture())
        struct.pack_into("<II", broken, 0x98 + 112 + 8, 0x1000, 20)
        self.assertEqual(evidence.parse_pe(bytes(broken))["pe"], "INVALID_IMPORT_TABLE")
        wrong = bytearray(fixture())
        struct.pack_into("<I", wrong, 0x500, 0)
        self.assertEqual(evidence.parse_pe(bytes(wrong))["delay_import_table"], "UNSUPPORTED")

    def test_family_identification_has_no_untrusted_output(self):
        self.assertEqual(evidence.family("api-ms-win-core-file-l1-2-0.dll"), "API_SET")
        self.assertEqual(evidence.family("vcruntime140_1.dll"), "VCRUNTIME")
        self.assertEqual(evidence.family("msvcp140.dll"), "MSVC_RUNTIME")
        self.assertEqual(evidence.family("Wintrust.dll"), "CRYPTO")
        self.assertEqual(evidence.family("totally-private.dll"), "OTHER")
        self.assertFalse(evidence.validate(dict(evidence.empty(), filename="secret")))
        self.assertFalse(evidence.validate(dict(evidence.empty(), genuine_dotnet48_running=True)))

    def test_no_original_archive_is_not_runtime_proof(self):
        with tempfile.TemporaryDirectory() as td:
            folder = Path(td)
            private = folder / "payload"
            private.mkdir()
            reader = folder / "7z.exe"
            reader.write_bytes(b"fake")
            self.assertEqual(evidence.scan(private, reader), evidence.empty())
            (private / "fake.mzz").write_bytes(b"fake")
            def fake_run(argv, **kwargs):
                if "l" in argv:
                    kwargs["stdout"].write(b"----------\nPath = clr_dll_amd64\n")
                else:
                    kwargs["stdout"].write(fixture())
                return mock.Mock(returncode=0)
            with mock.patch.object(evidence.subprocess, "run", side_effect=fake_run):
                result = evidence.scan(private, reader)
            self.assertEqual(result["members"]["CLR_AMD64"]["pe"], "PE_AMD64")
            self.assertEqual(result["members"]["CLR_AMD64"]["import_families"]["KERNEL32"], 1)
            self.assertEqual(result["members"]["MSCORLIB_AMD64"]["pe"], "NOT_FOUND")
            self.assertTrue(evidence.validate(result))
            self.assertFalse(result["genuine_dotnet48_running"])
            self.assertNotIn("fake.mzz", json.dumps(result))


if __name__ == "__main__":
    unittest.main()
