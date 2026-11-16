"""Guard Windows version data and avoid leaking vendor or machine details."""
import unittest
from scripts.netfx481_version_gate import decode, verify


class NativeVersionGateTests(unittest.TestCase):
    def test_valid_comparison(self):
        result = decode(b"SWCOMPAT_OS_SCHEMA=1\n"
                        b"SWCOMPAT_OS_WINAPI=BELOW_WIN10\n"
                        b"SWCOMPAT_OS_NTDLL=WIN10_SUPPORTED\n"
                        b"SWCOMPAT_OS_REGISTRY=WIN10_SUPPORTED\n"
                        b"SWCOMPAT_OS_ARCH=AMD64\n"
                        b"SWCOMPAT_OS_SP_API=MISSING_SP1\n"
                        b"SWCOMPAT_OS_SP_NTDLL=SP1_OR_LATER\n", 0)
        self.assertTrue(verify(result))
        self.assertEqual(result["ntdll"], "WIN10_SUPPORTED")
        self.assertEqual(result["sp_api"], "MISSING_SP1")
        self.assertEqual(result["sp_ntdll"], "SP1_OR_LATER")

    def test_no_leak_reject_duplicate_unknown_or_nonzero(self):
        valid = (b"SWCOMPAT_OS_SCHEMA=1\nSWCOMPAT_OS_WINAPI=WIN10_SUPPORTED\n"
                 b"SWCOMPAT_OS_NTDLL=WIN10_SUPPORTED\n"
                 b"SWCOMPAT_OS_REGISTRY=WIN10_SUPPORTED\nSWCOMPAT_OS_ARCH=AMD64\n"
                 b"SWCOMPAT_OS_SP_API=NOT_WIN7\nSWCOMPAT_OS_SP_NTDLL=NOT_WIN7\n")
        for sample, rc in (
            (valid, 1), (valid + b"SWCOMPAT_OS_WINAPI=WIN10_SUPPORTED\n", 0),
            (valid + b"SWCOMPAT_OS_PATH=SECRET\n", 0),
            (valid.replace(b"WIN10_SUPPORTED", b"BAD_VERSION"), 0),
            (valid.replace(b"SP_API=NOT_WIN7", b"SP_API=FAKE_SP"), 0),
            (valid.replace(b"SP_NTDLL=NOT_WIN7\n", b""), 0),
            (valid + b"\x00", 0), (b"trash" * 500, 0)):
            with self.subTest(rc=rc, raw=sample[:30]):
                self.assertEqual(decode(sample, rc)["status"], "INVALID")
        self.assertFalse(verify(dict(decode(valid, 0), installer_path="SECRET")))

if __name__ == "__main__":
    unittest.main()
