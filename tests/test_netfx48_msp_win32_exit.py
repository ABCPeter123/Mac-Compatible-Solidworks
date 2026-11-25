"""Original signed x64 MSP Win32 DWORD capture. Synthetic packets only."""
from pathlib import Path
from unittest import TestCase

from scripts import netfx48_msp_win32_exit as win32

ROOT = Path(__file__).resolve().parents[1]


def packet(status="EXIT", code="00000643"):
    return (
        f"SWCOMPAT_MSP_WIN32_SCHEMA=1\n"
        f"SWCOMPAT_MSP_WIN32_STATUS={status}\n"
        f"SWCOMPAT_MSP_WIN32_EXIT_HEX={code}\n"
    ).encode("ascii")


class NativeOriginalMSPPacketTests(TestCase):
    def test_real_win32_1603_is_different_from_host_low_byte_67(self):
        r = win32.parse(packet(), "SUCCESS")
        self.assertTrue(win32.valid(r))
        self.assertEqual(r["exit_hex"], "00000643")
        self.assertEqual(r["category"], "MSI_FATAL_ERROR")
        self.assertEqual(win32.patch_status(r), "EXIT_NONZERO")
        self.assertEqual(1603 % 256, 67)
        self.assertNotEqual(1603, 67)
        for code, expected in (
            ("0000066A", "PATCH_TARGET_NOT_FOUND"),
            ("00000643", "MSI_FATAL_ERROR"),
            ("00000645", "UNKNOWN_PRODUCT"),
            ("00000663", "PATCH_PACKAGE_OPEN_FAILED"),
            ("80070424", "OTHER_WIN32_ERROR"),
        ):
            with self.subTest(code=code):
                r = win32.parse(packet(code=code), "SUCCESS")
                self.assertEqual(r["category"], expected)
                self.assertTrue(win32.valid(r))
                self.assertEqual(win32.patch_status(r), "EXIT_NONZERO")

    def test_only_explicit_native_win32_zero_can_satisfy_patch(self):
        good = win32.parse(packet(code="00000000"), "SUCCESS")
        self.assertEqual(good["category"], "SUCCESS")
        self.assertEqual(win32.patch_status(good), "SUCCESS")
        self.assertFalse(win32.valid({**good, "category": "MSI_FATAL_ERROR"}))
        self.assertEqual(win32.patch_status(win32.blank("BAD_REPORT")),
                         "EXIT_NONZERO")

    def test_native_startup_selftest_cannot_fabricate_success(self):
        self.assertEqual(
            win32.parse(packet(status="SELFTEST"), "SUCCESS",
                        selftest=True)["status"], "SELFTEST_PASS")
        self.assertEqual(
            win32.parse(packet(), "SUCCESS", selftest=True)["status"],
            "BAD_REPORT")
        self.assertEqual(
            win32.parse(packet(status="SELFTEST"), "EXIT_NONZERO",
                        selftest=True)["status"], "BAD_REPORT")
        self.assertEqual(
            win32.parse(packet(status="WAIT_FAILED", code="FFFFFFFF"),
                        "EXIT_NONZERO")["status"], "WAIT_FAILED")

    def test_bad_or_private_process_packets_fail_closed_without_leak(self):
        bad = (
            b"MSI (s) original user path C:\\private\\product\n",
            packet() + b"PRIVATE_PATH=C:\\private\\user\n",
            packet().replace(b"SCHEMA=1", b"SCHEMA=2"),
            packet().replace(b"STATUS=EXIT", b"STATUS=PRIVATE"),
            packet().replace(b"00000643", b"0000064g"),
            packet() + packet(),
            packet() + b"\x00",
            b"x" * (win32.MAX_BYTES + 1),
            b"",
        )
        for data in bad:
            with self.subTest(data=data[:10]):
                result = win32.parse(data, "SUCCESS")
                self.assertEqual(result["status"], "BAD_REPORT")
                self.assertTrue(win32.valid(result))
                self.assertNotIn("private", str(result).lower())
        self.assertFalse(win32.valid({**win32.blank(), "exit_hex": "C:\\PII"}))
        self.assertFalse(win32.valid({**win32.blank(), "status": "EXIT_CAPTURED"}))
        self.assertFalse(win32.valid({**win32.blank(), "private_code": 1603}))

    def test_compiled_native_probe_pins_exact_original_msp_and_does_not_log(self):
        native = (ROOT / "probes/netfx48_msp_win32_status.c").read_text()
        self.assertIn(r"netfx_Patch_x64.msp", native)
        self.assertIn("CreateProcessW(", native)
        self.assertIn("GetExitCodeProcess(", native)
        self.assertIn("WaitForSingleObject(", native)
        self.assertIn("INFINITE", native)
        self.assertIn("--selftest-1603", native)
        self.assertIn("--apply-original-msp", native)
        self.assertIn("--selftest-msi-registration", native)
        self.assertIn("probe_registration(stderr)", native)
        self.assertIn("MSIDBOPEN_READONLY", native)
        self.assertIn("MsiQueryProductStateW(", native)
        self.assertIn("MsiDeterminePatchSequenceW(", native)
        self.assertIn("MSIPATCH_DATATYPE_PATCHFILE", native)
        self.assertIn("MSIINSTALLCONTEXT_USERUNMANAGED", native)
        self.assertIn("MSIINSTALLCONTEXT_MACHINE", native)
        self.assertIn("SWCOMPAT_MSI_SEQ_USER=%s", native)
        self.assertIn("SWCOMPAT_MSI_SEQ_MACHINE=%s", native)
        self.assertIn("--selftest-msi-sequence", native)
        self.assertIn("probe_registration(stderr)", native)
        self.assertNotIn("MsiApplyMultiplePatches", native)
        self.assertNotIn("MsiApplyPatchW(", native)
        self.assertIn("MsiGetProductInfoW(", native)
        self.assertIn("SWCOMPAT_MSI_REG_PRODUCT=%s", native)
        self.assertNotIn("MsiApplyPatchW(", native)
        self.assertNotIn("MsiConfigureProduct", native)
        self.assertNotIn("RegSetValue", native)
        self.assertIn('EXTUI=1 /L*v', native)
        self.assertNotIn("REINSTALLMODE", native)
        self.assertNotIn("MsiApplyPatch", native)
        self.assertNotIn("CreateServiceW", native)
        self.assertNotIn("printf(\"%ls", native)
