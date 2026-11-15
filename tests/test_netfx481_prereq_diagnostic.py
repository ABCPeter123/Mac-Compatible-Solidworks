"""Synthetic regression suite for the actual Microsoft 4.8.1 setup-log taxonomy."""
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from scripts.netfx481_prereq_diagnostic import (
    classify_text, classify_file, empty, validate,
)


class OriginalPrerequisiteTests(unittest.TestCase):
    def test_unmanifested_child_os_version_is_detected_without_raw_log(self):
        private = (
            b"OS Version = 6.1.7601, SP = 1.0, Platform 2\n"
            b"error: operating system is not supported; requirements not met\n"
            b"Original private path=C:\\Secret\\Account\\vendor.bin\n"
            b"Final Result: blocked with exit code 5100\n"
        )
        report = classify_text(private)
        self.assertEqual(report["os_versions"], ["BELOW_WINDOWS_10"])
        self.assertIn("OS_VERSION_BLOCK", report["blockers"])
        self.assertTrue(report["5100_in_log"])
        self.assertTrue(validate(report))
        self.assertNotIn("Secret", str(report))
        self.assertNotIn("vendor", str(report))

    def test_modern_19045_and_22621_are_supported_but_not_installed(self):
        for version, expected in (
            ("10.0.19045", "WINDOWS_10_SUPPORTED"),
            ("10.0.22621", "WINDOWS_11_SUPPORTED"),
            ("10.0.18362", "WINDOWS_10_TOO_OLD"),
        ):
            with self.subTest(version=version):
                report = classify_text(("OS Version = " + version + "\n").encode())
                self.assertEqual(report["os_versions"], [expected])
                self.assertEqual(report["blockers"], [])
                self.assertFalse(report["5100_in_log"])

    def test_prerequisite_taxonomy_has_no_log_text(self):
        report = classify_text(
            b"Error: servicing component store blocked setup\n"
            b"setup cannot continue because the Windows Update service is blocked\n"
            b"pending reboot required: failure\n"
            b"unsupported processor architecture: error\n"
        )
        self.assertEqual(report["status"], "CLASSIFIED")
        self.assertIn("WINDOWS_SERVICING_BLOCK", report["blockers"])
        self.assertIn("PENDING_REBOOT_BLOCK", report["blockers"])
        self.assertIn("PROCESSOR_BLOCK", report["blockers"])
        self.assertEqual(set(report), set(empty()))

    def test_malformed_or_missing_is_not_a_success(self):
        self.assertEqual(classify_text(b"x" * (8 * 1024 * 1024 + 1)),
                         empty("TOO_LARGE"))
        with TemporaryDirectory() as td:
            p = Path(td) / "missing"
            self.assertEqual(classify_file(p), empty("NOT_FOUND"))
            p.symlink_to(Path(td) / "private")
            self.assertEqual(classify_file(p), empty("READ_FAILED"))
        self.assertFalse(validate(dict(empty(), raw_original_log="SECRET")))
        self.assertFalse(validate(dict(empty(), blockers=["custom action copied"])))
        self.assertFalse(validate(dict(empty(), os_versions=["10.0.19045"])))

if __name__ == "__main__":
    unittest.main()
