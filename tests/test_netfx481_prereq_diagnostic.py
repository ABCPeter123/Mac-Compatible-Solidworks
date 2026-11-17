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

    def test_win7_sp_reported_by_original_setup_is_specific_to_net48(self):
        for original, expected in (
            (b"OS Version = 6.1.7601, SP = 1.0\n", "WINDOWS_7_SP1_REPORTED_48"),
            (b"OS Version = 6.1.7600, SP = 0.0\n", "WINDOWS_7_SP0_REPORTED_48"),
            (b"OS Version = 6.1.7601\n", "WINDOWS_7_SP_UNVERIFIED_48"),
            (b"OS Version = 6.3.9600\n", "WINDOWS_8_1_FAMILY_48"),
        ):
            with self.subTest(source=original):
                report = classify_text(original, family="NETFX48")
                self.assertEqual(report["os_versions"], [expected])
                self.assertEqual(report["blockers"], [])
                self.assertTrue(validate(report))
                self.assertNotIn("7601", str(report))
        old = classify_text(b"OS Version = 6.1.7601, SP = 1.0\n")
        self.assertEqual(old["os_versions"], ["BELOW_WINDOWS_10"])
        with self.assertRaises(ValueError):
            classify_text(b"OS Version = 6.1.7601\n", family="UNTRUSTED")

    def test_modern_19045_and_22621_are_supported_but_not_installed(self):
        for version, expected in (
            ("10.0.19045", "WINDOWS_10_SUPPORTED"),
            ("10.0.22000", "WINDOWS_11_21H2_INSTALLABLE"),
            ("10.0.22621", "WINDOWS_11_22H2_PLUS_INBOX_481"),
            ("10.0.26100", "WINDOWS_11_22H2_PLUS_INBOX_481"),
            ("10.0.18362", "WINDOWS_10_TOO_OLD"),
        ):
            with self.subTest(version=version):
                report = classify_text(("OS Version = " + version + "\n").encode())
                self.assertEqual(report["os_versions"], [expected])
                self.assertEqual(report["blockers"], [])
                self.assertFalse(report["5100_in_log"])

    def test_os_version_band_alone_never_asserts_prerequisite_root_cause(self):
        for build in ("22000", "22621", "26100"):
            raw = ("OS Version = 10.0." + build + "\n"
                   "Error: blocked, result 5100\n"
                   "Private path=C:\\\\Users\\\\secret\n").encode()
            report = classify_text(raw)
            self.assertTrue(validate(report))
            self.assertIn("UNKNOWN_PREREQUISITE", report["blockers"])
            self.assertTrue(report["5100_in_log"])
            self.assertNotIn("secret", str(report))

    def test_real_5100_stopblock_distinguishes_disk_deficit(self):
        raw = (
            b"OS Version = 10.0.22000, SP = 0.0, Platform 2\n"
            b"Drive:[C:\\] Bytes Needed:[1476239375] Bytes Available:[741433344]\n"
            b"Not enough disk space available to download files and/or install"
            b" - unable to complete install.\n"
            b"Final Result: Installation failed with error code: (0x000013EC), "
            b"A StopBlock was hit or a System Requirement was not met.\n"
            b"Private path=C:\\Users\\secret\\vendor.bin\n"
        )
        actual = classify_text(raw)
        self.assertEqual(actual["os_versions"], ["WINDOWS_11_21H2_INSTALLABLE"])
        self.assertEqual(actual["blockers"], ["DISK_SPACE_BLOCK"])
        self.assertTrue(actual["5100_in_log"])
        self.assertTrue(validate(actual))
        self.assertNotIn("741433344", str(actual))
        self.assertNotIn("secret", str(actual))

    def test_actual_setup_html_blocker_lines(self):
        raw = (
            b"Installation Blockers:\n"
            b"1.The setup cannot run in compatibility mode.\n"
            b"2.The .NET Framework 4.8.1 is not supported on this operating system.\n"
            b"Final Result: Installation failed with error code: (0x000013EC), "
            b"A StopBlock was hit.\n"
        )
        result = classify_text(raw)
        self.assertIn("COMPATIBILITY_MODE_BLOCK", result["blockers"])
        self.assertIn("OS_VERSION_BLOCK", result["blockers"])
        self.assertNotIn("UNKNOWN_PREREQUISITE", result["blockers"])

    def test_low_disk_free_bytes_without_explicit_message(self):
        below = classify_text(
            b"Drive:[C:\\] Bytes Needed:[5000000000] Bytes Available:[1000000000]\n"
            b"Final Result: failed 5100 StopBlock\n"
        )
        above = classify_text(
            b"Drive:[C:\\] Bytes Needed:[1000000] Bytes Available:[2000000]\n"
            b"Final Result: failed 5100 StopBlock\n"
        )
        self.assertEqual(below["blockers"], ["DISK_SPACE_BLOCK"])
        self.assertEqual(above["blockers"], ["UNKNOWN_PREREQUISITE"])

    def test_windows_update_service_unavailable(self):
        report = classify_text(
            b"Setup may not run because the Windows Update Service is not available\n"
            b"Final Result: failed 5100\n"
        )
        self.assertIn("WINDOWS_UPDATE_BLOCK", report["blockers"])
        self.assertNotIn("UNKNOWN_PREREQUISITE", report["blockers"])

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

    def test_error_prefix_can_report_missing_update_without_inventory_false_positive(self):
        failed = classify_text(
            b"Error: missing update KB12345678 prevents prerequisite setup\n"
            b"System file C:\\\\Users\\\\secret\\\\private.dll\n")
        self.assertEqual(failed["blockers"], ["MISSING_UPDATE_BLOCK"])
        self.assertNotIn("secret", str(failed))
        informational = classify_text(
            b"Installed update KB12345678 detected.\n"
            b"Info: KB12345678 is present.\n")
        self.assertEqual(informational["blockers"], [])

    def test_microsoft_documented_blocking_messages_without_error_prefix(self):
        # Real setup messages can be plain English, with no "error" prefix.
        # Only precise blocking phrases should classify a prerequisite.
        examples = (
            (b"The update corresponding to KB2919355 needs to be installed "
             b"before you can install this product.\n", "MISSING_UPDATE_BLOCK"),
            (b"Setup cannot continue because a previous installation requires "
             b"your computer to be restarted.\n", "PENDING_REBOOT_BLOCK"),
            (b"You do not have sufficient privileges to complete this "
             b"operation for all users of this computer.\n", "ADMIN_RIGHTS_BLOCK"),
            (b"The .NET Framework 4.8.1 redistributable does not apply to "
             b"this operating system.\n", "OS_VERSION_BLOCK"),
        )
        for message, category in examples:
            with self.subTest(category=category):
                report = classify_text(message)
                self.assertTrue(validate(report))
                self.assertIn(category, report["blockers"])
        # The mere mention of a KB or a restart is not an installer failure.
        self.assertEqual(classify_text(
            b"Installed update KB2919355 detected.\n"
            b"Restart is not required.\n")["blockers"], [])

    def test_true_windows_installer_block_not_false_os_or_permissions(self):
        raw = (
            b"[11/17/2026, 14:01:01]Global Block Checks: Checking for global blockers\n"
            b"[11/17/2026, 14:01:01]BlockIf: The .NET Framework 4.8 "
            b"redistributable does not apply to this operating system.\n"
            b"[11/17/2026, 14:01:01]evaluating BlockIf:\n"
            b"[11/17/2026, 14:01:02] LessThan evaluated to false\n"
            b"[11/17/2026, 14:01:02]BlockIf evaluated to false\n"
            b"[11/17/2026, 14:01:02]BlockIf: You do not have sufficient "
            b"privileges to complete this operation.\n"
            b"[11/17/2026, 14:01:02]evaluating BlockIf:\n"
            b"[11/17/2026, 14:01:02]BlockIf evaluated to false\n"
            b"[11/17/2026, 14:01:02]BlockIf: Setup cannot run because "
            b"the Windows Installer Service is not available on this computer.\n"
            b"[11/17/2026, 14:01:02]evaluating BlockIf:\n"
            b"[11/17/2026, 14:01:02]BlockIf evaluated to true\n"
            b"Final Result: Installation failed with error code: 5100 StopBlock\n"
        )
        report = classify_text(raw, family="NETFX48")
        self.assertEqual(report["blockers"], ["WINDOWS_INSTALLER_BLOCK"])
        self.assertTrue(report["5100_in_log"])
        self.assertTrue(validate(report))
        self.assertNotIn("Installer Service", str(report))

    def test_all_false_native_blockif_is_not_a_prerequisite_failure(self):
        raw = (
            b"BlockIf: The .NET Framework 4.8.1 is not supported "
            b"on this operating system.\n"
            b"evaluating BlockIf:\n"
            b"Exists evaluated to false\n"
            b"BlockIf evaluated to false\n"
            b"BlockIf: Setup cannot continue because a previous "
            b"installation requires restarting.\n"
            b"evaluating BlockIf:\n"
            b"BlockIf evaluated to false\n"
            b"Global Block Checks no blocking conditions found\n"
        )
        report = classify_text(raw)
        self.assertEqual(report["blockers"], [])
        self.assertFalse(report["5100_in_log"])

    def test_all_false_native_blockif_with_real_5100_is_unknown_not_os(self):
        raw = (
            b"BlockIf: This version is not supported on this operating system.\n"
            b"evaluating BlockIf:\n"
            b"BlockIf evaluated to false\n"
            b"Final Result: Installation failed with error code: "
            b"(0x000013EC), A StopBlock was hit.\n"
        )
        report = classify_text(raw)
        self.assertEqual(report["blockers"], ["UNKNOWN_PREREQUISITE"])
        self.assertTrue(report["5100_in_log"])

    def test_wrapped_description_and_true_safe_mode(self):
        raw = (
            b"[11/17/2026, 14:02:05] BlockIf: You cannot run the .NET "
            b"Framework setup program in safe\n"
            b"[11/17/2026, 14:02:05] mode. Restart Windows normally.\n"
            b"[11/17/2026, 14:02:05] evaluating BlockIf:\n"
            b"[11/17/2026, 14:02:05] Exists: evaluating\n"
            b"[11/17/2026, 14:02:05] BlockIf evaluated to true\n"
        )
        report = classify_text(raw)
        self.assertEqual(report["blockers"], ["SAFE_MODE_BLOCK"])

    def test_incomplete_block_does_not_become_true_when_other_block_is_false(self):
        raw = (
            b"BlockIf: The operating system is not supported.\n"
            b"evaluating BlockIf:\n"
            b"BlockIf: You cannot run the setup in safe mode.\n"
            b"evaluating BlockIf:\n"
            b"BlockIf evaluated to false\n"
            b"Global Block Checks no blocking conditions found\n"
        )
        report = classify_text(raw)
        self.assertEqual(report["blockers"], [])

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
