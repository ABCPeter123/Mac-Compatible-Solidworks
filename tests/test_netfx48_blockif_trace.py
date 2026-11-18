"""Synthetic-only true-versus-false BlockIf evidence and privacy regressions."""
import tempfile
from pathlib import Path
import unittest

from scripts import netfx48_blockif_trace as t


class BlockIfTraceTests(unittest.TestCase):
    def test_true_service_1060_vs_false_os_and_failed_5100(self):
        raw = (
            b"OS Version = 10.0.19045\n"
            b"BlockIf: The .NET Framework 4.8 does not apply to this OS.\n"
            b"evaluating BlockIf:\n"
            b"GetOSVersion: 10.0\nBlockIf evaluated to false\n"
            b"BlockIf: A setup prerequisite was not met\n"
            b"evaluating BlockIf:\n"
            b"Service 'TrustedInstaller' doesn't exist. Error 1060\n"
            b"BlockIf evaluated to true\n"
            b"Final Result: setup failed 5100\n"
            b"Private C:\\Users\\secret\\original.msi\n"
        )
        result = t.classify(raw)
        self.assertEqual(result["status"], "CAPTURED")
        self.assertEqual(result["true_count"], 1)
        self.assertEqual(result["false_count"], 1)
        self.assertIn("TRUSTEDINSTALLER_SERVICE_QUERY", result["true_logic_signals"])
        self.assertIn("TRUSTEDINSTALLER_MISSING_1060", result["true_logic_signals"])
        self.assertNotIn("OS_VERSION_CONDITION", result["true_logic_signals"])
        self.assertEqual(result["true_cause_categories"], ["UNKNOWN_PREREQUISITE"])
        self.assertNotIn("secret", str(result))
        self.assertNotIn("TrustedInstaller", str(result))
        self.assertTrue(t.validate(result))

    def test_true_named_service_description_is_classified(self):
        raw = (b"BlockIf: Setup cannot continue because Windows Modules Installer "
               b"service is not available\n"
               b"evaluating BlockIf:\nExists: 0\nBlockIf evaluated to true\n")
        result = t.classify(raw)
        self.assertEqual(result["true_cause_categories"],
                         ["WINDOWS_MODULES_INSTALLER_BLOCK"])
        self.assertEqual(result["true_logic_signals"], [])

    def test_false_service_1060_and_incomplete_block_do_not_claim_blocker(self):
        raw = (b"BlockIf: Windows Modules Installer is not available\n"
               b"evaluating BlockIf:\n"
               b"Service 'TrustedInstaller' doesn't exist. Error 1060\n"
               b"BlockIf evaluated to false\n"
               b"BlockIf: Windows Installer is not available\n"
               b"evaluating BlockIf:\n"
               b"Service 'msiserver' doesn't exist. Error 1060\n")
        result = t.classify(raw)
        self.assertEqual(result["status"], "CAPTURED")
        self.assertEqual(result["false_count"], 1)
        self.assertEqual(result["true_count"], 0)
        self.assertEqual(result["incomplete_count"], 1)
        self.assertEqual(result["true_logic_signals"], [])
        self.assertEqual(result["true_cause_categories"], [])

    def test_true_registry_condition_is_signal_not_installed_runtime(self):
        raw = (b"BlockIf: An unidentified setup requirement applies\n"
               b"evaluating BlockIf:\n"
               b"RegKeyValue: value is missing\nBlockIf evaluated to true\n")
        result = t.classify(raw)
        self.assertEqual(result["true_logic_signals"], ["REGISTRY_CONDITION"])
        self.assertEqual(result["true_cause_categories"], ["UNKNOWN_PREREQUISITE"])

    def test_original_5100_without_blockif_verdicts_reports_phase_only(self):
        raw = (
            b"OS Version = 10.0.19045, SP = 0.0\n"
            b"Global Block Checks: Checking for global blockers\n"
            b"Global Block Checks: No blocking conditions found\n"
            b"Final Result: Installation failed with error code: "
            b"(0x000013EC), A StopBlock was hit\n"
            b"Private path=C:\\Users\\private\\unknown.txt\n"
        )
        report = t.classify(raw)
        self.assertEqual(report["status"], "NO_VERDICTS")
        self.assertEqual(report["log_line_band"], "ONE_TO_100")
        self.assertEqual(report["true_count"], 0)
        self.assertEqual(report["false_count"], 0)
        self.assertEqual(report["milestones"], [
            "GLOBAL_BLOCK_CHECKS", "NO_BLOCKING_CONDITIONS",
            "OS_VERSION_REPORTED", "STOPBLOCK_TERMINAL"])
        self.assertNotIn("private", str(report))
        self.assertTrue(t.validate(report))

    def test_report_distinguishes_unrecognized_format_from_no_blockif_tokens(self):
        raw = (
            b"OS Version = 10.0.19045\n"
            b"BlockIf condition evaluated but structured result unavailable\n"
            b"Final Result 5100 StopBlock\n"
        )
        report = t.classify(raw)
        self.assertEqual(report["status"], "NO_VERDICTS")
        self.assertIn("BLOCKIF_TEXT", report["milestones"])
        self.assertNotIn("BLOCKIF_VERDICT", report["milestones"])
        self.assertTrue(t.validate(report))
        self.assertFalse(t.validate({**report, "milestones": ["PRIVATE"]}))
        self.assertFalse(t.validate({**report, "log_line_band": "C:/Users/private"}))
        self.assertTrue(t.validate(t.blank("LIMIT_REACHED")))

    def test_no_verdict_and_limits_fail_closed(self):
        unclassified = t.classify(b"Final Result: setup failed 5100\n")
        self.assertEqual(unclassified["status"], "NO_VERDICTS")
        self.assertEqual(unclassified["log_line_band"], "ONE_TO_100")
        self.assertTrue(t.validate(unclassified))
        self.assertEqual(t.classify(b"x" * (t.MAX_BYTES + 1)),
                         t.blank("TOO_LARGE"))
        self.assertEqual(t.classify(b"\xff\xfe\x00"), t.blank("INVALID_ENCODING"))
        self.assertEqual(
            t.classify(b"".join(
                b"BlockIf: generic\nBlockIf evaluated to false\n"
                for _ in range(t.MAX_VERDICTS + 1))),
            t.blank("LIMIT_REACHED"))
        self.assertFalse(t.validate({**t.blank(), "raw_log": "PRIVATE"}))
        self.assertFalse(t.validate({**t.blank(), "true_logic_signals": ["PRIVATE"]}))
        self.assertFalse(t.validate({**t.blank(), "true_count": True}))

    def test_private_file_handling(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            missing = root / "does-not-exist"
            self.assertEqual(t.classify_file(missing), t.blank("NOT_FOUND"))
            missing.symlink_to(root / "private")
            self.assertEqual(t.classify_file(missing), t.blank("READ_FAILED"))
            text = root / "setup.log"
            text.write_bytes(b"BlockIf: prerequisite\n"
                             b"evaluating BlockIf:\nBlockIf evaluated to true\n")
            self.assertEqual(t.classify_file(text)["true_count"], 1)


if __name__ == "__main__":
    unittest.main()
