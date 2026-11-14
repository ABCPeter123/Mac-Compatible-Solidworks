"""Independent, synthetic privacy tests for Microsoft .NET setup log classifier."""
import json
from pathlib import Path
import tempfile
from unittest import mock
import unittest

from scripts import netfx481_setup_evidence as evidence
from scripts import netfx481_trial as trial


class NetFxSetupEvidenceTests(unittest.TestCase):
    def test_stage_and_only_known_error_codes(self):
        raw = (
            b"2026-11-14 install phase\n"
            b"MSI error 0x80070643 while installing Native Framework\n"
            b"CBS servicing failed 0x800F081F during assembly resolution\n"
            b"Result: contact test-name@example.net path /Users/Test/private and 0xABCDABCD\n"
        )
        result = evidence.classify_text(raw)
        self.assertEqual(result["status"], "CLASSIFIED")
        self.assertEqual(result["phase"], "SERVICING")
        self.assertEqual(result["codes"], ["MSI_FATAL_ERROR", "SERVICING_SOURCE_MISSING"])
        blob = json.dumps(result)
        self.assertNotIn("test-name", blob)
        self.assertNotIn("Users", blob)
        self.assertNotIn("ABCDABCD", blob)

    def test_utf16_windows_setup_log(self):
        data = b"\xff\xfe" + "MSI custom action failed 0x80070005\n".encode("utf-16-le")
        result = evidence.classify_text(data)
        self.assertEqual(result["phase"], "MSI_INSTALL")
        self.assertEqual(result["codes"], ["ACCESS_DENIED"])

    def test_error_words_needed_to_classify_lines(self):
        result = evidence.classify_text(
            b"cache: 0x80070643 available, servicing package mentioned\n"
            b"Install succeeded\n"
        )
        self.assertEqual(result["phase"], "UNKNOWN")
        self.assertEqual(result["codes"], [])

    def test_empty_oversized_and_bad_encoding_fail_closed(self):
        self.assertEqual(evidence.classify_text(b"")["status"], "EMPTY")
        self.assertEqual(evidence.classify_text(b"x" * (evidence.MAX_LOG_BYTES + 1))["status"], "TOO_LARGE")
        self.assertEqual(evidence.classify_text(b"\xff\xff\xff")["status"], "CLASSIFIED")

    def test_private_prefix_required_and_log_removed_after_use(self):
        with tempfile.TemporaryDirectory() as temp:
            prefix = Path(temp)
            (prefix / "drive_c").mkdir()
            (prefix / "system.reg").write_text("")
            with self.assertRaises(ValueError):
                evidence.private_log_path(prefix)
            (prefix / trial.SENTINEL).write_text("")
            path = evidence.private_log_path(prefix)
            self.assertEqual(path, prefix / "drive_c" / evidence.FOLDER / evidence.NAME)
            self.assertFalse(path.exists())
            path.write_text("CBS Error 0x800F0922")
            self.assertEqual(evidence.classify_log(path)["codes"], ["SERVICING_FAILURE"])
            evidence.discard_log(path)
            self.assertFalse(path.exists())

    def test_refuse_symlink_and_preexisting_log(self):
        with tempfile.TemporaryDirectory() as temp:
            prefix = Path(temp)
            (prefix / "drive_c").mkdir()
            (prefix / "system.reg").write_text("")
            (prefix / trial.SENTINEL).write_text("")
            path = evidence.private_log_path(prefix)
            path.write_text("existing")
            with self.assertRaises(ValueError):
                evidence.private_log_path(prefix)
            path.unlink()
            try:
                path.symlink_to(prefix / "system.reg")
            except (NotImplementedError, OSError):
                self.skipTest("symlinks unavailable")
            with self.assertRaises(ValueError):
                evidence.private_log_path(prefix)
            self.assertEqual(evidence.classify_log(path)["status"], "READ_FAILED")
            evidence.discard_log(path)
            self.assertTrue(path.is_symlink())

    def test_sanitized_combine_rejects_unexpected_words(self):
        before = {"registry": "NOT_FOUND", "managed": "PASS", "clr_family": "MONO"}
        report = trial.combine(
            before, before, "EXIT_NONZERO", 194,
            setup_evidence=evidence.classify_text(b"MSI error 0x80070643")
        )
        self.assertEqual(report["setup_evidence"]["codes"], ["MSI_FATAL_ERROR"])
        with self.assertRaises(ValueError):
            trial.combine(before, before, "EXIT_NONZERO", 194,
                          setup_evidence={"status": "CLASSIFIED", "phase": "PRIVATE_PATH", "codes": []})
        with self.assertRaises(ValueError):
            trial.combine(before, before, "EXIT_NONZERO", 194,
                          setup_evidence={"status": "CLASSIFIED", "phase": "UNKNOWN", "codes": ["SECRET"]})

    def test_find_secondary_framework_temp_logs_and_cbs_with_no_paths(self):
        with tempfile.TemporaryDirectory() as temp:
            prefix = Path(temp)
            (prefix / "drive_c").mkdir()
            (prefix / "system.reg").write_text("")
            (prefix / trial.SENTINEL).write_text("")
            win_temp = prefix / "drive_c" / "users" / "runner" / "AppData" / "Local" / "Temp"
            win_temp.mkdir(parents=True)
            (win_temp / "dd_ndp481-x86-x64-allos-enu_decompression_log.txt").write_text(
                "extract failed 0x80070002 C:\\Users\\private\\Downloads\\installer\n"
            )
            (win_temp / "Microsoft .NET Framework 4.8.1 Setup_20261114_1300.html").write_text(
                "MSI installation failed 0x80070643 password secret"
            )
            cbs = prefix / "drive_c" / "windows" / "logs" / "CBS"
            cbs.mkdir(parents=True)
            (cbs / "CBS.log").write_text("CBS servicing failed 0x800F081F")
            (win_temp / "unrelated-private-document.txt").write_text("private text ignored")
            report = evidence.scan_secondary_logs(prefix)
            self.assertEqual(report["status"], "CLASSIFIED")
            self.assertEqual(report["files_scanned"], 3)
            self.assertEqual(report["sources"]["BOOTSTRAPPER_TEMP"], 1)
            self.assertEqual(report["sources"]["FRAMEWORK_SETUP"], 1)
            self.assertEqual(report["sources"]["SERVICING_CBS"], 1)
            self.assertIn(report["phase"], evidence.KNOWN_PHASES)
            self.assertEqual(report["codes"], [
                "FILE_NOT_FOUND", "MSI_FATAL_ERROR", "SERVICING_SOURCE_MISSING"
            ])
            self.assertTrue(evidence.validate_secondary_report(report))
            payload = json.dumps(report)
            for forbidden in ("runner", "private", "password", "dd_ndp", "AppData", "CBS.log"):
                self.assertNotIn(forbidden, payload)

    def test_secondary_scan_limits_symlinks_and_missing_source(self):
        with tempfile.TemporaryDirectory() as temp:
            prefix = Path(temp)
            (prefix / "drive_c").mkdir()
            (prefix / "system.reg").write_text("")
            (prefix / trial.SENTINEL).write_text("")
            no_files = evidence.scan_secondary_logs(prefix)
            self.assertEqual(no_files["status"], "NOT_FOUND")
            self.assertTrue(evidence.validate_secondary_report(no_files))
            tempdir = prefix / "drive_c" / "users" / "runner" / "Temp"
            tempdir.mkdir(parents=True)
            external = prefix / "sensitive.txt"
            external.write_text("MSI failed 0x80070643")
            linked = tempdir / "dd_fake_setup.log"
            try:
                linked.symlink_to(external)
            except (OSError, NotImplementedError):
                self.skipTest("symlinks unavailable")
            report = evidence.scan_secondary_logs(prefix)
            self.assertEqual(report["status"], "NOT_FOUND")
            self.assertEqual(report["files_scanned"], 0)

    def test_secondary_report_cannot_inject_arbitrary_data_into_json(self):
        before = {"registry": "NOT_FOUND", "managed": "PASS", "clr_family": "MONO"}
        legit = {
            "status": "CLASSIFIED", "files_scanned": 1,
            "sources": {"BOOTSTRAPPER_TEMP": 1, "FRAMEWORK_SETUP": 0,
                        "SETUP_EVENTS": 0, "SERVICING_CBS": 0},
            "phase": "MSI_INSTALL", "codes": ["MSI_FATAL_ERROR"],
        }
        result = trial.combine(before, before, "EXIT_NONZERO", 194,
                               secondary_evidence=legit)
        self.assertEqual(result["secondary_evidence"]["phase"], "MSI_INSTALL")
        for key, value in [
            ("phase", "C:\\Users\\secret"),
            ("status", "UNKNOWN_PRIVATE"),
            ("files_scanned", -4),
            ("codes", ["secret email"]),
        ]:
            unsafe = dict(legit)
            unsafe[key] = value
            with self.assertRaises(ValueError):
                trial.combine(before, before, "EXIT_NONZERO", 194,
                              secondary_evidence=unsafe)

    def test_real_microsoft_installer_has_only_fixed_private_log_path(self):
        with mock.patch.object(trial.subprocess, "Popen") as proc:
            proc.return_value.wait.return_value = 194
            result = trial.run_installer(
                Path("wine"), Path("/tmp/disposable"), Path("/tmp/NDP481-x86-x64-AllOS-ENU.exe"),
                210, log_windows_path=evidence.WINDOWS_LOG_PATH,
            )
        self.assertEqual(result, ("EXIT_NONZERO", 194))
        cmd = proc.call_args.args[0]
        self.assertEqual(cmd[-2:], ["/log", evidence.WINDOWS_LOG_PATH])
        self.assertEqual(cmd[2:4], ["/q", "/norestart"])
        with self.assertRaises(ValueError), mock.patch.object(trial.subprocess, "Popen") as denied:
            trial.run_installer(
                Path("wine"), Path("/tmp/disposable"), Path("/tmp/NDP481-x86-x64-AllOS-ENU.exe"),
                210, log_windows_path=r"C:\Users\someone\private.txt",
            )
        denied.assert_not_called()


if __name__ == "__main__":
    unittest.main()
