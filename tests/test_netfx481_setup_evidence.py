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
            self.assertEqual(report["prerequisite_files"], 2)
            self.assertEqual(report["stage_scope"], "NOT_REQUESTED")
            self.assertEqual(report["stage_files"], 0)
            self.assertEqual(report["sources"]["BOOTSTRAPPER_TEMP"], 1)
            self.assertEqual(report["sources"]["FRAMEWORK_SETUP"], 1)
            self.assertEqual(report["sources"]["SERVICING_CBS"], 1)
            self.assertIn(report["phase"], evidence.KNOWN_PHASES)
            self.assertEqual(report["codes"], [
                "FILE_NOT_FOUND", "MSI_FATAL_ERROR", "SERVICING_SOURCE_MISSING"
            ])
            self.assertTrue(evidence.validate_secondary_report(report))
            self.assertEqual(report["prerequisite"]["status"], "CLASSIFIED")
            self.assertFalse(report["prerequisite"]["5100_in_log"])
            payload = json.dumps(report)
            for forbidden in ("runner", "private", "password", "dd_ndp", "AppData", "CBS.log"):
                self.assertNotIn(forbidden, payload)

    def test_secondary_html_stopblock_private_and_causally_discriminating(self):
        with tempfile.TemporaryDirectory() as temp:
            prefix = Path(temp)
            (prefix / "drive_c").mkdir()
            (prefix / "system.reg").write_text("")
            (prefix / trial.SENTINEL).write_text("")
            local = prefix / "drive_c" / "users" / "tester" / "AppData" / "Local" / "Temp"
            local.mkdir(parents=True)
            (local / "Microsoft .NET Framework 4.8.1 Setup_20261115.html").write_text(
                "Installation Blockers:\n"
                "Not enough disk space available to download files and/or install\n"
                "Final Result: Installation failed with error code: (0x000013EC), "
                "A StopBlock was hit or a System Requirement was not met.\n"
                "OS Version = 10.0.19045\n"
                "Original account C:\\Users\\tester\\private\\important.txt\n"
            )
            outcome = evidence.scan_secondary_logs(prefix)
            self.assertTrue(evidence.validate_secondary_report(outcome))
            self.assertEqual(outcome["prerequisite"]["blockers"], ["DISK_SPACE_BLOCK"])
            self.assertEqual(outcome["prerequisite"]["os_versions"], ["WINDOWS_10_SUPPORTED"])
            self.assertTrue(outcome["prerequisite"]["5100_in_log"])
            for secret in ("tester", "private", "important.txt", "Microsoft .NET"):
                self.assertNotIn(secret, json.dumps(outcome))
            forged = dict(outcome)
            forged["prerequisite"] = dict(outcome["prerequisite"], original_html="LEAK")
            self.assertFalse(evidence.validate_secondary_report(forged))

    def test_prior_setup_failure_never_becomes_481_stopblock(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            prefix = root / "prefix"
            (prefix / "drive_c").mkdir(parents=True)
            (prefix / "system.reg").write_text("")
            (prefix / trial.SENTINEL).write_text("")
            logs = prefix / "drive_c" / "users" / "runner" / "AppData" / "Local" / "Temp"
            logs.mkdir(parents=True)
            previous = (b"OS Version = 6.1.7601\n"
                        b"Installation Blockers:\n"
                        b"1.The setup cannot run in compatibility mode.\n"
                        b"2.A missing update KB1234567 blocks this build.\n"
                        b"Final Result: failed 5100 StopBlock\n"
                        b"User path C:\\Users\\private\\old.exe\n")
            (logs / "dd_dotNetFx40_previous.log").write_bytes(previous)
            (logs / "NetFxSetupEvents.txt").write_bytes(previous)
            (logs / "dd_msxml3_previous.log").write_bytes(previous)
            result = evidence.scan_secondary_logs(prefix)
            self.assertTrue(evidence.validate_secondary_report(result))
            self.assertEqual(result["files_scanned"], 3)
            self.assertEqual(result["prerequisite_files"], 0)
            self.assertEqual(result["prerequisite"]["status"], "NOT_FOUND")
            self.assertEqual(result["prerequisite"]["os_versions"], [])
            self.assertEqual(result["prerequisite"]["blockers"], [])
            self.assertNotIn("private", json.dumps(result))

            (logs / "dd_ndp481_real.log").write_bytes(
                b"OS Version = 10.0.19045\n"
                b"Bytes Needed:[2000] Bytes Available:[1000]\n"
                b"Final Result: error 5100 StopBlock\n")
            filtered = evidence.scan_secondary_logs(prefix)
            self.assertTrue(evidence.validate_secondary_report(filtered))
            self.assertEqual(filtered["files_scanned"], 4)
            self.assertEqual(filtered["prerequisite_files"], 1)
            self.assertEqual(filtered["prerequisite"]["os_versions"], ["WINDOWS_10_SUPPORTED"])
            self.assertEqual(filtered["prerequisite"]["blockers"], ["DISK_SPACE_BLOCK"])
            self.assertTrue(filtered["prerequisite"]["5100_in_log"])
            self.assertNotIn("BELOW_WINDOWS_10", str(filtered))

    def test_prerequisite_census_cannot_be_forged(self):
        report = {
            "status": "CLASSIFIED", "files_scanned": 1, "prerequisite_files": 0,
            "stage_scope": "NOT_REQUESTED", "stage_files": 0,
            "stage_prerequisite": {"status": "NOT_REQUESTED", "os_versions": [],
                                   "blockers": [], "5100_in_log": False},
            "sources": {"BOOTSTRAPPER_TEMP": 1, "FRAMEWORK_SETUP": 0,
                        "SETUP_EVENTS": 0, "SERVICING_CBS": 0},
            "phase": "UNKNOWN", "codes": [],
            "prerequisite": {"status": "NOT_FOUND", "os_versions": [],
                             "blockers": [], "5100_in_log": False},
        }
        self.assertTrue(evidence.validate_secondary_report(report))
        for tamper in (dict(report, prerequisite_files=2),
                       dict(report, prerequisite_files=True),
                       dict(report, prerequisite=dict(report["prerequisite"],
                                                    blockers=["OS_VERSION_BLOCK"]))):
            self.assertFalse(evidence.validate_secondary_report(tamper))

    def test_stage_delta_separates_old_generic_and_changed_481_logs(self):
        with tempfile.TemporaryDirectory() as td:
            prefix = Path(td)
            (prefix / "drive_c").mkdir()
            (prefix / "system.reg").write_text("")
            (prefix / trial.SENTINEL).write_text("")
            logs = prefix / "drive_c" / "users" / "tester" / "AppData" / "Local" / "Temp"
            logs.mkdir(parents=True)
            stale = logs / "dd_old_generic.log"
            stale.write_bytes(b"OS Version = 6.1.7601\n"
                              b"Blocked on Windows update KB1111111\n"
                              b"Final Result: 5100 StopBlock\n")
            changed = logs / "dd_current_generic.log"
            changed.write_bytes(b"Original initial data\n")
            baseline = evidence.snapshot_secondary_logs(prefix)
            self.assertEqual(len(baseline), 2)
            self.assertTrue(all(isinstance(path, Path) for path in baseline))
            changed.write_bytes(b"OS Version = 10.0.19045\n"
                                b"Insufficient disk space\n"
                                b"Final Result: 5100 StopBlock\n")
            fresh = logs / "dd_one_new.log"
            fresh.write_bytes(b"Windows Update Service is not available\n")
            result = evidence.scan_secondary_logs(prefix, baseline=baseline)
            self.assertTrue(evidence.validate_secondary_report(result))
            self.assertEqual(result["files_scanned"], 3)
            self.assertEqual(result["stage_scope"], "CAPTURED")
            self.assertEqual(result["stage_files"], 2)
            self.assertEqual(result["prerequisite_files"], 0)
            self.assertEqual(result["prerequisite"]["status"], "NOT_FOUND")
            self.assertEqual(result["stage_prerequisite"]["os_versions"],
                             ["WINDOWS_10_SUPPORTED"])
            self.assertEqual(result["stage_prerequisite"]["blockers"],
                             ["DISK_SPACE_BLOCK", "WINDOWS_SERVICING_BLOCK", "WINDOWS_UPDATE_BLOCK"])
            self.assertTrue(result["stage_prerequisite"]["5100_in_log"])
            for secret in ("tester", "dd_old_generic", "dd_current_generic", "one_new"):
                self.assertNotIn(secret, json.dumps(result))

    def test_direct_48_isolated_from_40_and_481_with_changed_generic_logs(self):
        with tempfile.TemporaryDirectory() as td:
            prefix = Path(td)
            (prefix / "drive_c").mkdir()
            (prefix / "system.reg").write_text("")
            (prefix / trial.SENTINEL).write_text("")
            local = prefix / "drive_c" / "users" / "runner" / "AppData" / "Local" / "Temp"
            local.mkdir(parents=True)
            private = b"User=C:\\Users\\runner\\secret-install.exe\n"
            (local / "dd_dotNetFx40_old.log").write_bytes(
                b"Final Result: failure 5100 StopBlock, missing update KB1234567\n" + private)
            (local / "Microsoft .NET Framework 4.8.1 Setup_2026.html").write_bytes(
                b"Final Result: 5100 StopBlock, missing update KB8888888\n" + private)
            shared = local / "dd_generic_setup.log"
            shared.write_bytes(b"previous source\n")
            before = evidence.snapshot_secondary_logs(prefix)
            (local / "Microsoft .NET Framework 4.8 Setup_2026.html").write_bytes(
                b"OS Version = 6.1.7601\n"
                b"Final Result: error 5100 StopBlock, Windows Update Service not available\n" + private)
            shared.write_bytes(b"Final Result: error 5100 StopBlock.\n")
            (local / "dd_NDP48-decomp.html").write_bytes(
                b"Error: missing update KB12345678\n")
            report = evidence.scan_secondary_logs(
                prefix, baseline=before, family="NETFX48")
            self.assertTrue(evidence.validate_secondary_report(report))
            self.assertEqual(report["prerequisite_files"], 2)
            self.assertEqual(report["stage_files"], 3)
            self.assertEqual(report["stage_scope"], "CAPTURED")
            self.assertEqual(report["prerequisite"]["os_versions"], ["BELOW_WINDOWS_10"])
            self.assertTrue(report["prerequisite"]["5100_in_log"])
            self.assertIn("WINDOWS_UPDATE_BLOCK", report["prerequisite"]["blockers"])
            self.assertIn("MISSING_UPDATE_BLOCK", report["prerequisite"]["blockers"])
            self.assertNotIn("KB8888888", json.dumps(report))
            self.assertNotIn("secret-install.exe", json.dumps(report))
            self.assertEqual(report["stage_prerequisite"]["status"], "CLASSIFIED")
            with self.assertRaises(ValueError):
                evidence.scan_secondary_logs(prefix, baseline=before, family="UNTRUSTED")

    def test_stage_snapshot_rejects_limits_and_symlink_roots(self):
        with tempfile.TemporaryDirectory() as td:
            prefix = Path(td) / "prefix"
            (prefix / "drive_c").mkdir(parents=True)
            (prefix / "system.reg").write_text("")
            (prefix / trial.SENTINEL).write_text("")
            path = prefix / "drive_c" / "users"
            path.mkdir()
            for i in range(evidence.SECONDARY_MAX_FILES + 1):
                (path / f"dd_test_{i}.log").write_text("private")
            with self.assertRaises(ValueError):
                evidence.snapshot_secondary_logs(prefix)
            for file in path.glob("dd_test*"):
                file.unlink()
            external = Path(td) / "external"
            external.mkdir()
            path.rmdir()
            try:
                path.symlink_to(external)
            except (OSError, NotImplementedError):
                self.skipTest("Symlinks unavailable")
            with self.assertRaises(ValueError):
                evidence.snapshot_secondary_logs(prefix)
            self.assertFalse((external / "dd_test_0.log").exists())

    def test_stage_report_rejects_inconsistent_provenance(self):
        report = evidence.scan_secondary_logs
        with tempfile.TemporaryDirectory() as td:
            prefix = Path(td)
            (prefix / "drive_c").mkdir()
            (prefix / "system.reg").write_text("")
            (prefix / trial.SENTINEL).write_text("")
            baseline = evidence.snapshot_secondary_logs(prefix)
            valid = report(prefix, baseline=baseline)
            self.assertTrue(evidence.validate_secondary_report(valid))
            self.assertEqual(valid["stage_scope"], "CAPTURED")
            self.assertEqual(valid["stage_prerequisite"]["status"], "NOT_FOUND")
            for changed in (
                dict(valid, stage_files=True),
                dict(valid, stage_files=1),
                dict(valid, stage_scope="PRIVATE"),
                dict(valid, stage_prerequisite=dict(valid["stage_prerequisite"],
                                                    blockers=["OS_VERSION_BLOCK"])),
            ):
                self.assertFalse(evidence.validate_secondary_report(changed))

    def test_secondary_scan_limits_symlinks_and_missing_source(self):
        with tempfile.TemporaryDirectory() as temp:
            prefix = Path(temp)
            (prefix / "drive_c").mkdir()
            (prefix / "system.reg").write_text("")
            (prefix / trial.SENTINEL).write_text("")
            no_files = evidence.scan_secondary_logs(prefix)
            self.assertEqual(no_files["status"], "NOT_FOUND")
            self.assertEqual(no_files["prerequisite_files"], 0)
            self.assertEqual(no_files["stage_prerequisite"]["status"], "NOT_REQUESTED")
            self.assertEqual(no_files["prerequisite"]["status"], "NOT_FOUND")
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
            "prerequisite_files": 0, "stage_files": 0,
            "stage_scope": "NOT_REQUESTED",
            "stage_prerequisite": {"status": "NOT_REQUESTED", "os_versions": [],
                                   "blockers": [], "5100_in_log": False},
            "sources": {"BOOTSTRAPPER_TEMP": 1, "FRAMEWORK_SETUP": 0,
                        "SETUP_EVENTS": 0, "SERVICING_CBS": 0},
            "phase": "MSI_INSTALL", "codes": ["MSI_FATAL_ERROR"],
            "prerequisite": {"status": "NOT_FOUND", "os_versions": [],
                             "blockers": [], "5100_in_log": False},
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
