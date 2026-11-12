import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from scripts.installer_evidence_report import correlate


def media(*, root=True, bootstrapper=False, incomplete=False, kind="directory"):
    return {
        "schema": 1, "input_kind": kind, "files_examined": 4,
        "scan_incomplete": incomplete,
        "entrypoints": {"root_setup_observed": root,
                        "nested_setup_observed": False,
                        "bootstrapper_observed": bootstrapper},
        "package_indicators": {
            "vcredist_x64": {"observed": True,
                            "expected_public_filenames": ["vc_redist.x64.exe"]},
            "vcredist_x86": {"observed": False,
                            "expected_public_filenames": ["vc_redist.x86.exe"]},
        },
        "secret_path": "C:\\Users\\PRIVATE_USER\\License\\topsecret",
    }


def logs(issues=None, *, incomplete=False, invalid_zip=False):
    return {
        "schema": 1, "log_files_examined": 2, "scan_incomplete": incomplete,
        "invalid_zip_encountered": invalid_zip,
        "potential_issue_counts": issues if issues is not None else {},
        "secret_line": "user@example.com SERIAL SECRET KEY",
    }


class InstallerEvidenceReportTests(unittest.TestCase):
    def action_ids(self, report):
        return [action["id"] for action in report["recommended_next_actions"]]

    def test_correlates_known_com_service_msi_and_runtime_errors(self):
        result = correlate(media(), logs({
            "com_class_not_registered": 2,
            "service_not_found": 1,
            "service_disabled": 1,
            "msi_fatal_1603": 1,
            "msi_action_failure": 2,
            "webview2_error": 1,
        }))
        ids = self.action_ids(result)
        self.assertEqual(result["installation_and_cad_compatibility"], "NOT_DEMONSTRATED")
        self.assertEqual(result["media"]["status"], "root_setup_observed")
        self.assertEqual(result["media"]["public_package_groups_observed"], 1)
        self.assertEqual(result["logs"]["status"], "indicators_found")
        for action in ("inspect_com_registration", "inspect_service_registration",
                       "inspect_msi_failure", "inspect_webview2_runtime"):
            self.assertEqual(ids.count(action), 1)
        self.assertNotIn("verify_complete_installer", ids)
        self.assertNotIn("collect_installer_logs", ids)

    def test_bootstrapper_is_not_complete_installer(self):
        result = correlate(media(root=False, bootstrapper=True, kind="single_file"))
        self.assertEqual(result["media"]["status"], "bootstrapper_only")
        self.assertIn("verify_complete_installer", self.action_ids(result))
        self.assertIn("collect_installer_logs", self.action_ids(result))

    def test_single_setup_executable_cannot_claim_full_media(self):
        result = correlate(media(kind="single_file"))
        self.assertEqual(result["media"]["status"], "single_setup_executable")
        self.assertIn("verify_complete_installer", self.action_ids(result))

    def test_missing_media_and_empty_logs_do_not_infer_success(self):
        result = correlate(logs=logs())
        self.assertIn("run_media_preflight", self.action_ids(result))
        self.assertEqual(result["logs"]["status"], "no_recognized_indicators")
        self.assertEqual(result["installation_and_cad_compatibility"], "NOT_DEMONSTRATED")

    def test_incomplete_and_bad_zip_are_explicit(self):
        result = correlate(media(incomplete=True), logs(incomplete=True, invalid_zip=True))
        ids = self.action_ids(result)
        for action in ("review_media_scan_limits", "review_log_scan_limits", "recollect_damaged_logs"):
            self.assertIn(action, ids)

    def test_unknown_log_code_is_rejected_without_leaking_it(self):
        with self.assertRaisesRegex(ValueError, "Unsupported diagnostic identifier") as ctx:
            correlate(media(), logs({"private-secret-serial-key": 1}))
        self.assertNotIn("private-secret", str(ctx.exception))

    def test_non_integer_and_negative_counts_rejected(self):
        for count in (True, -1, "99", 99_999_999):
            with self.subTest(count=count):
                with self.assertRaises(ValueError):
                    correlate(media(), logs({"msi_fatal_1603": count}))

    def test_reports_never_echo_private_fields(self):
        output = json.dumps(correlate(media(), logs({"com_class_not_registered": 1})))
        for secret in ("PRIVATE_USER", "topsecret", "user@example.com", "SECRET KEY", "vc_redist.x64.exe"):
            self.assertNotIn(secret, output)

    def test_cli_uses_only_sanitized_reports(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            m, l, out = root / "media.json", root / "logs.json", root / "report.json"
            m.write_text(json.dumps(media()), encoding="utf-8")
            l.write_text(json.dumps(logs({"msi_fatal_1603": 1})), encoding="utf-8")
            cp = subprocess.run([sys.executable, "-m", "scripts.installer_evidence_report",
                                 "--media-report", str(m), "--log-report", str(l),
                                 "--output", str(out)], capture_output=True, text=True)
            self.assertEqual(cp.returncode, 0, cp.stderr)
            self.assertIn("NOT_DEMONSTRATED", cp.stdout)
            self.assertIn("inspect_msi_failure", out.read_text(encoding="utf-8"))
            self.assertNotIn(str(root), out.read_text(encoding="utf-8"))

    def test_cli_rejects_overwriting_input(self):
        with tempfile.TemporaryDirectory() as temp:
            m = Path(temp) / "media.json"
            content = json.dumps(media())
            m.write_text(content, encoding="utf-8")
            cp = subprocess.run([sys.executable, "-m", "scripts.installer_evidence_report",
                                 "--media-report", str(m), "--output", str(m)],
                                capture_output=True, text=True)
            self.assertNotEqual(cp.returncode, 0)
            self.assertEqual(m.read_text(encoding="utf-8"), content)

    def test_cli_rejects_oversized_and_unsanitized_json(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            m, out = root / "bad.json", root / "out.json"
            m.write_bytes(b"{" + b" " * (1024 * 1024 + 2) + b"}")
            cp = subprocess.run([sys.executable, "-m", "scripts.installer_evidence_report",
                                 "--media-report", str(m), "--output", str(out)],
                                capture_output=True, text=True)
            self.assertNotEqual(cp.returncode, 0)
            self.assertFalse(out.exists())

    def test_requires_one_report(self):
        with self.assertRaises(ValueError):
            correlate()


if __name__ == "__main__":
    unittest.main()
