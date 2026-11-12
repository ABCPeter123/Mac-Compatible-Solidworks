import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import zipfile

from scripts.solidworks_log_triage import analyze, classify, decode_log, MAX_LOG_BYTES


class SolidWorksLogTriageTests(unittest.TestCase):
    def test_whitelisted_categories_only_never_private_log_text(self):
        text = (
            "C:\\Users\\Jane.Doe\\Documents\\token1234567\\file.dll\n"
            "user@example.com Serial Number 1234-5678-9012\n"
            "ERROR 1603 and 0x80040154\n"
            "Fictional error 0xDEADBEEF\n"
        )
        result = classify(text)
        self.assertEqual(result["msi_fatal_1603"], 1)
        self.assertEqual(result["com_class_not_registered"], 1)
        self.assertNotIn("0xdeadbeef", json.dumps(result))
        self.assertNotIn("Jane.Doe", json.dumps(result))

    def test_utf16_windows_logs(self):
        source = "0x80070005 installation failed"
        data = b"\xff\xfe" + source.encode("utf-16-le")
        self.assertIn(source, decode_log(data))

    def test_directory_and_zip_no_filename_exposure(self):
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp) / "private-path-user-peter"
            folder.mkdir()
            (folder / "SummaryIMLog_secret-account.txt").write_text("MSI error 1603\n")
            with zipfile.ZipFile(folder / "IM_Logs.zip", "w") as archive:
                archive.writestr("../private-user-email.log", "0x80070424\n")
                archive.writestr("unrelated.exe", "0x80070005")
            report = analyze(folder)
            self.assertEqual(report["log_files_examined"], 2)
            self.assertEqual(report["zip_members_examined"], 1)
            self.assertEqual(report["potential_issue_counts"]["msi_fatal_1603"], 1)
            self.assertEqual(report["potential_issue_counts"]["service_not_found"], 1)
            self.assertNotIn("private-path-user-peter", json.dumps(report))
            self.assertNotIn("private-user-email", json.dumps(report))

    def test_zip_member_decompression_is_bounded(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "IM_Logs.zip"
            with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("excess.txt", b"A" * (MAX_LOG_BYTES + 5000))
            result = analyze(path)
            self.assertTrue(result["scan_incomplete"])
            self.assertEqual(result["bytes_examined"], MAX_LOG_BYTES)

    def test_report_output_outside_source_directory(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp) / "logs"
            directory.mkdir()
            output = directory / "report.json"
            result = subprocess.run(
                [sys.executable, "-m", "scripts.solidworks_log_triage",
                 "--logs", str(directory), "--output", str(output)],
                capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("outside", result.stderr)
            self.assertFalse(output.exists())

    def test_no_recognized_indicators_is_not_install_success(self):
        with tempfile.TemporaryDirectory() as temp:
            file = Path(temp) / "SummaryIMLog.txt"
            file.write_text("No error yet\n")
            result = analyze(file)
            self.assertTrue(result["no_recognized_indicators"])
            self.assertEqual(result["potential_issue_counts"], {})

    def test_refuses_to_scan_installer_executable_as_log(self):
        with tempfile.TemporaryDirectory() as temp:
            file = Path(temp) / "setup.exe"
            file.write_bytes(b"MZ")
            with self.assertRaises(ValueError):
                analyze(file)


if __name__ == "__main__":
    unittest.main()
