"""Synthetic Microsoft offline package inventory, no copyrighted packages."""
import json
import unittest
from scripts import netfx481_archive_evidence as audit


def listing(*items):
    lines = ["7-Zip [64] 24.0", "Path = original-Microsoft.exe",
             "Type = PE", "----------"]
    for item in items:
        lines.extend(["Path = " + item, "Size = 123456", "Folder = -", ""])
    return ("\n".join(lines) + "\n").encode()


class ArchiveEvidenceTests(unittest.TestCase):
    def test_expected_windows_cab_layout_and_no_names_leaked(self):
        report = audit.analyze(listing(
            r"x64-Windows10.0-KB5000000-x64.cab",
            r"x86-Windows10.0-KB5000000-x86.cab",
            r"packages\NetFxMSI.msi",
            r"payload\clr.dll",
            r"other\mscorlib.dll",
            "PRIVATE_USERNAME.txt",
        ), True)
        self.assertEqual(report["status"], "LISTED")
        self.assertEqual(report["entries"], 6)
        self.assertEqual(report["groups"]["CAB"], 2)
        self.assertTrue(report["features"]["WINDOWS_SERVICING_PACKAGE"])
        self.assertTrue(report["features"]["X64_WINDOWS_UPDATE"])
        self.assertTrue(report["features"]["X86_WINDOWS_UPDATE"])
        self.assertTrue(report["features"]["DIRECT_CLR_DLL"])
        self.assertTrue(report["features"]["DIRECT_MSCORLIB_DLL"])
        self.assertTrue(audit.validate(report))
        encoded = json.dumps(report)
        self.assertNotIn("KB5000000", encoded)
        self.assertNotIn("PRIVATE_USERNAME", encoded)
        self.assertNotIn("clr.dll", encoded)

    def test_unknown_archive_and_bounded_cases(self):
        self.assertEqual(audit.analyze(b"not supported", False)["status"], "NOT_LISTABLE")
        self.assertEqual(audit.analyze(b"no divider", True)["status"], "INVALID_LISTING")
        self.assertEqual(audit.analyze(listing("payload.dll") + b"\x00", True)["status"], "TOO_LARGE")
        self.assertEqual(audit.analyze(b"x" * (audit.MAX_INPUT_BYTES + 1), True)["status"], "TOO_LARGE")

    def test_unrecognized_file_types_stay_aggregated(self):
        result = audit.analyze(listing("file.inf", "update.xml", "random.bin"), True)
        self.assertEqual(result["groups"]["OTHER"], 3)
        self.assertFalse(result["features"]["WINDOWS_SERVICING_PACKAGE"])
        self.assertTrue(audit.validate(result))

    def test_invalid_reports_fail_closed(self):
        good = audit.analyze(listing("x64-Windows10.0-KB123.cab"), True)
        self.assertTrue(audit.validate(good))
        for key, value in [
            ("status", "C:\\private"),
            ("entries", "2"),
            ("entries", 20001),
            ("groups", {"CAB": 1}),
            ("features", {"FULL_FILE_PATH": True}),
        ]:
            wrong = dict(good)
            wrong[key] = value
            with self.subTest(key=key):
                self.assertFalse(audit.validate(wrong))
