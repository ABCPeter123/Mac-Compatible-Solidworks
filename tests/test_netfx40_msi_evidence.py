"""Privacy-safe evidence tests for original Microsoft .NET 4.0 inner MSI failure."""
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from scripts import netfx40_msi_evidence as e


class InnerMSIFailureEvidenceTests(unittest.TestCase):
    def test_actual_microsoft_msi_action_syntax_not_a_keyword_guess(self):
        raw = (
            b"MSI (s) (04:08) [13:34:12:123]: Note: 1: 1402 2: PRIVATE-KEY\n"
            b"Action ended 13:34:12: WriteRegistryValues. Return value 3.\n"
            b"Action ended 13:34:12: InstallFinalize. Return value 3.\n"
            b"Action ended 13:34:12: INSTALL. Return value 3.\n"
        )
        r = e.classify_msi_log(raw)
        self.assertTrue(r["readable"])
        self.assertTrue(r["failure"])
        self.assertEqual(r["action"], "REGISTRY_COM")
        self.assertIn("REGISTRY_ACCESS", r["errors"])
        self.assertNotIn("PRIVATE", str(r))

    def test_known_version_service_assembly_and_custom_action(self):
        for name, expected in (
            ("CA_BlockOlderVersionInstall", "VERSION_GUARD"),
            ("InstallServices", "SERVICE"),
            ("ServiceModelReg", "SERVICE"),
            ("MsiPublishAssemblies", "ASSEMBLY_GAC"),
            ("RegisterTypeLibraries", "REGISTRY_COM"),
            ("InstallFiles", "FILESYSTEM"),
            ("CA_RunFrameworkFix", "CUSTOM_ACTION"),
            ("InstallFinalize", "FINALIZE_CASCADE"),
            ("UnfamiliarPrivateAction", "UNKNOWN"),
        ):
            with self.subTest(name=name):
                self.assertEqual(e.classify_action(name), expected)

    def test_win32_hresults_only_from_actual_error_lines(self):
        raw = (
            b"test reference 0x80070005 SUCCESS, not a failing stage\n"
            b"CustomAction Startup returned actual error code 1603\n"
            b"CA: Error 1723. Private payload path C:\\users\\someone\\secret\n"
            b"Error code 0x80131700 found in runtime activation\n"
            b"Action ended 17:36:12: CA_RuntimeCheck. Return value 3.\n"
        )
        result = e.classify_msi_log(raw)
        self.assertEqual(result["action"], "CUSTOM_ACTION")
        self.assertIn("CLR_ACTIVATION", result["errors"])
        self.assertIn("CUSTOM_DLL_ACTION_FAILURE", result["errors"])
        self.assertNotIn("ACCESS_DENIED", result["errors"])
        self.assertNotIn("someone", str(result))

    def test_text_encoding_and_oversize(self):
        text = "Action ended 08:12:14: StartServices. Return value 3."
        self.assertEqual(e.classify_msi_log(text.encode("utf-16"))["action"], "SERVICE")
        self.assertFalse(e.classify_msi_log(b"x" * (e.MAX_FILE_BYTES + 1))["readable"])

    def test_private_temp_scan_prefers_nested_msi_not_generic_install_finalize(self):
        with TemporaryDirectory() as td:
            prefix = Path(td) / "prefix"
            temp = prefix / "drive_c" / "users" / "runner" / "AppData" / "Local" / "Temp"
            temp.mkdir(parents=True)
            (prefix / "system.reg").touch()
            (prefix / ".swcompat-netfx481-disposable").touch()
            setup = temp / "Microsoft .NET Framework 4 Setup_20130614_224227356.txt"
            setup.write_text("Installation failed 0x80070643\n")
            inner = temp / "Microsoft .NET Framework 4 Setup_20130614_224227356-MSI_netfx_Core_x64.msi.txt"
            inner.write_text(
                "Action ended 12:01:24: CA_RegisterCLR. Return value 3.\n"
                "Action ended 12:01:24: INSTALL. Return value 3.\n"
            )
            result = e.scan(prefix)
            self.assertTrue(e.validate(result))
            self.assertEqual(result["status"], "SCANNED")
            self.assertEqual(result["msi_files"], 1)
            self.assertEqual(result["primary_source"], "NESTED_MSI")
            self.assertEqual(result["msi_result"], "FAILURE_MARKER")
            self.assertEqual(result["first_failed_action_class"], "CUSTOM_ACTION")
            self.assertEqual(result["causality"], "ACTION_HINT_ONLY")
            self.assertEqual(result["errors"], ["GENERIC_MSI_FAILURE"])
            self.assertNotIn(str(prefix), str(result))
            self.assertNotIn("RegisterCLR", str(result))

    def test_untrusted_names_and_symlinks_do_not_leave_prefix(self):
        with TemporaryDirectory() as td:
            prefix = Path(td) / "prefix"
            temp = prefix / "drive_c" / "users" / "runner" / "Temp"
            temp.mkdir(parents=True)
            (prefix / "system.reg").touch()
            (prefix / ".swcompat-netfx481-disposable").touch()
            outside = Path(td) / "secret"
            outside.write_text("Action ended 12:00:00: CA_Fake. Return value 3.")
            link = temp / "Microsoft .NET Framework 4 Setup_20130614_224227356-MSI_netfx_Core_x64.msi.txt"
            try:
                link.symlink_to(outside)
            except OSError:
                return
            result = e.scan(prefix)
            self.assertEqual(result["status"], "NO_LOG")
            self.assertEqual(result["files_scanned"], 0)
            self.assertEqual(result["msi_result"], "NOT_FOUND")

    def test_invalid_enum_or_invented_claim_fails_closed(self):
        report = e.empty()
        self.assertTrue(e.validate(report))
        self.assertFalse(e.validate(dict(report, errors=["C:\\private\\setup.txt"])))
        self.assertFalse(e.validate(dict(report, first_failed_action_class="FIXED")))
        self.assertFalse(e.validate(dict(report, causality="ROOT_CAUSE_PROVEN")))
        self.assertFalse(e.validate(dict(report, files_scanned=True)))
        self.assertFalse(e.validate(dict(report, source_log="secret")))
        self.assertFalse(e.validate(dict(report, msi_result="FAILURE_MARKER")))


if __name__ == "__main__":
    unittest.main()
