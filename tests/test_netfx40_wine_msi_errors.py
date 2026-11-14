"""Narrow Wine MSI error channel must emit only fixed safe classes."""
import unittest
from scripts import netfx40_wine_msi_errors as w


class WineMsiErrorTests(unittest.TestCase):
    def test_detect_old_upstream_reported_cabinet_and_action_dll_failures(self):
        raw = (
            b'0128:err:msi:ready_media cabinet not found: L"I:\\hidden\\netfx_core.mzz"\n'
            b'0128:err:msi:ACTION_InstallFiles Failed to ready media for L"dfshim"\n'
            b'0238:err:msi:__wine_msi_call_dll_function failed to load dll L"C:\\secret\\msi5857.tmp" (193)\n'
            b'0128:err:msi:execute_script Execution of script 0 halted; action L"InstallFinalize" returned 1603\n'
        )
        report = w.parse(raw)
        self.assertTrue(w.validate(report))
        self.assertEqual(report["classes"], [
            "CABINET_MEDIA_MISSING", "CUSTOM_ACTION_BAD_EXE",
            "CUSTOM_ACTION_DLL_LOAD", "MSI_ACTION_FINALIZE",
            "MSI_ACTION_INSTALLFILES", "NETFX_CORE_CAB_MISSING",
        ])
        self.assertEqual(report["msi_error_lines"], 4)
        self.assertNotIn("secret", str(report))
        self.assertNotIn("msi5857", str(report))

    def test_cabinet_extraction_is_not_the_same_as_missing_media(self):
        raw = (
            b'0150:err:msi:extract_cabinet FDICopy failed\n'
            b'0150:err:msi:ACTION_InstallFiles Failed to extract cabinet: L"netfx_core.mzz"\n'
        )
        r = w.parse(raw)
        self.assertTrue(w.validate(r))
        self.assertEqual(r["classes"], ["CABINET_EXTRACT_FAILED"])
        self.assertEqual(r["msi_error_lines"], 2)

    def test_does_not_trigger_on_text_without_actual_wine_err_msi(self):
        data = (
            b'xxx:fixme:msi:ready_media cabinet not found: L"C:\\netfx_core.mzz"\n'
            b"Action ended 12:00:00: InstallFiles. Return value 3.\n"
            b"hello err:msi:not-an-actual-failure\n"
        )
        result = w.parse(data)
        self.assertTrue(w.validate(result))
        self.assertEqual(result["msi_error_lines"], 0)
        self.assertEqual(result["classes"], [])

    def test_other_errors_remain_generic_not_raw(self):
        result = w.parse(b"0100:err:msi:someprivate error C:\\fake\\secret\n")
        self.assertEqual(result["classes"], ["OTHER_MSI_ERROR"])
        self.assertNotIn("secret", str(result))

    def test_truncation_is_never_reported_as_no_failures(self):
        r = w.parse(b"x" * (w.MAX_BYTES + 1))
        self.assertEqual(r["status"], "TRUNCATED")
        self.assertEqual(r["classes"], [])
        self.assertTrue(w.validate(r))
        bad = dict(r, classes=["NETFX_CORE_CAB_MISSING"])
        self.assertFalse(w.validate(bad))

    def test_only_predefined_values_and_counts(self):
        r = w.empty()
        self.assertTrue(w.validate(r))
        self.assertFalse(w.validate(dict(r, classes=["/Users/private"])))
        self.assertFalse(w.validate(dict(r, status="HOOK_REQUIRED")))
        self.assertFalse(w.validate(dict(r, msi_error_lines=1)))
        self.assertFalse(w.validate(dict(r, raw_wine="secret")))


if __name__ == "__main__":
    unittest.main()
