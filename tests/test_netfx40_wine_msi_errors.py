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

    def test_actual_netfx_custom_action_pipe_failure_is_not_classed_as_msi_service(self):
        raw = (
            b'0374:err:msi:custom_client_thread failed to write to custom action client pipe: 232\n'
            b'015c:err:msi:custom_get_thread_return invalid Return Code 232\n'
            b'015c:err:msi:execute_script Execution of script 0 halted; action L"[C:\\users\\private\\file<=>S-1-5-21-0]CA_Regtlb_Microsoft_amd64" returned 1603\n'
            b'015c:err:msi:ITERATE_Actions Execution halted, action L"InstallFinalize" returned 1603\n'
            b'015c:fixme:msi:ACTION_CustomAction msidbCustomActionTypeTSAware not handled\n'
        )
        result = w.parse(raw)
        self.assertTrue(w.validate(result))
        self.assertEqual(result["msi_error_lines"], 4)
        self.assertEqual(result["classes"], [
            "CUSTOM_ACTION_PIPE_FAILURE", "CUSTOM_ACTION_RETURN_FAILURE",
            "MSI_ACTION_CUSTOM", "MSI_ACTION_FINALIZE",
            "MSI_TSAWARE_UNIMPLEMENTED",
        ])
        self.assertNotIn("private", str(result))
        self.assertNotIn("Regtlb", str(result))

    def test_specific_installfiles_or_registry_service_failure_precedes_finalization(self):
        raw = (
            b"0120:err:msi:ACTION_InstallFiles compressed file wasn't installed (L'PRIVATE')\n"
            b'0120:err:msi:execute_script Execution of script 0 halted; action L"InstallFiles" returned 1603\n'
            b'0120:err:msi:execute_script Execution of script 0 halted; action L"StartServices" returned 1603\n'
            b'0120:err:msi:execute_script Execution of script 0 halted; action L"WriteRegistryValues" returned 1603\n'
            b'0120:err:msi:ITERATE_Actions Execution halted, action L"InstallFinalize" returned 1603\n'
        )
        result = w.parse(raw)
        self.assertTrue(w.validate(result))
        self.assertIn("MSI_COMPRESSED_FILE_MISSING", result["classes"])
        self.assertIn("MSI_ACTION_SERVICE", result["classes"])
        self.assertIn("MSI_ACTION_REGISTRY", result["classes"])
        self.assertIn("MSI_ACTION_FINALIZE", result["classes"])

    def test_exact_original_msi_service_action_not_just_generic_service(self):
        raw = (
            b'01ac:err:msi:execute_script Execution of script 0 halted; action L"StartServices" returned 1603\n'
            b'01ac:err:msi:ITERATE_Actions Execution halted, action L"InstallFinalize" returned 1603\n'
        )
        r = w.parse(raw)
        self.assertTrue(w.validate(r))
        self.assertEqual(r["first_failed_action"], "START_SERVICES")
        self.assertEqual(r["service_action_failures"], ["START_SERVICES"])
        self.assertEqual(r["msi_error_lines"], 2)
        self.assertEqual(w.parse(raw.replace(b"StartServices", b"InstallServices"))["first_failed_action"],
                         "INSTALL_SERVICES")
        self.assertEqual(w.parse(raw.replace(b"StartServices", b"StopServices"))["first_failed_action"],
                         "STOP_SERVICES")
        # An arbitrary custom action with StartServices in its name is NOT a
        # system StartServices action and cannot justify an SCM hook.
        injected = raw.replace(b"StartServices", b"StartServices_Secret")
        r2 = w.parse(injected)
        self.assertEqual(r2["first_failed_action"], "OTHER_ACTION")
        self.assertEqual(r2["service_action_failures"], [])
        self.assertNotIn("Secret", str(r2))

    def test_script_failure_order_and_no_false_claim_without_action_name(self):
        raw = (
            b'01ac:err:msi:ITERATE_Actions action L"InstallFinalize" returned 1603\n'
            b'01ac:err:msi:execute_script action L"InstallServices" returned 1603\n'
            b'01ac:err:msi:execute_script action L"StartServices" returned 1603\n'
        )
        r = w.parse(raw)
        self.assertTrue(w.validate(r))
        self.assertEqual(r["first_failed_action"], "INSTALL_SERVICES")
        self.assertEqual(r["service_action_failures"],
                         ["INSTALL_SERVICES", "START_SERVICES"])
        only_finalize = w.parse(raw.splitlines(keepends=True)[0])
        self.assertEqual(only_finalize["first_failed_action"], "FINALIZE_ONLY")
        self.assertEqual(only_finalize["service_action_failures"], [])
        no_action = w.parse(b'0120:err:msi:CreateService failed with code 1055\n')
        self.assertEqual(no_action["first_failed_action"], "NOT_IDENTIFIED")
        self.assertEqual(no_action["service_action_failures"], [])
        self.assertTrue(w.validate(no_action))
        self.assertFalse(w.validate(dict(r, service_action_failures=["PRIVATE"])))
        self.assertFalse(w.validate(dict(r, first_failed_action="C:\\Users\\private")))
        self.assertFalse(w.validate(dict(r, service_action_failures=[])))

    def test_targeted_wine_fixme_is_a_warning_not_a_fatal_error(self):
        result = w.parse(
            b'0100:fixme:msi:ACTION_CustomAction msidbCustomActionTypeTSAware not handled\n'
        )
        self.assertEqual(result["msi_error_lines"], 0)
        self.assertEqual(result["classes"], ["MSI_TSAWARE_UNIMPLEMENTED"])
        self.assertTrue(w.validate(result))
        other = w.parse(b'0100:fixme:msi:internal_ui_handler not implemented\n')
        self.assertEqual(other["msi_error_lines"], 0)
        self.assertEqual(other["classes"], [])
        self.assertTrue(w.validate(other))

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
