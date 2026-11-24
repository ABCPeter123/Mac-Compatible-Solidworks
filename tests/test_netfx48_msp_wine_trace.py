"""Synthetic private Wine MSI trace fixtures. NEVER upload actual vendor logs."""
from unittest import TestCase

from scripts import netfx48_msp_wine_trace as t


class OriginalMSPPrivateWineMSIErrors(TestCase):
    def test_original_script_1603_and_later_rollback_are_not_confused(self):
        raw = (
            b'003c:err:msi:execute_script Execution of script 0 halted; '
            b'action L"CA_Ngen_X64_PRIVATE_PATH_GUID" returned 1603\n'
            b'0040:err:msi:execute_script Execution of script 2 halted; '
            b'action L"[SchedServiceConfig<=>S-1-5-21-SECRET]RollbackServiceConfig" '
            b'returned 1603\n'
            b'0040:err:msi:ITERATE_Actions Execution halted, '
            b'action L"InstallFinalize" returned 1603\n'
        )
        result = t.classify(raw)
        self.assertTrue(t.valid(result))
        self.assertEqual(result, {
            "status": "CLASSIFIED",
            "first_forward_action": "NGEN",
            "first_forward_return": "WIN32_1603",
            "first_rollback_action": "SERVICE",
            "first_rollback_return": "WIN32_1603",
            "signals": ["INSTALL_SCRIPT_HALTED", "MSI_SERVICE_OPERATION_FAILURE",
                        "ROLLBACK_SCRIPT_HALTED"],
        })
        self.assertNotIn("SECRET", str(result))
        self.assertNotIn("PRIVATE_PATH", str(result))
        self.assertNotIn("GUID", str(result))
        self.assertNotIn("SchedServiceConfig", str(result))

    def test_actual_wine_quoted_command_inside_deferred_msi_action_is_parsed(self):
        # Wine MSI commonly logs original deferred actions with nested
        # executable/TLB quotes, a private SID, and a trailing CA identifier.
        # These are synthetic placeholders: no original vendor path/data.
        trace = (
            b'015c:err:msi:execute_script Execution of script 0 halted; '
            b'action L"[\\"C:\\PRIVATE_PATH\\Framework64\\regtlibv12.exe\\" '
            b'\\"C:\\PRIVATE_PATH\\Microsoft.JScript.tlb\\";11<=>S-1-5-21-SECRET'
            b'<=>{PRIVATE-GUID}]CA_Regtlb_JScript_amd64" returned 1603\n'
            b'015c:err:msi:execute_script Execution of script 2 halted; '
            b'action L"[SchedServiceConfig<=>S-1-5-21-SECRET'
            b'<=>{PRIVATE-GUID}]RollbackServiceConfig" returned 1603\n'
        )
        result = t.classify(trace)
        self.assertEqual(result["status"], "CLASSIFIED")
        self.assertEqual(result["first_forward_action"], "TYPE_LIBRARY")
        self.assertEqual(result["first_forward_return"], "WIN32_1603")
        self.assertEqual(result["first_rollback_action"], "SERVICE")
        self.assertEqual(result["first_rollback_return"], "WIN32_1603")
        self.assertEqual(result["signals"], [
            "INSTALL_SCRIPT_HALTED",
            "MSI_SERVICE_OPERATION_FAILURE",
            "ROLLBACK_SCRIPT_HALTED",
        ])
        self.assertTrue(t.valid(result))
        for private in ("PRIVATE_PATH", "PRIVATE-GUID", "SECRET",
                        "JScript", "regtlibv12", "SchedServiceConfig"):
            self.assertNotIn(private, str(result))

    def test_payload_text_cannot_override_trailing_action_name(self):
        # Private command text can mention NGen while the actual action is
        # registry registration. A classifier must use the trailing name.
        raw = (
            b'0009:err:msi:execute_script Execution of script 0 halted; '
            b'action L"[\\"C:\\PRIVATE\\ngen.exe\\" '
            b'\\"C:\\PRIVATE\\thing.tlb\\";11<=>SECRET]'
            b'CA_Regtlb_amd64" returned 1603\n'
        )
        result = t.classify(raw)
        self.assertEqual(result["first_forward_action"], "TYPE_LIBRARY")
        self.assertNotEqual(result["first_forward_action"], "NGEN")
        self.assertTrue(t.valid(result))
        self.assertNotIn("SECRET", str(result))
        no_identifier = t.classify(
            b'0009:err:msi:execute_script Execution of script 0 halted; '
            b'action L"[C:\\PRIVATE\\ngen.exe]" returned 1603\n')
        self.assertEqual(no_identifier["first_forward_action"], "UNKNOWN")
        self.assertTrue(t.valid(no_identifier))

    def test_wine_custom_action_pipe_failure_is_reported_without_private_data(self):
        # A broken Wine MSI custom-action pipe is distinct from the vendor
        # action that later returns 1603, and from rollback side effects.
        raw = (
            b'015c:err:msi:custom_client_thread failed to write to '
            b'custom action client pipe: 232 PRIVATE_SID\n'
            b'015c:err:msi:custom_get_thread_return Invalid Return Code 232\n'
            b'015c:err:msi:execute_script Execution of script 0 halted; '
            b'action L"CA_Regasm_PRIVATE_GUID" returned 1603\n'
            b'015c:err:msi:execute_script Execution of script 2 halted; '
            b'action L"RollbackServiceConfig_PRIVATE_PATH" returned 1603\n'
        )
        result = t.classify(raw)
        self.assertTrue(t.valid(result))
        self.assertEqual(result["first_forward_action"], "REGISTRY")
        self.assertEqual(result["first_rollback_action"], "SERVICE")
        self.assertEqual(result["signals"], [
            "INSTALL_SCRIPT_HALTED", "MSI_CUSTOM_ACTION_PIPE_FAILURE",
            "MSI_CUSTOM_ACTION_RETURN_INVALID", "MSI_SERVICE_OPERATION_FAILURE",
            "ROLLBACK_SCRIPT_HALTED",
        ])
        for private in ("PRIVATE_SID", "PRIVATE_GUID", "PRIVATE_PATH"):
            self.assertNotIn(private, str(result))

    def test_plain_type_library_action_is_distinct_from_other_registry_action(self):
        raw = (
            b'015c:err:msi:execute_script Execution of script 0 halted; '
            b'action L"CA_Regtlb_amd64" returned 1603\n'
        )
        self.assertEqual(t.classify(raw)["first_forward_action"], "TYPE_LIBRARY")
        self.assertTrue(t.valid(t.classify(raw)))

    def test_oversize_deferred_action_is_not_fabricated_or_leaked(self):
        oversized = (
            b'003c:err:msi:execute_script Execution of script 0 halted; '
            b'action L"[' + b'P' * 2500 +
            b']CA_Regtlb_amd64" returned 1603\n'
        )
        result = t.classify(oversized)
        self.assertEqual(result["first_forward_action"], "NOT_SEEN")
        self.assertEqual(result["signals"], ["MSI_UNATTRIBUTED_SCRIPT_ENGINE"])
        self.assertTrue(t.valid(result))
        self.assertNotIn("PPPP", str(result))

    def test_first_forward_error_wins_over_later_finalization_cascade(self):
        raw = (
            b'1111:err:msi:execute_script Execution of script 0 halted; '
            b'action L"InstallFiles" returned 1603\n'
            b'2222:err:msi:execute_script Execution of script 0 halted; '
            b'action L"CA_Ngen_X64" returned 1603\n'
            b'0001:err:msi:extract_cabinet_stream FDICopy failed\n'
        )
        report = t.classify(raw)
        self.assertEqual(report["first_forward_action"], "CABINET")
        self.assertEqual(report["first_rollback_action"], "NOT_SEEN")
        self.assertEqual(report["signals"],
                         ["INSTALL_SCRIPT_HALTED", "MSI_CABINET_FAILURE"])
        self.assertTrue(t.valid(report))

    def test_unknown_script_is_not_a_forward_failure(self):
        s = (b'003c:err:msi:execute_script Execution of script 8 halted; '
             b'action L"CA_PRIVATE_SID" returned 1642\n')
        report = t.classify(s)
        self.assertEqual(report["status"], "CLASSIFIED")
        self.assertEqual(report["first_forward_action"], "NOT_SEEN")
        self.assertEqual(report["first_rollback_action"], "NOT_SEEN")
        self.assertEqual(report["signals"], ["MSI_UNATTRIBUTED_SCRIPT_ENGINE"])
        self.assertTrue(t.valid(report))

    def test_unattributed_wine_error_subsystems_stay_fixed_and_private(self):
        # This is the exact diagnostic gap after an authentic signed MSP
        # returned full 1603 without a recognized script-0 action.
        cases = (
            (b'0011:err:msi:ITERATE_Actions Execution halted, '
             b'action L"InstallFinalize" returned 1603\n',
             "MSI_UNATTRIBUTED_SCRIPT_ENGINE"),
            (b'0011:err:msi:patch_set_offsets private-package-path\n',
             "MSI_UNATTRIBUTED_PATCH_ENGINE"),
            (b'0011:err:msi:private_unrecognized PRIVATE_GUID_SID\n',
             "MSI_UNATTRIBUTED_OTHER"),
        )
        for raw, want in cases:
            with self.subTest(source=want):
                result = t.classify(raw)
                self.assertTrue(t.valid(result))
                self.assertEqual(result["first_forward_action"], "NOT_SEEN")
                self.assertEqual(result["first_rollback_action"], "NOT_SEEN")
                self.assertEqual(result["signals"], [want])
                self.assertNotIn("PRIVATE", str(result))
                self.assertNotIn("GUID", str(result))
        # A later finalization cascade must not hide an earlier Wine
        # subsystem error, and neither is asserted to be the root cause.
        two = t.classify(
            b'0011:err:msi:patch_set_offsets private-patch\n'
            b'0011:err:msi:ITERATE_Actions Execution halted, '
            b'action L"InstallFinalize" returned 1603\n')
        self.assertEqual(two["signals"], [
            "MSI_UNATTRIBUTED_PATCH_ENGINE", "MSI_UNATTRIBUTED_SCRIPT_ENGINE",
        ])
        self.assertTrue(t.valid(two))

    def test_no_wine_msi_errors_is_not_framework_success(self):
        for raw in (b"", b'0000:fixme:msi:install_secret PRIVATE\n',
                    b'0000:err:ole:private_path\n'):
            r = t.classify(raw)
            self.assertEqual(r, t.blank("NO_MSI_ERRORS"))
            self.assertTrue(t.valid(r))
        self.assertTrue(t.valid(t.blank()))
        self.assertFalse(t.valid({**t.blank(), "signals": ["PRIVATE"]}))

    def test_only_fixed_categories_and_strict_private_limits(self):
        for action, want in (
            ("SchedServiceConfig PRIVATE_SID", "SERVICE"),
            ("CA_Ngen_X64", "NGEN"),
            ("MsiPublishAssemblies", "ASSEMBLY"),
            ("CA_RegAsm_X64", "REGISTRY"),
            ("Some_private_action_name", "UNKNOWN"),
            ("CA_CustomPrivateIdentity", "CUSTOM"),
        ):
            with self.subTest(action=action):
                raw = (f'0011:err:msi:execute_script Execution of script 0 halted; '
                       f'action L"{action}" returned 1603\n').encode()
                r = t.classify(raw)
                self.assertEqual(r["first_forward_action"], want)
                self.assertEqual(r["first_forward_return"], "WIN32_1603")
                self.assertNotIn(action, str(r))
                self.assertTrue(t.valid(r))
        self.assertEqual(t.classify(b"a" * (t.MAX_BYTES + 1)),
                         t.blank("TOO_LARGE"))
        self.assertEqual(t.classify(b"0011:err:msi:foo " + b"a" * 9000),
                         t.blank("NO_MSI_ERRORS"))
        bad = {**t.blank("CLASSIFIED"),
               "first_forward_action": "NGEN",
               "first_forward_return": "WIN32_1603"}
        self.assertFalse(t.valid(bad))
        self.assertFalse(t.valid({**t.blank(), "first_forward_action": []}))
        self.assertFalse(t.valid({**t.blank(), "signals": ["INSTALL_SCRIPT_HALTED"]}))
