"""Synthetic private Wine MSI trace fixtures. NEVER upload actual vendor logs."""
from io import BytesIO
from unittest import TestCase, mock

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
            "signals": ["INSTALL_SCRIPT_HALTED", "MSI_SEQUENCE_ACTION_FINALIZE", "MSI_SEQUENCE_RETURN_WIN32_1603",
                        "MSI_SERVICE_OPERATION_FAILURE", "ROLLBACK_SCRIPT_HALTED"],
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
                expected = [want]
                if b'ITERATE_Actions Execution halted' in raw:
                    expected += ["MSI_SEQUENCE_ACTION_FINALIZE", "MSI_SEQUENCE_RETURN_WIN32_1603"]
                self.assertEqual(result["signals"], sorted(expected))
                self.assertNotIn("PRIVATE", str(result))
                self.assertNotIn("GUID", str(result))
        # A later finalization cascade must not hide an earlier Wine
        # subsystem error, and neither is asserted to be the root cause.
        two = t.classify(
            b'0011:err:msi:patch_set_offsets private-patch\n'
            b'0011:err:msi:ITERATE_Actions Execution halted, '
            b'action L"InstallFinalize" returned 1603\n')
        self.assertEqual(two["signals"], [
            "MSI_SEQUENCE_ACTION_FINALIZE", "MSI_SEQUENCE_RETURN_WIN32_1603",
            "MSI_UNATTRIBUTED_PATCH_ENGINE", "MSI_UNATTRIBUTED_SCRIPT_ENGINE",
        ])
        self.assertTrue(t.valid(two))

    def test_immediate_sequence_failure_is_not_deferred_failure(self):
        for name, category in (("CA_ScheduleCacheGACAssembly_PRIVATE", "ASSEMBLY"),
                               ("InstallValidate", "VALIDATE"),
                               ("InstallFinalize", "FINALIZE"),
                               ("CA_PrivateThing", "CUSTOM")):
            with self.subTest(category=category):
                raw = (
                    f'0011:err:msi:ITERATE_Actions Execution halted, action L"{name}" returned 1603\n'
                    '0011:err:msi:ITERATE_Actions Execution halted, action L"InstallFinalize" returned 5\n'
                ).encode("ascii")
                report = t.classify_stream(BytesIO(raw))
                self.assertTrue(t.valid(report))
                self.assertEqual(report["first_forward_action"], "NOT_SEEN")
                self.assertIn("MSI_SEQUENCE_ACTION_" + category, report["signals"])
                self.assertIn("MSI_SEQUENCE_RETURN_WIN32_1603", report["signals"])
                self.assertNotIn("MSI_SEQUENCE_RETURN_OTHER_NONZERO", report["signals"])
                self.assertNotIn("PRIVATE", str(report))

    def test_commit_and_finalize_failure_remain_distinct_from_forward_and_rollback(self):
        raw = (
            b'0001:err:msi:ACTION_InstallFinalize Failed to install patched assembly\n'
            b'0001:err:msi:execute_script Execution of script 1 halted; action L"CA_Ngen_PRIVATE" returned 1603\n'
            b'0001:err:msi:ITERATE_Actions Execution halted, action L"InstallFinalize" returned 1603\n'
        )
        report = t.classify(raw)
        self.assertTrue(t.valid(report))
        self.assertEqual(report["first_forward_action"], "NOT_SEEN")
        self.assertEqual(report["first_rollback_action"], "NOT_SEEN")
        for signal in ("MSI_FINALIZE_PATCHED_ASSEMBLY_FAILURE",
                       "MSI_COMMIT_SCRIPT_HALTED", "MSI_COMMIT_ACTION_NGEN",
                       "MSI_COMMIT_RETURN_WIN32_1603", "MSI_SEQUENCE_ACTION_FINALIZE"):
            self.assertIn(signal, report["signals"])
        self.assertNotIn("PRIVATE", str(report))

    def test_trace_action_prior_to_finalize_is_only_observational_context(self):
        # Wine action.c traces action dispatch before the generic finalizer
        # logs 1603. The action context does not establish causation.
        raw = (
            b'0011:trace:msi:ACTION_PerformAction Performing action '
            b'(L"CA_Regtlb_Synthetic_amd64")\n'
            b'0011:trace:msi:ACTION_PerformAction Performing action '
            b'(L"InstallFinalize")\n'
            b'0011:err:msi:ITERATE_Actions Execution halted, '
            b'action L"InstallFinalize" returned 1603\n'
        )
        report = t.classify(raw)
        self.assertTrue(t.valid(report))
        self.assertEqual(report["first_forward_action"], "NOT_SEEN")
        self.assertEqual(report["signals"], [
            "MSI_SEQUENCE_ACTION_FINALIZE", "MSI_SEQUENCE_RETURN_WIN32_1603",
            "MSI_TRACE_FINALIZE_OBSERVED",
            "MSI_TRACE_NONFINAL_TYPE_LIBRARY",
            "MSI_UNATTRIBUTED_SCRIPT_ENGINE",
        ])
        self.assertNotIn("Regtlb", str(report))
        self.assertNotIn("Synthetic", str(report))

    def test_trace_action_category_ignores_private_nested_command_payload(self):
        raw = (
            b'0011:trace:msi:ACTION_PerformAction Performing action '
            b'(L"[\\"C:\\PRIVATE\\ngen.exe\\";11<=>S-1-5-21-SECRET]'
            b'CA_Regtlb_private_amd64")\n'
            b'0011:err:msi:ITERATE_Actions Execution halted, '
            b'action L"InstallFinalize" returned 1603\n'
        )
        report = t.classify(raw)
        self.assertTrue(t.valid(report))
        self.assertIn("MSI_TRACE_NONFINAL_TYPE_LIBRARY", report["signals"])
        self.assertNotIn("MSI_TRACE_NONFINAL_NGEN", report["signals"])
        for private in ("PRIVATE", "SECRET", "Regtlb"):
            self.assertNotIn(private, str(report))
        no_error = t.classify(raw.split(b'0011:err:msi:')[0])
        self.assertEqual(no_error, t.blank("NO_MSI_ERRORS"))

    def test_native_registration_before_original_msp_is_fixed_enum_only(self):
        header = (
            b"SWCOMPAT_MSI_REG_SCHEMA=1\n"
            b"SWCOMPAT_MSI_REG_STATUS=OBSERVED\n"
            b"SWCOMPAT_MSI_REG_PRODUCT=INSTALLED\n"
            b"SWCOMPAT_MSI_REG_CACHE=MISSING\n"
        )
        trace = (
            b'011c:err:msi:ITERATE_Actions Execution halted, '
            b'action L"InstallFinalize" returned 1603\n'
        )
        report = t.classify_stream(BytesIO(header + trace))
        self.assertTrue(t.valid(report))
        self.assertEqual(report["signals"], [
            "MSI_REG_CACHE_MISSING",
            "MSI_REG_PRODUCT_INSTALLED",
            "MSI_SEQUENCE_ACTION_FINALIZE", "MSI_SEQUENCE_RETURN_WIN32_1603",
            "MSI_UNATTRIBUTED_SCRIPT_ENGINE",
        ])
        self.assertNotIn("ProductCode", str(report))
        self.assertNotIn("swcompat-original", str(report))
        # A vendor-supplied line with invalid enum is never exported.
        poisoned = header.replace(b"INSTALLED", b"PRIVATE-PRODUCT-ID")
        result = t.classify_stream(BytesIO(poisoned + trace))
        self.assertTrue(t.valid(result))
        self.assertNotIn("MSI_REG_PRODUCT_INSTALLED", result["signals"])
        self.assertNotIn("PRIVATE", str(result))

    def test_signed_msi_registration_unavailable_does_not_fabricate_success(self):
        header = (
            b"SWCOMPAT_MSI_REG_SCHEMA=1\n"
            b"SWCOMPAT_MSI_REG_STATUS=OPEN_FAILED\n"
            b"SWCOMPAT_MSI_REG_PRODUCT=UNKNOWN\n"
            b"SWCOMPAT_MSI_REG_CACHE=UNKNOWN\n"
        )
        report = t.classify_stream(BytesIO(header))
        self.assertEqual(report["status"], "CLASSIFIED")
        self.assertEqual(report["signals"], ["MSI_REG_QUERY_FAILED"])
        self.assertTrue(t.valid(report))
        no_registration = t.classify_stream(BytesIO(b'0009:err:msi:ITERATE_Actions Failed\n'))
        self.assertNotIn("MSI_REG_QUERY_FAILED", no_registration["signals"])

    def test_actual_msi_patch_sequence_contexts_are_not_vendor_success(self):
        seq = (
            b"SWCOMPAT_MSI_SEQ_SCHEMA=1\n"
            b"SWCOMPAT_MSI_SEQ_STATUS=OBSERVED\n"
            b"SWCOMPAT_MSI_SEQ_USER=APPLICABLE\n"
            b"SWCOMPAT_MSI_SEQ_MACHINE=PRODUCT_UNKNOWN\n"
        )
        reg = (
            b"SWCOMPAT_MSI_REG_SCHEMA=1\n"
            b"SWCOMPAT_MSI_REG_STATUS=OBSERVED\n"
            b"SWCOMPAT_MSI_REG_PRODUCT=INSTALLED\n"
            b"SWCOMPAT_MSI_REG_CACHE=PRESENT\n"
        )
        fail = (
            b'0022:err:msi:ITERATE_Actions Execution halted, '
            b'action L"InstallFinalize" returned 1603\n'
        )
        result = t.classify_stream(BytesIO(reg + seq + fail))
        self.assertTrue(t.valid(result))
        self.assertEqual(result["signals"], [
            "MSI_REG_CACHE_PRESENT", "MSI_REG_PRODUCT_INSTALLED",
            "MSI_SEQUENCE_ACTION_FINALIZE", "MSI_SEQUENCE_RETURN_WIN32_1603",
            "MSI_SEQ_MACHINE_PRODUCT_UNKNOWN", "MSI_SEQ_USER_APPLICABLE",
            "MSI_UNATTRIBUTED_SCRIPT_ENGINE",
        ])
        self.assertEqual(result["first_forward_action"], "NOT_SEEN")
        self.assertNotIn("PATCH.msp", str(result))
        self.assertNotIn("ProductCode", str(result))
        # API *eligibility* does not upgrade original signed MSP Win32 1603.
        self.assertIn("MSI_UNATTRIBUTED_SCRIPT_ENGINE", result["signals"])

    def test_msi_sequence_invalid_private_values_cannot_leak(self):
        trace = (
            b"SWCOMPAT_MSI_SEQ_SCHEMA=1\n"
            b"SWCOMPAT_MSI_SEQ_STATUS=OBSERVED\n"
            b"SWCOMPAT_MSI_SEQ_USER=PRIVATE-PATCH-ID\n"
            b"SWCOMPAT_MSI_SEQ_MACHINE=PRODUCT_UNKNOWN\n"
        )
        result = t.classify_stream(BytesIO(trace))
        self.assertEqual(result, t.blank("NO_MSI_ERRORS"))
        self.assertTrue(t.valid(result))
        self.assertNotIn("PRIVATE", str(result))
        no_run = (
            b"SWCOMPAT_MSI_SEQ_SCHEMA=1\n"
            b"SWCOMPAT_MSI_SEQ_STATUS=NOT_RUN\n"
            b"SWCOMPAT_MSI_SEQ_USER=UNKNOWN\n"
            b"SWCOMPAT_MSI_SEQ_MACHINE=UNKNOWN\n"
        )
        self.assertEqual(t.classify_stream(BytesIO(no_run)),
                         t.blank("NO_MSI_ERRORS"))

    def test_stream_scans_early_original_msp_error_beyond_eight_megabyte_tail(self):
        early = (
            b'0001:trace:msi:ACTION_PerformAction Performing action '
            b'(L"CA_Regtlb_PRIVATE_amd64")\n'
            b'0001:err:msi:ITERATE_Actions Execution halted, '
            b'action L"InstallFinalize" returned 1603\n'
        )
        raw = early + b'X' * (9 * 1024 * 1024)
        self.assertEqual(t.classify(raw), t.blank("TOO_LARGE"))
        report = t.classify_stream(BytesIO(raw))
        self.assertEqual(report["status"], "CLASSIFIED")
        self.assertEqual(report["signals"], [
            "MSI_SEQUENCE_ACTION_FINALIZE", "MSI_SEQUENCE_RETURN_WIN32_1603",
            "MSI_TRACE_NONFINAL_TYPE_LIBRARY",
            "MSI_UNATTRIBUTED_SCRIPT_ENGINE",
        ])
        self.assertTrue(t.valid(report))
        self.assertNotIn("PRIVATE", str(report))

    def test_post_failure_rollback_trace_cannot_replace_original_action_context(self):
        stream = (
            b'0011:trace:msi:ACTION_PerformAction Performing action '
            b'(L"CA_Regtlb_private_amd64")\n'
            b'0011:trace:msi:ACTION_PerformAction Performing action '
            b'(L"InstallFinalize")\n'
            b'0011:err:msi:ITERATE_Actions Execution halted, '
            b'action L"InstallFinalize" returned 1603\n'
            b'0011:trace:msi:ACTION_PerformAction Performing action '
            b'(L"CA_Ngen_Rollback_private")\n'
        )
        result = t.classify_stream(BytesIO(stream))
        self.assertIn("MSI_TRACE_NONFINAL_TYPE_LIBRARY", result["signals"])
        self.assertNotIn("MSI_TRACE_NONFINAL_NGEN", result["signals"])
        self.assertTrue(t.valid(result))
        self.assertNotIn("private", str(result))

    def test_stream_matches_bounded_bytes_and_skips_oversized_private_lines(self):
        valid = (
            b'0001:err:msi:execute_script Execution of script 0 halted; '
            b'action L"CA_Ngen_X64" returned 1603\n'
        )
        self.assertEqual(t.classify_stream(BytesIO(valid)), t.classify(valid))
        too_long = (
            b'0001:err:msi:execute_script Execution of script 0 halted; '
            + b'PRIVATE' * 3000 + b'\n'
        )
        self.assertEqual(
            t.classify_stream(BytesIO(too_long)),
            t.blank("NO_MSI_ERRORS"))
        with mock.patch.object(t, "MAX_STREAM_BYTES", 128):
            self.assertEqual(
                t.classify_stream(BytesIO(valid + b'X' * 200)),
                t.blank("TOO_LARGE"))
        self.assertTrue(t.valid(t.classify_stream(BytesIO(b''))))

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
