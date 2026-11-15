"""Failure-action MSI type correlation must never export original identifiers."""
import unittest
from scripts import netfx40_msi_custom_type as t


class OriginalMsiCustomTypeTests(unittest.TestCase):
    def test_correlates_deferred_original_action_to_exact_wine_type(self):
        raw = (
            b'0170:trace:msi:ACTION_CustomAction Handling custom action '
            b'L"ServiceRegistrationVendor" (4c01 L"C:\\Private\\original.dll" L"PrivateTarget")\n'
            b'01ac:err:msi:execute_script Execution of script 0 halted; '
            b'action L"[SECRET<=>S-1-5-1<=>PRODUCT]ServiceRegistrationVendor" returned 1603\n'
            b'01ac:err:msi:ITERATE_Actions action L"InstallFinalize" returned 1603\n'
        )
        report = t.parse(raw)
        self.assertTrue(t.validate(report))
        self.assertEqual(report, {
            "status": "TRACE_MATCHED", "family": "DLL_BINARY", "base_type": 1,
            "execution": "DEFERRED", "impersonation": "NO_IMPERSONATE",
            "asynchronous": "SYNCHRONOUS", "ts_aware": True,
        })
        for secret in ("Private", "SECRET", "Vendor", "original.dll", "PRODUCT"):
            self.assertNotIn(secret, str(report))

    def test_exact_match_not_loose_substring_or_unrelated_action(self):
        raw = (
            b'0100:trace:msi:ACTION_CustomAction Handling custom action '
            b'L"InstallServices" (401 L"secret" L"secret")\n'
            b'0100:trace:msi:ACTION_CustomAction Handling custom action '
            b'L"ServiceVendorExtra" (402 L"secret" L"secret")\n'
            b'0100:err:msi:execute_script action L"ServiceVendor" returned 1603\n'
        )
        self.assertEqual(t.parse(raw)["status"], "TRACE_MISSING")
        direct = (
            b'0100:trace:msi:ACTION_CustomAction Handling custom action '
            b'L"ServiceVendor" (402 L"secret" L"secret")\n'
        )
        r = t.parse(raw + direct)
        self.assertEqual(r["status"], "TRACE_MATCHED")
        self.assertEqual(r["family"], "EXE_BINARY")
        self.assertEqual(r["execution"], "DEFERRED")
        self.assertTrue(t.validate(r))

    def test_ambiguous_types_and_no_private_data_in_status(self):
        raw = (
            b'0100:trace:msi:ACTION_CustomAction Handling custom action L"CA_PRIVATE" '
            b'(401 L"secret" L"secret")\n'
            b'0100:trace:msi:ACTION_CustomAction Handling custom action L"CA_PRIVATE" '
            b'(402 L"secret" L"secret")\n'
            b'0100:err:msi:execute_script action L"CA_PRIVATE" returned 1603\n'
        )
        r = t.parse(raw)
        self.assertEqual(r, t.empty("TRACE_AMBIGUOUS"))
        self.assertTrue(t.validate(r))
        self.assertNotIn("PRIVATE", str(r))
        self.assertEqual(t.parse(b"0100:err:msi:execute_script action L\"StartServices\" returned 1603\n"),
                         t.empty("NO_NONSTANDARD_FAILURE"))
        self.assertEqual(t.parse(raw, truncated=True), t.empty("CAPTURE_TRUNCATED"))

    def test_type_families_and_reject_false_success(self):
        for raw_type, family, phase in [
            (0x1, "DLL_BINARY", "IMMEDIATE"),
            (0x112, "EXE_FILE", "ROLLBACK"),
            (0x223, "SET_DIRECTORY", "COMMIT"),
            (0x407, "NESTED_MSI", "DEFERRED"),
            (0x63, "OTHER_TYPE", "IMMEDIATE"),
        ]:
            with self.subTest(raw_type=raw_type):
                raw = (
                    b'0100:trace:msi:ACTION_CustomAction Handling custom action '
                    b'L"VendorAction" (' + f"{raw_type:x}".encode("ascii") +
                    b' L"source" L"target")\n'
                    b'0100:err:msi:execute_script action L"VendorAction" returned 1603\n'
                )
                r = t.parse(raw)
                self.assertEqual(r["status"], "TRACE_MATCHED")
                self.assertEqual(r["family"], family)
                self.assertEqual(r["execution"], phase)
                self.assertTrue(t.validate(r))
                self.assertFalse(t.validate(dict(r, family="FORGED")))
                self.assertFalse(t.validate(dict(r, base_type=999)))
                self.assertFalse(t.validate(dict(r, private_action_name="VendorAction")))
        self.assertTrue(t.validate(t.empty()))
        self.assertFalse(t.validate(dict(t.empty(), status="TRACE_MATCHED")))
        self.assertFalse(t.validate(dict(t.empty(), ts_aware=1)))

    def test_only_allowlisted_bounded_relevant_lines(self):
        self.assertTrue(t.relevant(b'0100:err:msi:execute_script error\n'))
        self.assertTrue(t.relevant(b'0100:fixme:msi:ACTION_CustomAction warning\n'))
        self.assertTrue(t.relevant(b'0100:trace:msi:ACTION_CustomAction Handling custom action L"secret" (1)\n'))
        self.assertFalse(t.relevant(b'0100:trace:msi:ACTION_InstallFiles L"secret"\n'))
        self.assertFalse(t.relevant(b'0100:trace:service:OpenServiceW L"secret"\n'))
        self.assertFalse(t.relevant(b'0100:trace:msi:ACTION_CustomAction Handling custom action '
                                    + b"X" * (t.MAX_LINE_BYTES + 1)))


if __name__ == "__main__":
    unittest.main()
