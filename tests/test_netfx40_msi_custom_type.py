"""Failure-action MSI type correlation must never export original identifiers."""
import unittest
import io
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock
from scripts import netfx40_legacy as legacy
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
            "capture_reason": "NONE",
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
            (0x3f, "OTHER_TYPE", "IMMEDIATE"),
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

    def test_private_streaming_original_launcher_does_not_emit_original_action(self):
        original = (
            b'0140:trace:msi:ACTION_CustomAction Handling custom action '
            b'L"ServiceOriginalPrivate" (4c01 L"C:\\Private\\secret.dll" L"private target")\n'
            b'0140:err:msi:execute_script action L"ServiceOriginalPrivate" returned 1603\n'
        )
        proc = mock.Mock()
        proc.stderr = io.BytesIO(original)
        proc.wait.return_value = 0
        with TemporaryDirectory() as td:
            root = Path(td)
            fixture = root / "netfx40_win32_launch.exe"
            fixture.write_bytes(b"synthetic fixture")
            with (mock.patch.object(legacy, "validate_prefix"),
                  mock.patch.object(legacy.subprocess, "Popen", return_value=proc) as popen,
                  mock.patch.object(legacy, "parse_win32", return_value={"status": "EXIT_CAPTURED"})):
                r = legacy._run_traced(root / "wine", root, fixture, ["SYNTHETIC"], timeout=30)
            self.assertEqual(r["custom_action_type"]["family"], "DLL_BINARY")
            self.assertEqual(r["custom_action_type"]["execution"], "DEFERRED")
            self.assertEqual(r["wine_msi_errors"]["msi_error_lines"], 1)
            self.assertTrue(t.validate(r["custom_action_type"]))
            self.assertNotIn("ServiceOriginalPrivate", str(r))
            self.assertNotIn("secret.dll", str(r))
            self.assertNotIn("Private", str(r))
            self.assertIn("trace+msi", popen.call_args.kwargs["env"]["WINEDEBUG"])
            self.assertEqual(popen.call_args.kwargs["stderr"], legacy.subprocess.PIPE)

    def test_opt_in_private_store_never_enters_result(self):
        original = (
            b'0140:err:msi:execute_script action '
            b'L"[DATA<=>S-1-5<=>P]ServicePrivateReference" returned 1603\n'
        )
        proc = mock.Mock()
        proc.stderr = io.BytesIO(original)
        proc.wait.return_value = 0
        with TemporaryDirectory() as td:
            root = Path(td)
            fixture = root / "netfx40_win32_launch.exe"
            fixture.write_bytes(b"synthetic fixture")
            with (mock.patch.object(legacy, "validate_prefix"),
                  mock.patch.object(legacy.subprocess, "Popen", return_value=proc),
                  mock.patch.object(legacy, "parse_win32", return_value={
                      "status": "EXIT_CAPTURED", "category": "MSI_FATAL_ERROR"}),
                  mock.patch.object(legacy, "store_private_action") as saver):
                report = legacy._run_traced(root / "wine", root, fixture,
                                            ["SYNTHETIC"], timeout=30,
                                            store_private=True)
            saver.assert_called_once_with(root, b"ServicePrivateReference")
            self.assertNotIn("private_failed_action", report)
            self.assertNotIn("ServicePrivateReference", str(report))

    def test_timed_out_original_setup_cannot_assert_custom_action_type(self):
        original = (
            b'0140:trace:msi:ACTION_CustomAction Handling custom action L"Secret" '
            b'(4c01 L"private" L"private")\n'
            b'0140:err:msi:execute_script action L"Secret" returned 1603\n'
        )
        proc = mock.Mock()
        proc.stderr = io.BytesIO(original)
        proc.wait.side_effect = [__import__("subprocess").TimeoutExpired("wine", 30), 124]
        with TemporaryDirectory() as td:
            root = Path(td)
            fixture = root / "netfx40_win32_launch.exe"
            fixture.write_bytes(b"synthetic fixture")
            with (mock.patch.object(legacy, "validate_prefix"),
                  mock.patch.object(legacy.subprocess, "Popen", return_value=proc)):
                r = legacy._run_traced(root / "wine", root, fixture, ["SYNTHETIC"], timeout=30)
            proc.kill.assert_called_once()
            self.assertEqual(r["status"], "TIMEOUT")
            self.assertEqual(r["custom_action_type"], t.empty(
                "CAPTURE_TRUNCATED", reason="PROCESS_INCOMPLETE"))
            self.assertNotIn("Secret", str(r))

    def test_rollback_failure_never_becomes_private_install_action(self):
        only_rollback = (
            b'0100:err:msi:execute_script Execution of script 2 halted; '
            b'action L"RollbackServicePrivate" returned 1603\n'
        )
        self.assertIsNone(t._private_failed_action(only_rollback))
        installed = (
            b'0100:err:msi:execute_script Execution of script 0 halted; '
            b'action L"ServiceActualInstall" returned 1603\n'
        )
        self.assertEqual(t._private_failed_action(only_rollback + installed),
                         b"ServiceActualInstall")
        self.assertEqual(t._private_failed_action(installed + only_rollback),
                         b"ServiceActualInstall")

    def test_only_allowlisted_bounded_relevant_lines(self):
        self.assertTrue(t.relevant(b'0100:err:msi:execute_script error\n'))
        self.assertTrue(t.relevant(b'0100:fixme:msi:ACTION_CustomAction warning\n'))
        self.assertTrue(t.relevant(b'0100:trace:msi:ACTION_CustomAction Handling custom action L"ServiceSecret" (1 L"private" L"private")\n'))
        self.assertFalse(t.relevant(b'0100:trace:msi:ACTION_CustomAction Handling custom action L"other" (1 L"private" L"private")\n'))
        self.assertFalse(t.relevant(b'0100:trace:msi:ACTION_InstallFiles L"secret"\n'))
        self.assertFalse(t.relevant(b'0100:trace:service:OpenServiceW L"secret"\n'))
        self.assertFalse(t.relevant(b'0100:trace:msi:ACTION_CustomAction Handling custom action '
                                    + b"X" * (t.MAX_LINE_BYTES + 1)))


if __name__ == "__main__":
    unittest.main()
