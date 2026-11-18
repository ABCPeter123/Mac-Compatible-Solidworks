"""Prove missing-service hints cannot leak Microsoft MSI paths/action names."""
import unittest
from scripts import netfx48_msi_service_evidence as ev


class SignedMSIServiceEvidenceTests(unittest.TestCase):
    def test_missing_service_context_and_last_ngen_action(self):
        raw = (b"MSI (s) ... Action start 12:30:20: CA_NgenServiceVersionCheck.\n"
               b"Service clr_optimization_v4.0.30319_64 did not start\n"
               b"Error: 0x80070424 from private-vendor-path\n"
               b"MSI (s) ... Action start 12:31:45: CA_ServiceConfig.\n")
        report = ev.classify(raw)
        self.assertEqual(report, {
            "services_mentioned": ["CLR_OPTIMIZATION_64"],
            "services_near_missing_error": ["CLR_OPTIMIZATION_64"],
            "custom_action_detail": "SERVICE_CONFIG",
        })
        self.assertTrue(ev.valid(report))
        self.assertNotIn("private-vendor-path", str(report))
        self.assertNotIn("CA_Ngen", str(report))
        self.assertNotIn("clr_optimization_v4", str(report))

    def test_known_services_only_and_missing_error_not_assumed_causal(self):
        raw = (b"Notice wuauserv service may be queried\n"
               b"Action start 13:14:20: CA_NgenWork.\n"
               b"MSI service TrustedInstaller not found\n"
               b"Result 0x80070424\n"
               b"Some unrelated secret service name\n"
               b"Action start 13:15:20: PublishProduct.\n")
        report = ev.classify(raw)
        self.assertEqual(report["services_mentioned"],
                         ["TRUSTEDINSTALLER", "WUAUSERV"])
        self.assertEqual(report["services_near_missing_error"],
                         ["TRUSTEDINSTALLER", "WUAUSERV"])
        self.assertEqual(report["custom_action_detail"], "NGEN")
        self.assertNotIn("secret", str(report))

    def test_last_custom_type_remains_bounded(self):
        for action, want in (
            ("CA_Ngen", "NGEN"),
            ("CA_InstallAssembly", "ASSEMBLY"),
            ("CA_ServiceConfiguration", "SERVICE_CONFIG"),
            ("CA_RegAsm", "REGISTRATION"),
            ("CA_CustomUnknownPrivateString", "OTHER_CUSTOM"),
        ):
            with self.subTest(action=action):
                self.assertEqual(ev.classify(
                    f"Action start 11:12:34: {action}.".encode()
                )["custom_action_detail"], want)

    def test_invalid_input_never_exports_or_corrupts_evidence(self):
        self.assertEqual(ev.classify(b""), ev.blank())
        self.assertEqual(ev.classify(b"x" * (ev.MAX_FILE_BYTES + 1)), ev.blank())
        self.assertEqual(ev.classify(b"new custom service private_name\n"), ev.blank())
        self.assertFalse(ev.valid({**ev.blank(), "private_service": "secret"}))
        self.assertFalse(ev.valid({
            **ev.blank(), "services_mentioned": ["UNTRUSTED_NAME"],
        }))
        self.assertFalse(ev.valid({
            **ev.blank(), "services_near_missing_error": ["MSISERVER"],
        }))
        self.assertFalse(ev.valid({
            **ev.blank(), "custom_action_detail": "PRIVATE",
        }))
        self.assertEqual(ev.classify(
            b"Service TrustedInstaller shown without an error."
        )["services_near_missing_error"], [])


if __name__ == "__main__":
    unittest.main()
