import unittest
from scripts.wow64_report import CHECKS, assess


class Wow64Tests(unittest.TestCase):
    def test_requires_32bit_process_and_actual_interfaces(self):
        good = {"PROCESS_BITS": "32", **{x: "PRESENT" for x in CHECKS}}
        self.assertTrue(assess(good, "macos")["passed"])
        good["PROCESS_BITS"] = "64"
        self.assertFalse(assess(good, "macos")["passed"])

    def test_missing_com_is_failure(self):
        x = {"PROCESS_BITS": "32", **{key: "PRESENT" for key in CHECKS}}
        x["SHELLLINK_COM"] = "ABSENT"
        self.assertFalse(assess(x, "wine")["passed"])

    def test_vc_registry_absence_is_observational(self):
        x = {"PROCESS_BITS": "32", "VC_X86_REGISTRY": "ABSENT",
             **{key: "PRESENT" for key in CHECKS}}
        report = assess(x, "wine")
        self.assertEqual(report["vc_x86_registry_indicator"], "ABSENT")
        self.assertTrue(report["passed"])
        self.assertIn("does not test", report["scope"])


if __name__ == "__main__":
    unittest.main()
