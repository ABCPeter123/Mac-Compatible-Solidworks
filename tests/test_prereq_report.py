import json
from pathlib import Path
import unittest
from scripts.prereq_report import make_report, markdown_report, parse_probe

CATALOG = {
    "product": "SOLIDWORKS Design 2026",
    "requirements": [
        {"id": "msi", "name": "MSI", "classification": "compatibility_probe",
         "probe": "MSI_EXPORTS", "verification": "api_exports_only"},
        {"id": "netfx", "name": ".NET", "classification": "required",
         "probe": "NETFX481_REGISTRY", "verification": "registry_indication"},
        {"id": "webview2", "name": "WebView2", "classification": "listed_prerequisite",
         "probe": None, "verification": "not_tested"},
    ],
}

class PrereqReportTests(unittest.TestCase):
    def test_accepts_completed_probe(self):
        data = parse_probe("SWCOMPAT_PREREQ_SCHEMA=1\nSWCOMPAT_PREREQ_MSI_EXPORTS=PRESENT\n"
                           "SWCOMPAT_PREREQ_PROBE=PASS\n")
        self.assertEqual(data["MSI_EXPORTS"], "PRESENT")

    def test_rejects_incomplete_probe(self):
        for sample in ("", "SWCOMPAT_PREREQ_SCHEMA=1\n", "SWCOMPAT_PREREQ_PROBE=PASS\n"):
            with self.subTest(sample=sample), self.assertRaises(ValueError):
                parse_probe(sample)

    def test_does_not_treat_missing_registry_as_application_failure(self):
        result = make_report({"PROBE": "PASS", "SCHEMA": "1", "MSI_EXPORTS": "PRESENT",
                              "NETFX481_REGISTRY": "ABSENT"}, CATALOG, host="wine")
        self.assertTrue(result["probe_executed"])
        self.assertEqual(result["runtime_signals"][1]["signal"], "ABSENT")
        self.assertEqual(result["runtime_signals"][2]["signal"], "NOT_TESTED")
        self.assertIn("do not demonstrate", result["warning"])

    def test_unknown_values_do_not_become_present(self):
        result = make_report({"MSI_EXPORTS": "UNKNOWN_STATE"}, CATALOG, host="test")
        self.assertEqual(result["runtime_signals"][0]["signal"], "UNKNOWN")

    def test_markdown(self):
        result = make_report({"MSI_EXPORTS": "PRESENT"}, CATALOG, host="macos-15")
        output = markdown_report(result)
        self.assertIn("| MSI | PRESENT | api_exports_only |", output)
        self.assertIn("installation readiness", output)

    def test_catalog_schema(self):
        catalog = json.loads((Path(__file__).resolve().parent.parent / "config/prerequisites_2026.json").read_text())
        self.assertEqual(catalog["reference_environment"]["architecture"], "x86_64")
        self.assertIn("netfx481", [x["id"] for x in catalog["requirements"]])

if __name__ == "__main__":
    unittest.main()
