import unittest

from scripts.compare_graphics import markers, interpret, report


class GraphicsComparisonTests(unittest.TestCase):
    def test_parse_markers(self):
        text = ("unrelated debug line\n"
                "SWCOMPAT_PIXELFORMAT_COUNT=0\n"
                "SWCOMPAT_WGL=FAIL\n")
        self.assertEqual(markers(text)["SWCOMPAT_PIXELFORMAT_COUNT"], "0")

    def test_host_unavailable_is_not_definitive(self):
        cgl = {"SWCOMPAT_CGL": "UNAVAILABLE"}
        wgl = {"SWCOMPAT_WGL": "FAIL", "SWCOMPAT_PIXELFORMAT_COUNT": "0"}
        self.assertIn("plausible blocker", interpret(cgl, wgl))

    def test_wine_defect_candidate(self):
        cgl = {"SWCOMPAT_CGL": "PASS"}
        wgl = {"SWCOMPAT_WGL": "FAIL", "SWCOMPAT_PIXELFORMAT_COUNT": "0"}
        self.assertIn("winemac.drv", interpret(cgl, wgl))

    def test_success_does_not_claim_solidworks(self):
        self.assertIn("SOLIDWORKS is still untested",
                      interpret({"SWCOMPAT_CGL": "PASS"}, {"SWCOMPAT_WGL": "PASS"}))

    def test_missing_data(self):
        self.assertEqual(report("", "")["wine_wgl"], "NOT_RUN")
        self.assertEqual(report("", "")["native_cgl"], "NOT_RUN")

    def test_output_uses_last_diagnostic_marker(self):
        data = report("SWCOMPAT_CGL=UNAVAILABLE\nSWCOMPAT_CGL=PASS\n",
                      "SWCOMPAT_WGL=FAIL\nSWCOMPAT_PIXELFORMAT_COUNT=0\n")
        self.assertEqual(data["native_cgl"], "PASS")


if __name__ == "__main__":
    unittest.main()
