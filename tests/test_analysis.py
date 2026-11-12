from pathlib import Path
import tempfile
import unittest
from swcompat.analysis import analyze, recommendations

class AnalysisTests(unittest.TestCase):
    def read(self, value):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "log.txt"
            path.write_text(value)
            return analyze(path)

    def test_missing_dll_and_exceptions(self):
        report = self.read("err:module:import_dll Library msvcp140.dll not found\nUnhandled exception: page fault\n")
        self.assertEqual(report.missing_dlls["msvcp140.dll"], 1)
        self.assertEqual(report.errors["module"], 1)
        self.assertGreater(report.exceptions, 0)
        self.assertTrue(recommendations(report))

    def test_fixme_not_error(self):
        report = self.read("fixme:graphics:unsupported\n")
        self.assertFalse(report.errors)
        self.assertEqual(report.exceptions, 0)

if __name__ == "__main__":
    unittest.main()
