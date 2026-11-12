import unittest
from scripts.msvc_runtime_check import passed


class MSVCRuntimeReportTests(unittest.TestCase):
    def test_requires_runtime_markers_and_architecture(self):
        markers = [f"SWCOMPAT_MSVC_{x}=PASS" for x in
                   ("STL", "ASYNC", "STREAM", "FILEIO", "RUNTIME")]
        run = {"exit_code": 0, "output": "\n".join(markers + ["SWCOMPAT_MSVC_PROCESS_BITS=32"])}
        self.assertTrue(passed(run, 32))
        self.assertFalse(passed(run, 64))
        self.assertFalse(passed({**run, "exit_code": 1}, 32))

    def test_missing_section_fails(self):
        run = {"exit_code": 0, "output": "SWCOMPAT_MSVC_RUNTIME=PASS\nSWCOMPAT_MSVC_PROCESS_BITS=64"}
        self.assertFalse(passed(run, 64))


if __name__ == "__main__":
    unittest.main()
