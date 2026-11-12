import unittest
from scripts.service_single_report import analyze


class SingleServiceReportTests(unittest.TestCase):
    @staticmethod
    def output(**override):
        data = {
            "CREATE": "PASS", "START_ERROR": "0",
            "RUNNING_STATE": "4", "RUNNING_PID": "644",
            "STOP_ERROR": "0", "STOPPED_STATE": "1",
            "DELETE_ERROR": "0", "REMOVED": "1", "PROCESS": "PASS",
        }
        data.update(override)
        return "\n".join("SWCOMPAT_SERVICE_SINGLE_" + key + "=" + value
                         for key, value in data.items())

    def test_complete_success(self):
        self.assertTrue(analyze(self.output(), 0)["passed"])

    def test_missing_pid_rejected(self):
        self.assertIn("RUNNING_PID",
                      analyze(self.output(RUNNING_PID="0"), 0)["failed_checks"])

    def test_missing_service_stop_rejected(self):
        self.assertIn("STOPPED_STATE",
                      analyze(self.output(STOPPED_STATE="4"), 0)["failed_checks"])

    def test_nonzero_process_exit_rejected(self):
        self.assertIn("EXIT_CODE", analyze(self.output(), 1)["failed_checks"])

    def test_spoofed_prefix_marker_rejected(self):
        output = self.output().replace("SWCOMPAT_SERVICE_SINGLE_PROCESS=PASS",
                                       "noiseSWCOMPAT_SERVICE_SINGLE_PROCESS=PASS")
        self.assertIn("PROCESS", analyze(output, 0)["failed_checks"])


if __name__ == "__main__":
    unittest.main()
