import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from scripts.service_smoke import run_sequence, succeeded


def result(step, state=None):
    content = f"SWCOMPAT_SERVICE_PHASE={step}\nSWCOMPAT_SERVICE_CHECK=PASS\n"
    if state:
        content += f"SWCOMPAT_SERVICE_STATE={state}\n"
    return {"exit_code": 0, "output": content}


class ServiceSmokeTests(unittest.TestCase):
    def test_requires_service_states_and_clean_exit(self):
        self.assertTrue(succeeded(result("start","4"),"start"))
        self.assertFalse(succeeded(result("start","1"),"start"))
        self.assertFalse(succeeded({"exit_code":1,"output":result("start","4")["output"]},"start"))
        self.assertFalse(succeeded(result("stop","4"),"stop"))

    def test_full_lifecycle(self):
        with tempfile.TemporaryDirectory() as tmp:
            exe=Path(tmp)/"service_smoke.exe"
            exe.touch()
            with patch("scripts.service_smoke.execute", side_effect=[
                result("absent"),result("install"),result("status","1"),
                result("start","4"),result("status","4"),result("stop","1"),
                result("delete"),result("absent")]) as execute:
                report=run_sequence("native",None,Path(tmp),exe)
            self.assertTrue(report["passed"])
            self.assertEqual(execute.call_count,8)

    def test_failed_start_always_attempts_cleanup(self):
        with tempfile.TemporaryDirectory() as tmp:
            exe=Path(tmp)/"service_smoke.exe"
            exe.touch()
            with patch("scripts.service_smoke.execute",side_effect=[
                result("absent"),result("install"),result("status","1"),
                {"exit_code":1,"output":"SWCOMPAT_SERVICE_CHECK=FAIL"},
                result("stop","1"),result("delete"),result("absent")]) as execute:
                report=run_sequence("native",None,Path(tmp),exe)
            self.assertFalse(report["passed"])
            self.assertIn("cleanup_stop",report)
            self.assertEqual(execute.call_count,7)

    def test_retries_cross_process_service_discovery(self):
        with tempfile.TemporaryDirectory() as tmp:
            exe=Path(tmp)/"service_smoke.exe"
            exe.touch()
            with patch("scripts.service_smoke.time.sleep") as sleep, \
                 patch("scripts.service_smoke.execute", side_effect=[
                    result("absent"), result("install"),
                    {"exit_code": 1, "output": "SWCOMPAT_SERVICE_PHASE=status\\nSWCOMPAT_SERVICE_CHECK=FAIL"},
                    result("status","1"), result("start","4"),
                    result("status","4"), result("stop","1"),
                    result("delete"), result("absent")]):
                report=run_sequence("native",None,Path(tmp),exe)
            self.assertTrue(report["passed"])
            self.assertEqual(report["registration_poll_attempts"],2)
            sleep.assert_called_once()

    def test_existing_service_not_modified(self):
        with tempfile.TemporaryDirectory() as tmp:
            exe=Path(tmp)/"service_smoke.exe"
            exe.touch()
            with patch("scripts.service_smoke.execute",return_value={
                "exit_code":1,"output":"SWCOMPAT_SERVICE_PHASE=absent\nSWCOMPAT_SERVICE_CHECK=FAIL\n"}) as execute:
                report=run_sequence("native",None,Path(tmp),exe)
            self.assertFalse(report["passed"])
            self.assertEqual(execute.call_count,1)

if __name__=="__main__":
    unittest.main()
