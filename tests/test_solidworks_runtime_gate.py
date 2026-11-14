"""Synthetic safety tests for actual SOLIDWORKS WebView2 prerequisite gate."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from scripts.solidworks_runtime_gate import evaluate

def report():
    return {
        "schema": 1,
        "scope": "OFFICIAL_INSTALLER_TRIAL_NOT_SOLIDWORKS",
        "installer_execution": "EXIT_ZERO",
        "installer_sha256_verified": True,
        "runtime_installation_confirmed": True,
        "browser_controller_confirmed": True,
        "controller_transition": "BECAME_READY",
        "after": {"probe_result": "COMPLETE", "controller_creation": "READY"},
    }

class RuntimeGateTests(unittest.TestCase):
    def test_confirmed_controller_allows_launch(self):
        self.assertTrue(evaluate(report())["ready"])

    def test_exit_zero_alone_cannot_pass(self):
        for field in ("runtime_installation_confirmed", "browser_controller_confirmed",
                      "installer_sha256_verified"):
            with self.subTest(field=field):
                x = report()
                x[field] = False
                self.assertFalse(evaluate(x)["ready"])

    def test_timeout_or_controller_not_ready_blocks(self):
        for field, value in (("installer_execution", "TIMEOUT"),
                             ("controller_transition", "REGRESSED")):
            x = report()
            x[field] = value
            self.assertFalse(evaluate(x)["ready"])
        x = report()
        x["after"]["controller_creation"] = "NOT_REACHED"
        self.assertFalse(evaluate(x)["ready"])

    def test_wrong_source_rejected(self):
        x = report()
        x["scope"] = "UNKNOWN"
        with self.assertRaises(ValueError):
            evaluate(x)

    def test_cli_is_fail_closed_and_never_prints_untrusted_text(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "report.json"
            x = report()
            x["untrusted_private_secret"] = "SECRET_NEVER_PRINT"
            path.write_text(json.dumps(x))
            command = [sys.executable, "-m", "scripts.solidworks_runtime_gate",
                       "--input", str(path), "--require-ready"]
            ok = subprocess.run(command, text=True, capture_output=True)
            self.assertEqual(ok.returncode, 0)
            self.assertNotIn("SECRET_NEVER_PRINT", ok.stdout + ok.stderr)
            x["browser_controller_confirmed"] = False
            path.write_text(json.dumps(x))
            fail = subprocess.run(command, text=True, capture_output=True)
            self.assertEqual(fail.returncode, 1)
            self.assertNotIn(str(path), fail.stdout + fail.stderr)

if __name__ == "__main__":
    unittest.main()
