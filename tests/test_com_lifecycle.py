import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.com_lifecycle import completed, lifecycle


def phase_run(phase):
    return {"exit_code": 0, "output": f"SWCOMPAT_COM_PHASE={phase}\nSWCOMPAT_COM_CHECK=PASS\n"}


class COMLifecycleTests(unittest.TestCase):
    def test_completed_requires_exit_and_markers(self):
        self.assertTrue(completed(phase_run("activate"), "activate"))
        self.assertFalse(completed(phase_run("activate"), "unregister"))
        self.assertFalse(completed({"exit_code": 1, "output": phase_run("activate")["output"]}, "activate"))

    def test_complete_register_activate_remove(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            checker, dll = root / "check.exe", root / "server.dll"
            checker.touch()
            dll.touch()
            with patch("scripts.com_lifecycle.execute", side_effect=[
                    phase_run("absent"), phase_run("register"),
                    phase_run("activate"), phase_run("unregister"),
                    phase_run("absent")]) as exec_mock:
                result = lifecycle("native", None, root, checker, dll)
            self.assertTrue(result["passed"])
            self.assertEqual(exec_mock.call_count, 5)

    def test_cleanup_on_activation_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            checker, dll = root / "check.exe", root / "server.dll"
            checker.touch()
            dll.touch()
            with patch("scripts.com_lifecycle.execute", side_effect=[
                    phase_run("absent"), phase_run("register"),
                    {"exit_code": 1, "output": "SWCOMPAT_COM_CHECK=FAIL"},
                    phase_run("unregister"), phase_run("absent")]):
                result = lifecycle("native", None, root, checker, dll)
            self.assertFalse(result["passed"])
            self.assertEqual(result["unregister"]["exit_code"], 0)

    def test_classes_root_mode_uses_wine_only_registration_exports(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            checker, dll = root / "check.exe", root / "server.dll"
            checker.touch()
            dll.touch()
            with patch("scripts.com_lifecycle.wine_environment", return_value={}), \
                 patch("scripts.com_lifecycle.execute", side_effect=[
                    phase_run("absent"), phase_run("register-root"),
                    phase_run("activate"), phase_run("unregister-root"),
                    phase_run("absent")]) as execute_mock:
                with patch("scripts.com_lifecycle.wine_path", return_value="Z:\\server.dll"):
                    result = lifecycle("wine", "wine", root, checker, dll, "classes-root")
            self.assertTrue(result["passed"])
            commands = [call.args[0] for call in execute_mock.call_args_list]
            self.assertIn("register-root", commands[1])
            self.assertIn("unregister-root", commands[3])

    def test_reject_classes_root_registration_on_real_windows(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            checker, dll = root / "check.exe", root / "server.dll"
            checker.touch()
            dll.touch()
            with self.assertRaisesRegex(ValueError, "only permitted"):
                lifecycle("native", None, root, checker, dll, "classes-root")

    def test_reject_missing_server(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError):
                lifecycle("native", None, Path(tmp), Path(tmp)/"x.exe", Path(tmp)/"missing.dll")


if __name__ == "__main__":
    unittest.main()
