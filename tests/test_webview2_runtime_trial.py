import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from unittest import mock
import unittest

from scripts import webview2_runtime_trial as trial


def sample(*, runtime="NOT_DISCOVERED", environment="REQUEST_FAILED",
           controller="NOT_REACHED", complete=True):
    return {
        "probe_result": "COMPLETE" if complete else "FAILED_OR_INCOMPLETE",
        "runtime_discovery": runtime,
        "environment_creation": environment,
        "controller_creation": controller,
        "controller_created": controller == "READY" and complete,
    }


class TrialTests(unittest.TestCase):
    def test_must_mark_disposable_prefix_and_initialize_wine(self):
        with tempfile.TemporaryDirectory() as t:
            path = Path(t)
            with self.assertRaisesRegex(ValueError, "disposable"):
                trial.validate_prefix(path)
            (path / trial.SENTINEL).write_text("")
            with self.assertRaisesRegex(ValueError, "not initialized"):
                trial.validate_prefix(path)
            (path / "drive_c").mkdir()
            (path / "system.reg").write_text("")
            trial.validate_prefix(path)

    def test_installer_sha256_must_match(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            installer, digest = root / "setup.exe", root / "sha.txt"
            installer.write_bytes(b"x" * (8 * 1024 * 1024 + 10))
            sha = hashlib.sha256(installer.read_bytes()).hexdigest()
            digest.write_text(sha)
            self.assertEqual(trial.verify_installer(installer, digest), sha)
            installer.write_bytes(b"z" * (8 * 1024 * 1024 + 10))
            with self.assertRaisesRegex(ValueError, "mismatch"):
                trial.verify_installer(installer, digest)

    def test_sha256_manifest_disallows_arbitrary_content(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            installer, digest = root / "setup.exe", root / "sha.txt"
            installer.write_bytes(b"x" * (8 * 1024 * 1024 + 10))
            digest.write_text("abc /private/home/secret")
            with self.assertRaisesRegex(ValueError, "single SHA"):
                trial.verify_installer(installer, digest)

    def test_installer_size_bounds(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            installer, digest = root / "setup.exe", root / "sha.txt"
            installer.write_bytes(b"small")
            digest.write_text("0" * 64)
            with self.assertRaisesRegex(ValueError, "size bounds"):
                trial.verify_installer(installer, digest)

    def test_ready_after_install(self):
        before = sample()
        after = sample(runtime="VERSION_FOUND", environment="READY", controller="READY")
        x = trial.combine(before, after, "EXIT_ZERO", 0)
        self.assertTrue(x["runtime_installation_confirmed"])
        self.assertTrue(x["browser_controller_confirmed"])
        self.assertEqual(x["controller_transition"], "BECAME_READY")
        self.assertEqual(x["solidworks_compatibility"], "NOT_DEMONSTRATED")

    def test_installer_zero_exit_without_runtime_is_not_success(self):
        x = trial.combine(sample(), sample(), "EXIT_ZERO", 0)
        self.assertFalse(x["runtime_installation_confirmed"])
        self.assertFalse(x["browser_controller_confirmed"])
        self.assertEqual(x["controller_transition"], "REMAINED_UNAVAILABLE")

    def test_installer_nonzero_exit_with_runtime_not_attributed_to_success(self):
        before = sample()
        after = sample(runtime="VERSION_FOUND", environment="READY", controller="READY")
        x = trial.combine(before, after, "EXIT_NONZERO", 1603)
        self.assertFalse(x["runtime_installation_confirmed"])
        self.assertEqual(x["installer_exit_code"], 1603)

    def test_preexisting_runtime_not_attributed_to_install(self):
        ready = sample(runtime="VERSION_FOUND", environment="READY", controller="READY")
        result = trial.combine(ready, ready, "EXIT_ZERO", 0)
        self.assertFalse(result["runtime_installation_confirmed"])
        self.assertEqual(result["controller_transition"], "REMAINED_READY")

    def test_timeout_and_process_errors_are_explicit(self):
        x = trial.combine(sample(), sample(), "TIMEOUT", None)
        self.assertEqual(x["installer_execution"], "TIMEOUT")
        self.assertIsNone(x["installer_exit_code"])
        with self.assertRaises(ValueError):
            trial.combine(sample(), sample(), "SILENT_SUCCESS", 0)

    def test_unfinished_probe_cannot_count_as_evidence(self):
        x = trial.combine(sample(complete=False), sample(), "EXIT_ZERO", 0)
        self.assertEqual(x["controller_transition"], "UNKNOWN")
        self.assertFalse(x["runtime_installation_confirmed"])

    def test_summary_never_includes_private_paths_or_raw_logs(self):
        before = sample()
        after = sample()
        before["private_path"] = "/Users/PRIVATE/wineprefix"
        before["license_token"] = "SECRET-LICENSE"
        report = json.dumps(trial.combine(before, after, "EXIT_NONZERO", 5))
        self.assertNotIn("PRIVATE", report)
        self.assertNotIn("SECRET-LICENSE", report)
        self.assertNotIn("private_path", report)

    def test_run_installer_process_error(self):
        with mock.patch.object(trial.subprocess, "Popen", side_effect=OSError("private path")):
            result = trial.run_installer(Path("wine"), Path("installer.exe"), {}, 30)
        self.assertEqual(result, ("PROCESS_ERROR", None))

    def test_probe_incomplete_on_unexpected_process_error(self):
        with mock.patch.object(trial.subprocess, "run", side_effect=OSError("Private")):
            x = trial.probe(Path("wine"), Path("example.exe"), {}, 1)
        self.assertEqual(x["probe_result"], "FAILED_OR_INCOMPLETE")
        self.assertNotIn("Private", json.dumps(x))

    def test_cli_requires_explicit_disposable_opt_in(self):
        proc = subprocess.run(
            [sys.executable, "-m", "scripts.webview2_runtime_trial",
             "--wine", "/fake", "--prefix", "/fake", "--installer", "/fake",
             "--probe", "/fake", "--sha256-file", "/fake", "--output", "/fake"],
            text=True, capture_output=True,
        )
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("agree-disposable-prefix", proc.stderr)


if __name__ == "__main__":
    unittest.main()
