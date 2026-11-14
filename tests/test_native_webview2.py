"""The real WebView2 controller, not a registry marker, gates local Mac setup."""
import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from swcompat import native_webview2 as webview2
from swcompat.cli import main


def status(ready: bool) -> dict:
    return {
        "probe_result": "COMPLETE",
        "runtime_discovery": "VERSION_FOUND" if ready else "NOT_DISCOVERED",
        "environment_creation": "READY" if ready else "REQUEST_FAILED",
        "controller_creation": "READY" if ready else "NOT_REACHED",
        "controller_created": ready,
    }


class NativeWebView2Tests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.prefix = root / "prefix"
        (self.prefix / "drive_c").mkdir(parents=True)
        (self.prefix / "system.reg").write_text("")
        self.logs = root / "logs"
        self.wine = root / "wine"
        self.wine.write_text("#!/bin/sh\nexit 0\n")
        self.wine.chmod(0o755)
        self.installer = root / "MicrosoftEdgeWebView2RuntimeInstallerX64.exe"
        self.installer.write_bytes(b"not genuine, synthetic test only")
        self.sha = root / "sha256.txt"
        self.sha.write_text("0" * 64)
        self.probe = root / "webview2_controller_probe.exe"
        self.probe.write_bytes(b"synthetic probe")
        (root / "WebView2Loader.dll").write_bytes(b"synthetic DLL")

    def prep(self, *, statuses, installer_result=("EXIT_ZERO", 0)):
        runner = mock.Mock(return_value=installer_result)
        probe = mock.Mock(side_effect=statuses)
        with mock.patch.object(webview2, "verify_microsoft_installer", return_value="0" * 64):
            report = webview2.prepare_webview2(
                self.wine, self.prefix, self.logs, self.installer, self.sha, self.probe,
                run_probe=probe, installer_runner=runner, pause=lambda _: None,
            )
        return report, runner, probe

    def test_detects_existing_ready_runtime_without_reinstall(self):
        report, runner, probe = self.prep(statuses=[status(True)])
        self.assertEqual(report["result"], "ALREADY_READY")
        self.assertEqual(report["installer_execution"], "NOT_NEEDED")
        runner.assert_not_called()
        self.assertEqual(probe.call_count, 1)

    def test_installs_official_runtime_in_same_prefix_and_verifies_controller(self):
        report, runner, probe = self.prep(statuses=[status(False), status(True)])
        self.assertEqual(report["result"], "READY")
        self.assertEqual(report["before_controller"], "NOT_READY")
        self.assertEqual(report["after_controller"], "READY")
        self.assertEqual(report["installer_authenticode"], "NOT_VERIFIED_LOCALLY")
        runner.assert_called_once()
        self.assertEqual(runner.call_args.args[3], 240)
        self.assertEqual(runner.call_args.args[2]["WINEPREFIX"], str(self.prefix.resolve()))
        self.assertEqual(probe.call_args.args[2]["WINEPREFIX"], str(self.prefix.resolve()))
        saved = list(self.logs.glob("native-webview2-*.json"))
        self.assertEqual(len(saved), 1)
        text = saved[0].read_text()
        self.assertNotIn(str(self.prefix), text)
        self.assertNotIn(str(self.installer), text)
        self.assertNotIn("0" * 64, text)
        self.assertEqual(json.loads(text)["result"], "READY")
        if os.name != "nt":
            self.assertEqual(saved[0].stat().st_mode & 0o077, 0)

    def test_relative_media_paths_are_normalized_before_subprocess_chdir(self):
        # This reproduces GitHub's real command: --installer build/runtime.exe
        # while the Wine runtime subprocess uses cwd=build.
        runner = mock.Mock(return_value=("EXIT_ZERO", 0))
        probe = mock.Mock(side_effect=[status(False), status(True)])
        relative = lambda p: Path(os.path.relpath(p, Path.cwd()))
        with mock.patch.object(webview2, "verify_microsoft_installer", return_value="0" * 64):
            result = webview2.prepare_webview2(
                relative(self.wine), relative(self.prefix), relative(self.logs),
                relative(self.installer), relative(self.sha), relative(self.probe),
                run_probe=probe, installer_runner=runner, pause=lambda _: None,
            )
        self.assertEqual(result["result"], "READY")
        self.assertEqual(runner.call_args.args[1], self.installer.resolve())
        self.assertEqual(probe.call_args.args[1], self.probe.resolve())
        self.assertEqual(runner.call_args.args[2]["WINEPREFIX"], str(self.prefix.resolve()))

    def test_exit_zero_without_controller_is_not_accepted(self):
        report, runner, _ = self.prep(statuses=[status(False), status(False)])
        self.assertEqual(report["result"], "WEBVIEW2_NOT_READY")
        self.assertEqual(report["after_controller"], "NOT_READY")
        runner.assert_called_once()

    def test_runtime_installer_nonzero_cannot_count_as_success(self):
        report, _, _ = self.prep(statuses=[status(False), status(True)],
                                 installer_result=("EXIT_NONZERO", 1603))
        self.assertEqual(report["result"], "WEBVIEW2_NOT_READY")
        self.assertEqual(report["installer_execution"], "EXIT_NONZERO")

    def test_readiness_requires_real_controller(self):
        invalid = status(True)
        invalid["controller_created"] = False
        self.assertFalse(webview2.ready(invalid))
        invalid["controller_created"] = True
        invalid["probe_result"] = "FAILED_OR_INCOMPLETE"
        self.assertFalse(webview2.ready(invalid))

    def test_refuses_linked_executable(self):
        linked = self.probe.parent / "other.exe"
        try:
            linked.symlink_to(self.installer)
        except (OSError, NotImplementedError):
            self.skipTest("symlink unavailable")
        with self.assertRaisesRegex(ValueError, "Symbolic links"):
            webview2.prepare_webview2(
                self.wine, self.prefix, self.logs, linked, self.sha, self.probe)

    def test_native_install_blocks_if_controller_not_ready(self):
        media = self.probe.parent / "setup.exe"
        media.write_bytes(b"synthetic setup")
        with mock.patch("swcompat.cli.find_wine", return_value=self.wine), \
             mock.patch("swcompat.native_webview2.check_webview2", return_value=False), \
             mock.patch("swcompat.native_install.run_interactive") as install_run:
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                result = main(["--prefix", str(self.prefix), "--logs-dir", str(self.logs),
                               "native-install", str(self.probe.parent),
                               "--require-webview2-probe", str(self.probe)])
        self.assertEqual(result, 1)
        install_run.assert_not_called()
        self.assertIn("NOT_READY", out.getvalue())

    def test_native_install_runs_after_controller_ready(self):
        media = self.probe.parent / "setup.exe"
        media.write_bytes(b"synthetic setup")
        with mock.patch("swcompat.cli.find_wine", return_value=self.wine), \
             mock.patch("swcompat.native_webview2.check_webview2", return_value=True), \
             mock.patch("swcompat.native_install.run_interactive", return_value=0) as launch:
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                result = main(["--prefix", str(self.prefix), "--logs-dir", str(self.logs),
                               "native-install", str(self.probe.parent),
                               "--require-webview2-probe", str(self.probe)])
        self.assertEqual(result, 0)
        launch.assert_called_once()
        self.assertIn("READY", out.getvalue())


if __name__ == "__main__":
    unittest.main()
