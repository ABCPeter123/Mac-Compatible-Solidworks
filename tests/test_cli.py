import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
import subprocess
import signal
from unittest import mock

from swcompat.cli import main, find_wine, capture

class CLITests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.prefix = self.root / "prefix"
        self.logs = self.root / "logs"
        self.wine = self.root / "wine"
        self.boot = self.root / "wineboot"
        self.wine.write_text(
            '#!/bin/sh\n'
            'if [ "$1" = "--version" ]; then echo wine-11-test; exit 0; fi\n'
            'if [ "$1" = "cmd.exe" ]; then echo Microsoft Windows; exit 0; fi\n'
            'if [ "$1" = "winecfg" ]; then exit 0; fi\n'
            'case "$1" in *prereq.exe) printf "SWCOMPAT_PREREQ_SCHEMA=1\\nSWCOMPAT_PREREQ_PROBE=PASS\\n"; exit 0;; esac\n'
            'case "$1" in *bitmap.exe) echo SWCOMPAT_BITMAP_WGL=PASS; exit 0;; '
            '*good.exe) echo SWCOMPAT_WGL=PASS; exit 0;; '
            '*bad.exe) echo SWCOMPAT_WGL=FAIL; exit 0;; esac\n'
            'exit 1\n'
        )
        self.boot.write_text('#!/bin/sh\nmkdir -p "$WINEPREFIX"\n')
        self.wine.chmod(0o755)
        self.boot.chmod(0o755)

    def invoke(self, *args):
        output = io.StringIO()
        common = ["--wine", str(self.wine), "--prefix", str(self.prefix),
                  "--logs-dir", str(self.logs)]
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            code = main([*common, *args])
        return code, output.getvalue()

    def test_discovery(self):
        self.assertEqual(find_wine(str(self.wine)), self.wine.resolve())
        self.assertIsNone(find_wine("/a/nonexistent/file/that/is-not-wine"))

    def test_doctor(self):
        code, output = self.invoke("doctor", "--json")
        self.assertEqual(code, 0)
        report = json.loads(output)
        self.assertTrue(report["wine_responds"])
        self.assertEqual(report["wine_version"], "wine-11-test")
        self.assertFalse(report["prefix_exists"])

    def test_prefix_required(self):
        code, output = self.invoke("probe-win32")
        self.assertEqual(code, 2)
        self.assertIn("prefix missing", output)

    def test_init_and_win32(self):
        self.assertEqual(self.invoke("init")[0], 0)
        self.assertTrue(self.prefix.is_dir())
        code, output = self.invoke("probe-win32")
        self.assertEqual(code, 0)
        self.assertIn("PASS", output)
        self.assertEqual(len(list(self.logs.glob("*-win32-*.log"))), 1)

    def test_wineboot_timeout_uses_isolated_process_group_and_forced_kill(self):
        child = mock.Mock()
        child.pid = 71321
        child.wait.side_effect = [
            subprocess.TimeoutExpired("wineboot", 120),
            subprocess.TimeoutExpired("wineboot", 3),
            0,
        ]
        with (mock.patch("swcompat.cli.subprocess.Popen", return_value=child) as launched,
              mock.patch("swcompat.cli.os.killpg") as killpg):
            status, path = capture([str(self.boot), "--init"], self.prefix,
                                   self.logs, "init", timeout=120,
                                   kill_group_on_timeout=True)
        self.assertEqual(status, 124)
        self.assertIn("SWCOMPAT_TIMED_OUT=1", path.read_text())
        self.assertNotIn("SWCOMPAT_TIMED_OUT_CLEANUP_DENIED=1", path.read_text())
        self.assertTrue(launched.call_args.kwargs["start_new_session"])
        self.assertEqual(launched.call_args.kwargs["stdin"], subprocess.DEVNULL)
        self.assertEqual(killpg.call_args_list, [
            mock.call(71321, signal.SIGTERM),
            mock.call(71321, signal.SIGKILL),
        ])

    def test_wineboot_denied_process_group_cleanup_remains_explicit_failure(self):
        child = mock.Mock()
        child.pid = 71322
        child.wait.side_effect = [
            subprocess.TimeoutExpired("wineboot", 120),
            subprocess.TimeoutExpired("wineboot", 3),
            subprocess.TimeoutExpired("wineboot", 5),
        ]
        with (mock.patch("swcompat.cli.subprocess.Popen", return_value=child),
              mock.patch("swcompat.cli.os.killpg",
                         side_effect=PermissionError("private host path"))):
            status, path = capture([str(self.boot), "--init"], self.prefix,
                                   self.logs, "init", timeout=120,
                                   kill_group_on_timeout=True)
        self.assertEqual(status, 125)
        self.assertIn("SWCOMPAT_TIMED_OUT_CLEANUP_DENIED=1", path.read_text())
        self.assertNotIn("private host path", path.read_text())

    def test_wineboot_timeout_can_be_120_or_240_only(self):
        self.assertEqual(self.invoke("init", "--timeout", "120")[0], 0)
        self.assertEqual(self.invoke("init", "--timeout", "240")[0], 0)
        with self.assertRaises(SystemExit):
            self.invoke("init", "--timeout", "25")

    def test_skip_mono_gecko_is_scoped_to_one_wineboot_child_only(self):
        child = mock.Mock()
        child.wait.return_value = 0
        with (mock.patch("swcompat.cli.subprocess.Popen", return_value=child) as launch,
              mock.patch.dict("swcompat.cli.os.environ", {
                  "WINEDLLOVERRIDES": "mscoree=n;clr=n",
              })):
            status, _ = capture([str(self.boot), "--init"], self.prefix,
                                self.logs, "init", timeout=120,
                                kill_group_on_timeout=True,
                                skip_bootstrap_mono_gecko=True)
        self.assertEqual(status, 0)
        boot_env = launch.call_args.kwargs["env"]
        self.assertEqual(boot_env["WINEDLLOVERRIDES"], "mscoree,mshtml=d")
        self.assertEqual(boot_env["WINE_SKIP_MONO_INSTALLATION"], "1")
        self.assertEqual(boot_env["WINE_SKIP_GECKO_INSTALLATION"], "1")
        self.assertEqual(boot_env["WINEARCH"], "win64")
        self.assertEqual(boot_env["WINEPREFIX"], str(self.prefix))
        with (mock.patch("swcompat.cli.subprocess.run") as ordinary,
              mock.patch.dict("swcompat.cli.os.environ",
                              {"WINEDLLOVERRIDES": "mscoree=n;clr=n"})):
            ordinary.return_value.returncode = 0
            status, _ = capture([str(self.wine), "cmd.exe"], self.prefix,
                                self.logs, "win32", timeout=20)
        self.assertEqual(status, 0)
        self.assertEqual(
            ordinary.call_args.kwargs["env"]["WINEDLLOVERRIDES"],
            "mscoree=n;clr=n")
        self.assertEqual(boot_env["WINEDLLOVERRIDES"], "mscoree,mshtml=d")

    def test_mono_gecko_suppression_cannot_be_used_for_managed_probe(self):
        with self.assertRaises(ValueError):
            capture([str(self.wine), "managed.exe"], self.prefix,
                    self.logs, "managed", timeout=20,
                    kill_group_on_timeout=True,
                    skip_bootstrap_mono_gecko=True)
        with self.assertRaises(ValueError):
            capture([str(self.boot), "--init"], self.prefix,
                    self.logs, "init", timeout=120,
                    kill_group_on_timeout=False,
                    skip_bootstrap_mono_gecko=True)

    def test_command_line_scoped_suppression_starts_real_wineboot_stub(self):
        code, message = self.invoke(
            "init", "--timeout", "120", "--skip-bootstrap-mono-gecko")
        self.assertEqual(code, 0, message)
        self.assertTrue(self.prefix.is_dir())

    def test_windows11_profile_command_isolated_prefix(self):
        self.assertEqual(self.invoke("set-winver", "win11")[0], 2)
        self.assertEqual(self.invoke("init")[0], 0)
        code, message = self.invoke("set-winver", "win11")
        self.assertEqual(code, 0)
        self.assertIn("APPLIED", message)
        self.assertEqual(len(list(self.logs.glob("*-winver-*.log"))), 1)

    def test_installer_prerequisite_probe_requires_completion_marker(self):
        self.assertEqual(self.invoke("init")[0], 0)
        good = self.root / "prereq.exe"
        good.touch()
        code, message = self.invoke("probe-prereqs", "--exe", str(good))
        self.assertEqual(code, 0)
        self.assertIn("COMPLETE", message)
        self.assertIn("SWCOMPAT_PREREQ_PROBE=PASS", message)

    def test_wgl_requires_success_marker_not_only_exit_zero(self):
        self.assertEqual(self.invoke("init")[0], 0)
        bad = self.root / "bad.exe"
        bad.touch()
        code, output = self.invoke("probe-wgl", "--exe", str(bad))
        self.assertEqual(code, 1)
        self.assertIn("FAIL", output)
        good = self.root / "good.exe"
        good.touch()
        code, output = self.invoke("probe-wgl", "--exe", str(good))
        self.assertEqual(code, 0)
        self.assertIn("PASS", output)

    def test_bitmap_probe_requires_its_own_success_marker(self):
        self.assertEqual(self.invoke("init")[0], 0)
        ordinary = self.root / "good.exe"
        ordinary.touch()
        code, message = self.invoke("probe-bitmap", "--exe", str(ordinary))
        self.assertEqual(code, 1)
        self.assertIn("FAIL", message)
        bitmap = self.root / "bitmap.exe"
        bitmap.touch()
        code, message = self.invoke("probe-bitmap", "--exe", str(bitmap))
        self.assertEqual(code, 0)
        self.assertIn("PASS", message)

    def test_analyze(self):
        log = self.root / "wine.log"
        log.write_text("0000:err:module:import_dll Library msvcp140.dll not found\n")
        code, output = self.invoke("analyze", str(log))
        self.assertEqual(code, 0)
        self.assertIn("msvcp140.dll", output)

    def test_does_not_run_nonexistent_exe(self):
        self.assertEqual(self.invoke("init")[0], 0)
        self.assertEqual(self.invoke("install", str(self.root / "nonexistent.exe"))[0], 2)

if __name__ == "__main__":
    unittest.main()
