"""Original .NET4 Wine installer may leave real nested MSI processes after wrapper exit.

A successful Win32 launcher wait or outer Python timeout is never permission
to let a still-running genuine Microsoft installer race the next CLR4 NGen.
Only a *new* process session and finite group termination are allowed.
"""
from __future__ import annotations

from pathlib import Path
import os
import signal
import subprocess
from tempfile import TemporaryDirectory
import unittest
from unittest import mock

from scripts import netfx40_legacy as legacy
from scripts.netfx481_payload_audit import ITEMS


class OriginalMicrosoftGroupCleanupTests(unittest.TestCase):
    def fixture(self, root):
        wine = root / "wine"
        wine.write_bytes(b"synthetic Wine executable")
        wine.chmod(0o755)
        prefix = root / "prefix"
        (prefix / "drive_c").mkdir(parents=True)
        (prefix / "system.reg").touch()
        (prefix / ".swcompat-netfx481-disposable").touch()
        launcher = root / "netfx40_win32_launch.exe"
        installer = root / "dotNetFx40_Full_x86_x64.exe"
        loader = root / "netfx481_clr_load.exe"
        managed = root / "netfx481_runtime_probe.exe"
        for p in (launcher, installer, loader, managed):
            p.write_bytes(b"synthetic self-authored fixture")
        return wine, prefix, installer, launcher, loader, managed

    def test_terminate_group_even_if_installer_parent_has_exited(self):
        child = mock.Mock(pid=23114, wait=mock.Mock(return_value=0))
        with mock.patch.object(legacy.os, "killpg") as kill:
            self.assertTrue(legacy._terminate_private_setup_group(child))
        self.assertEqual(kill.call_args_list, [
            mock.call(child.pid, signal.SIGTERM),
            mock.call(child.pid, signal.SIGKILL),
        ])
        self.assertEqual(child.wait.call_count, 2)
        self.assertTrue(all(x.kwargs["timeout"] == 5 for x in child.wait.call_args_list))

    def test_permission_error_fail_closed_not_successfully_reaped(self):
        child = mock.Mock(pid=23114, wait=mock.Mock(return_value=0))
        with mock.patch.object(legacy.os, "killpg", side_effect=PermissionError("denied")):
            self.assertFalse(legacy._terminate_private_setup_group(child))

    def test_isolated_microsoft_installer_outer_timeout_reaps_descendants(self):
        with TemporaryDirectory() as td:
            root = Path(td)
            wine, prefix, _, launcher, _, _ = self.fixture(root)
            child = mock.Mock(pid=23114,
                              wait=mock.Mock(side_effect=subprocess.TimeoutExpired("Wine", 390)))
            reader = mock.Mock()
            reader.is_alive.return_value = False
            with (
                mock.patch.object(legacy.subprocess, "Popen", return_value=child) as popen,
                mock.patch.object(legacy.threading, "Thread", return_value=reader),
                mock.patch.object(legacy, "_terminate_private_setup_group", return_value=True) as term,
            ):
                result = legacy._run_traced(wine, prefix, launcher,
                                            ["Z:\\dotNetFx40_Full_x86_x64.exe"],
                                            timeout=390)
            self.assertTrue(popen.call_args.kwargs["start_new_session"])
            self.assertEqual(popen.call_args.kwargs["stderr"], subprocess.PIPE)
            self.assertEqual(popen.call_args.kwargs["cwd"], launcher.parent)
            term.assert_called_once_with(child)
            self.assertEqual(result["status"], "TIMEOUT")
            self.assertEqual(result["setup_cleanup"], "GROUP_REAPED")
            self.assertEqual(result["category"], "NOT_AVAILABLE")

    def test_finished_launcher_open_pipe_triggers_group_cleanup(self):
        with TemporaryDirectory() as td:
            root = Path(td)
            wine, prefix, _, launcher, _, _ = self.fixture(root)
            child = mock.Mock(pid=23115, wait=mock.Mock(return_value=0))
            reader = mock.Mock()
            reader.is_alive.side_effect = [True, False, False]
            with (
                mock.patch.object(legacy.subprocess, "Popen", return_value=child),
                mock.patch.object(legacy.threading, "Thread", return_value=reader),
                mock.patch.object(legacy, "_terminate_private_setup_group", return_value=True) as term,
            ):
                result = legacy._run_traced(wine, prefix, launcher, ["Z:\\vendor.exe"])
            term.assert_called_once_with(child)
            self.assertEqual(result["setup_cleanup"], "GROUP_REAPED")
            self.assertEqual(result["status"], "BAD_REPORT")
            self.assertEqual(reader.join.call_count, 2)

    def test_clean_exit_does_not_send_unnecessary_termination_signal(self):
        with TemporaryDirectory() as td:
            root = Path(td)
            wine, prefix, _, launcher, _, _ = self.fixture(root)
            child = mock.Mock(pid=23116, wait=mock.Mock(return_value=0))
            reader = mock.Mock()
            reader.is_alive.return_value = False
            with (
                mock.patch.object(legacy.subprocess, "Popen", return_value=child),
                mock.patch.object(legacy.threading, "Thread", return_value=reader),
                mock.patch.object(legacy, "_terminate_private_setup_group") as term,
            ):
                result = legacy._run_traced(wine, prefix, launcher, ["Z:\\vendor.exe"])
            term.assert_not_called()
            self.assertEqual(result["setup_cleanup"], "PIPE_CLOSED")

    def test_disposable_wineserver_fallback_never_targets_user_prefix(self):
        with TemporaryDirectory() as td:
            root = Path(td)
            engine = root / "isolated-engine" / "bin"
            engine.mkdir(parents=True)
            wine = engine / "wine"
            server = engine / "wineserver"
            for exe in (wine, server):
                exe.write_bytes(b"synthetic Wine fixture")
                exe.chmod(0o755)
            prefix = root / "netfx40-msxml3-prefix"
            (prefix / "drive_c").mkdir(parents=True)
            (prefix / "system.reg").touch()
            (prefix / ".swcompat-netfx481-disposable").touch()
            with mock.patch.dict(os.environ, {"RUNNER_TEMP": td}):
                with mock.patch.object(
                    legacy.subprocess, "run",
                    return_value=mock.Mock(returncode=0),
                ) as run:
                    self.assertTrue(
                        legacy._terminate_private_setup_wineserver(wine, prefix))
                self.assertEqual(run.call_count, 2)
                self.assertEqual([c.args[0] for c in run.call_args_list],
                                 [[str(server), "-k"], [str(server), "-w"]])
                self.assertTrue(all(
                    c.kwargs["env"]["WINEPREFIX"] == str(prefix)
                    and c.kwargs["cwd"] == prefix
                    and c.kwargs["timeout"] == 18
                    and c.kwargs["stdout"] == subprocess.DEVNULL
                    and c.kwargs["stderr"] == subprocess.DEVNULL
                    for c in run.call_args_list))
                with mock.patch.object(legacy.subprocess, "run") as run:
                    self.assertFalse(
                        legacy._terminate_private_setup_wineserver(
                            wine, root / "not-the-test-prefix"))
                    self.assertFalse(
                        legacy._terminate_private_setup_wineserver(
                            wine, prefix.parent.parent / prefix.name))
                    run.assert_not_called()

    def test_disposable_wineserver_fallback_requires_both_kill_and_wait(self):
        with TemporaryDirectory() as td:
            root = Path(td)
            engine = root / "isolated-engine" / "bin"
            engine.mkdir(parents=True)
            wine = engine / "wine"
            server = engine / "wineserver"
            for exe in (wine, server):
                exe.write_bytes(b"fixture")
                exe.chmod(0o755)
            prefix = root / "netfx40-msxml3-prefix"
            (prefix / "drive_c").mkdir(parents=True)
            (prefix / "system.reg").touch()
            (prefix / ".swcompat-netfx481-disposable").touch()
            with mock.patch.dict(os.environ, {"RUNNER_TEMP": td}):
                with mock.patch.object(
                    legacy.subprocess, "run",
                    side_effect=[mock.Mock(returncode=0),
                                 subprocess.TimeoutExpired("wineserver", 18)],
                ) as run:
                    self.assertFalse(
                        legacy._terminate_private_setup_wineserver(wine, prefix))
                self.assertEqual(run.call_count, 2)
                (prefix / ".swcompat-netfx481-disposable").unlink()
                with mock.patch.object(legacy.subprocess, "run") as run:
                    self.assertFalse(
                        legacy._terminate_private_setup_wineserver(wine, prefix))
                    run.assert_not_called()

    def test_detached_installer_pipe_can_close_after_prefix_server_kill(self):
        with TemporaryDirectory() as td:
            root = Path(td)
            wine, prefix, _, launcher, _, _ = self.fixture(root)
            proc = mock.Mock(pid=23120, wait=mock.Mock(return_value=0))
            reader = mock.Mock()
            # Finished Win32 wrapper, detached Wine child still holds stderr.
            # Only killing the marked prefix's server closes the final writer.
            reader.is_alive.side_effect = [True, True, False, False]
            with (
                mock.patch.object(legacy.subprocess, "Popen", return_value=proc),
                mock.patch.object(legacy.threading, "Thread", return_value=reader),
                mock.patch.object(legacy, "_terminate_private_setup_group",
                                  return_value=True) as group,
                mock.patch.object(legacy, "_terminate_private_setup_wineserver",
                                  return_value=True) as server,
            ):
                result = legacy._run_traced(
                    wine, prefix, launcher, ["SYNTHETIC"], timeout=30)
            group.assert_called_once_with(proc)
            server.assert_called_once_with(wine, prefix)
            self.assertEqual(result["setup_cleanup"], "PREFIX_REAPED")
            self.assertEqual(result["status"], "BAD_REPORT")
            self.assertIn(mock.call(timeout=10), reader.join.call_args_list)

    def test_failed_prefix_server_cleanup_still_blocks_all_next_probes(self):
        with TemporaryDirectory() as td:
            root = Path(td)
            wine, prefix, _, launcher, _, _ = self.fixture(root)
            proc = mock.Mock(pid=23121, wait=mock.Mock(
                side_effect=subprocess.TimeoutExpired("Wine", 30)))
            reader = mock.Mock()
            reader.is_alive.return_value = True
            with (
                mock.patch.object(legacy.subprocess, "Popen", return_value=proc),
                mock.patch.object(legacy.threading, "Thread", return_value=reader),
                mock.patch.object(legacy, "_terminate_private_setup_group",
                                  return_value=True),
                mock.patch.object(legacy, "_terminate_private_setup_wineserver",
                                  return_value=False) as server,
            ):
                result = legacy._run_traced(
                    wine, prefix, launcher, ["SYNTHETIC"], timeout=30)
            server.assert_called_once_with(wine, prefix)
            self.assertEqual(result["status"], "TIMEOUT")
            self.assertEqual(result["setup_cleanup"], "UNVERIFIED")

    def test_ci_reports_cleanup_blocker_before_missing_restart(self):
        workflow = (Path(__file__).resolve().parents[1] /
                    ".github/workflows/netfx40-legacy-ci.yml").read_text()
        validator = workflow.split(
            "- name: Validate that msxml3 cannot fabricate a CLR install", 1)[1]
        cleaned = validator.index('if r["status"] == "BLOCKED_INSTALLER_CLEANUP":')
        restart = validator.index('assert restart_path.is_file()')
        self.assertLess(cleaned, restart)
        self.assertIn("CLR, MSI and NGen tests were deliberately blocked",
                      validator[cleaned:restart])

    def test_unclear_cleanup_blocks_all_further_wine_and_clr_probes(self):
        with TemporaryDirectory() as td:
            root = Path(td)
            wine, prefix, installer, launcher, loader, managed = self.fixture(root)
            before = {key: ("ABSENT", None) for key in ITEMS}
            selftest = {
                "status": "EXIT_CAPTURED", "category": "REBOOT_REQUIRED",
                "exit_hex": "00000BC2", "child_seen": "NOT_OBSERVED",
                "child_lifecycle": "NOT_OBSERVED", "child_exit": "NOT_VERIFIED",
            }
            installed = {
                "status": "TIMEOUT", "category": "NOT_AVAILABLE",
                "exit_hex": "NOT_VERIFIED", "child_seen": "NOT_VERIFIED",
                "child_lifecycle": "NOT_VERIFIED", "child_exit": "NOT_VERIFIED",
                "setup_cleanup": "UNVERIFIED",
            }
            with (
                mock.patch.object(legacy, "verify_media"),
                mock.patch.object(legacy, "snapshot", return_value=before) as inventory,
                mock.patch.object(legacy, "set_legacy_winver", return_value="APPLIED"),
                mock.patch.object(legacy, "clear_unbacked_release", return_value="NOT_NEEDED"),
                mock.patch.object(legacy, "inventory", return_value=()),
                mock.patch.object(legacy, "windows_media_path", return_value=r"Z:\\original.exe"),
                mock.patch.object(legacy, "_run", return_value=selftest),
                mock.patch.object(legacy, "_run_traced", return_value=installed),
                mock.patch.object(legacy, "probe") as probe,
                mock.patch.object(legacy, "clr_load") as clr,
                mock.patch.object(legacy, "wineboot_restart") as restart,
            ):
                result = legacy.inspect(
                    wine, prefix, installer, launcher, loader, managed,
                    timeout=330, enable_custom_action_type=True,
                    enable_extended_setup_wait=True,
                )
            self.assertEqual(result["status"], "BLOCKED_INSTALLER_CLEANUP")
            self.assertEqual(result["installer_cleanup"], "UNVERIFIED")
            self.assertTrue(legacy.validate(result))
            self.assertEqual(inventory.call_count, 1)
            clr.assert_not_called()
            probe.assert_not_called()
            restart.assert_not_called()
            self.assertFalse(result["candidate_native40"])
            self.assertFalse(legacy.validate({
                **result, "installer_cleanup": "GROUP_REAPED",
            }))

    def test_unclosed_pipe_cannot_be_treated_as_reaped(self):
        with TemporaryDirectory() as td:
            root = Path(td)
            wine, prefix, _, launcher, _, _ = self.fixture(root)
            child = mock.Mock(pid=23117, wait=mock.Mock(return_value=0))
            reader = mock.Mock()
            reader.is_alive.return_value = True
            with (
                mock.patch.object(legacy.subprocess, "Popen", return_value=child),
                mock.patch.object(legacy.threading, "Thread", return_value=reader),
                mock.patch.object(legacy, "_terminate_private_setup_group", return_value=True),
            ):
                result = legacy._run_traced(wine, prefix, launcher, ["Z:\\vendor.exe"])
            self.assertEqual(result["setup_cleanup"], "UNVERIFIED")
            self.assertEqual(result["custom_action_type"]["capture_reason"], "READER_UNFINISHED")

    def test_report_not_leaking_descendant_process_identifiers(self):
        with TemporaryDirectory() as td:
            root = Path(td)
            wine, prefix, _, launcher, _, _ = self.fixture(root)
            child = mock.Mock(pid=23117, wait=mock.Mock(
                side_effect=subprocess.TimeoutExpired("wine", 390)))
            reader = mock.Mock()
            reader.is_alive.return_value = False
            with (
                mock.patch.object(legacy.subprocess, "Popen", return_value=child),
                mock.patch.object(legacy.threading, "Thread", return_value=reader),
                mock.patch.object(legacy, "_terminate_private_setup_group", return_value=False),
            ):
                result = legacy._run_traced(wine, prefix, launcher, ["Z:\\private.exe"])
            self.assertEqual(result["setup_cleanup"], "UNVERIFIED")
            self.assertNotIn("23117", str(result))
            self.assertNotIn("private.exe", str(result))


if __name__ == "__main__":
    unittest.main()
