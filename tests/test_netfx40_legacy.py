"""Safety, executable-path and runtime-readiness regressions for real .NET 4.0."""
from __future__ import annotations
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from scripts import netfx40_legacy as legacy
from scripts.netfx481_payload_audit import ITEMS


class Netfx40LegacyTests(unittest.TestCase):
    def test_pinned_microsoft_installer_and_symlink_guard(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            installer = root / "dotNetFx40_Full_x86_x64.exe"
            installer.write_bytes(b"not a signed original")
            with self.assertRaises(ValueError):
                legacy.verify_media(installer)
            unknown = root / "other.exe"
            unknown.write_bytes(b"fake")
            with self.assertRaises(ValueError):
                legacy.verify_media(unknown)
            link = root / "dotnetfx40_full_x86_x64.exe"
            try:
                link.symlink_to(unknown)
            except OSError:
                return
            with self.assertRaises(ValueError):
                legacy.verify_media(link)

    def test_setup_override_is_temporary_and_windows_xp_requested(self):
        env = legacy._env(Path("/dummy"), installation=True)
        self.assertEqual(env["WINEDLLOVERRIDES"], "fusion=b")
        self.assertNotIn("WINEDLLOVERRIDES", legacy._env(Path("/dummy")))
        with mock.patch.object(legacy, "validate_prefix"):
            with mock.patch.object(legacy.subprocess, "run",
                                   return_value=mock.Mock(returncode=0)) as run:
                self.assertEqual(
                    legacy.set_legacy_winver(Path("/wine"), Path("/prefix")),
                    "APPLIED")
                self.assertEqual(run.call_args.args[0][1:],
                                 ["winecfg.exe", "-v", "winxp"])
                self.assertNotIn("WINEDLLOVERRIDES",
                                 run.call_args.kwargs["env"])

    def test_monitor_setup_scopes_fusion_and_resolves_media(self):
        with tempfile.TemporaryDirectory() as tmp:
            fixture = Path(tmp) / "netfx40_win32_launch.exe"
            fixture.write_bytes(b"synthetic only")
            with mock.patch.object(legacy, "validate_prefix"):
                with mock.patch.object(legacy.subprocess, "run",
                                       return_value=mock.Mock(returncode=1)) as run:
                    report = legacy._run(Path("/wine"), Path(tmp), fixture,
                                         ["--selftest-3010"], setup=False)
                    self.assertEqual(report["status"], "BAD_REPORT")
                    self.assertNotIn("WINEDLLOVERRIDES", run.call_args.kwargs["env"])
                with mock.patch.object(legacy.subprocess, "run",
                                       return_value=mock.Mock(returncode=1)) as run:
                    legacy._run(Path("/wine"), Path(tmp), fixture,
                                [r"Z:\safe\dotNetFx40_Full_x86_x64.exe"], setup=True)
                    self.assertEqual(run.call_args.kwargs["env"]["WINEDLLOVERRIDES"], "fusion=b")

    @unittest.skipIf(os.name == "nt", "Original Wine install must never run on Windows")
    def test_monitor_success_cannot_fake_native_clr(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            prefix = root / "prefix"
            (prefix / "drive_c").mkdir(parents=True)
            (prefix / "system.reg").touch()
            (prefix / ".swcompat-netfx481-disposable").touch()
            wine = root / "wine"
            wine.write_bytes(b"test")
            wine.chmod(0o700)
            paths = (
                root / "dotNetFx40_Full_x86_x64.exe",
                root / "netfx40_win32_launch.exe",
                root / "netfx481_clr_load.exe",
                root / "netfx481_runtime_probe.exe",
            )
            for x in paths:
                x.write_bytes(b"fixture")
            absent = {key: ("ABSENT", None) for key in ITEMS}
            samples = [absent, absent]
            test = {"status": "EXIT_CAPTURED", "category": "REBOOT_REQUIRED",
                    "exit_hex": "00000BC2", "child_seen": "NOT_OBSERVED",
                    "child_lifecycle": "NOT_OBSERVED", "child_exit": "NOT_VERIFIED"}
            installed = {"status": "EXIT_CAPTURED", "category": "SUCCESS",
                         "exit_hex": "00000000", "child_seen": "OBSERVED",
                         "child_lifecycle": "ALL_EXITED", "child_exit": "NONZERO"}
            with (
                mock.patch.object(legacy, "verify_media"),
                mock.patch.object(legacy, "snapshot", side_effect=samples),
                mock.patch.object(legacy, "set_legacy_winver", return_value="APPLIED"),
                mock.patch.object(legacy, "clear_unbacked_release", return_value="NOT_NEEDED"),
                mock.patch.object(legacy, "inventory", return_value=()),
                mock.patch.object(legacy, "windows_media_path",
                                  return_value=r"Z:\dummy\dotNetFx40_Full_x86_x64.exe"),
                mock.patch.object(legacy, "_run", side_effect=[test, installed]) as run,
                mock.patch.object(legacy, "probe",
                                  return_value={"clr_family": "MICROSOFT_CLR_CANDIDATE",
                                                "managed": "PASS"}),
                mock.patch.object(legacy, "clr_load", return_value="LOADED"),
                mock.patch.object(legacy, "wineboot_restart", return_value="COMPLETED") as restart,
            ):
                result = legacy.inspect(
                    *(Path(os.path.relpath(p, Path.cwd()))
                      for p in (wine, prefix, *paths)),
                    refresh_scm_after_mono=True)
            restart.assert_called_once()
            self.assertEqual(result["pre_setup_scm_restart"], "COMPLETED")
            self.assertTrue(legacy.validate(result))
            self.assertEqual(result["installer_exit"], "SUCCESS")
            self.assertEqual(result["installer_child_seen"], "OBSERVED")
            self.assertEqual(result["installer_child_lifecycle"], "ALL_EXITED")
            self.assertEqual(result["installer_child_exit"], "NONZERO")
            self.assertEqual(result["installer_status"], "EXIT_CAPTURED")
            self.assertEqual(result["selftest"], "PASS")
            self.assertEqual(result["clr64_after"], "ABSENT")
            self.assertFalse(result["candidate_native40"])
            self.assertFalse(result["netfx481_ready"])
            self.assertEqual(run.call_args_list[1].kwargs["setup"], True)
            self.assertEqual(run.call_args_list[1].args[2], paths[1].resolve())
            self.assertNotIn("dotNetFx40_Full_x86_x64.exe", json.dumps(result))
            self.assertNotIn(str(root), json.dumps(result))
            for key, illegal in [
                ("installer_exit_hex", "/Users/private/serial"),
                ("winver", "FAKE_VERSION"),
                ("mono", "C:\\private"),
                ("clr64_after", "PRIVATE_DLL_PATH"),
                ("candidate_native40", 1),
                ("installer_child_exit", "C:\\fake\\private"),
                ("installer_child_lifecycle", "INVENTED_CHILD"),
                ("netfx481_ready", True),
            ]:
                changed = dict(result)
                changed[key] = illegal
                with self.subTest(key=key):
                    self.assertFalse(legacy.validate(changed))

    @unittest.skipIf(os.name == "nt", "Only marked disposable Wine prefixes")
    def test_failed_scm_refresh_blocks_original_microsoft_setup(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            prefix = root / "prefix"
            (prefix / "drive_c").mkdir(parents=True)
            (prefix / "system.reg").touch()
            (prefix / ".swcompat-netfx481-disposable").touch()
            wine = root / "wine"; wine.write_bytes(b"mock"); wine.chmod(0o700)
            exe = root / "dotNetFx40_Full_x86_x64.exe"
            launcher = root / "netfx40_win32_launch.exe"
            loader = root / "netfx481_clr_load.exe"
            managed = root / "netfx481_runtime_probe.exe"
            for item in (exe, launcher, loader, managed):
                item.write_bytes(b"fixture")
            absent = {key: ("ABSENT", None) for key in ITEMS}
            with (
                mock.patch.object(legacy, "verify_media"),
                mock.patch.object(legacy, "snapshot", return_value=absent),
                mock.patch.object(legacy, "set_legacy_winver", return_value="APPLIED"),
                mock.patch.object(legacy, "clear_unbacked_release", return_value="NOT_NEEDED"),
                mock.patch.object(legacy, "inventory", return_value=()),
                mock.patch.object(legacy, "wineboot_restart", return_value="TIMED_OUT") as restart,
                mock.patch.object(legacy, "_run") as original,
            ):
                r = legacy.inspect(wine, prefix, exe, launcher, loader, managed,
                                   refresh_scm_after_mono=True)
                restart.assert_called_once()
                original.assert_not_called()
            self.assertEqual(r["status"], "BLOCKED_SCM_RESTART")
            self.assertEqual(r["installer_status"], "NOT_RUN")
            self.assertEqual(r["pre_setup_scm_restart"], "TIMED_OUT")
            self.assertTrue(legacy.validate(r))
            self.assertFalse(legacy.validate(dict(r, pre_setup_scm_restart="FORGED")))
            self.assertFalse(legacy.validate(dict(r, installer_status="EXIT_CAPTURED")))

    def test_incomplete_trace_candidate_requires_exact_reader_unfinished(self):
        result = {"status": "EXIT_CAPTURED", "category": "MSI_FATAL_ERROR"}
        good = {"overflow": False, "lines": 2, "reason": "NONE"}
        self.assertTrue(legacy._may_store_incomplete_action(True, good, result))
        partial = {"overflow": True, "lines": 2, "reason": "READER_UNFINISHED"}
        self.assertTrue(legacy._may_store_incomplete_action(True, partial, result))
        self.assertFalse(legacy._may_store_incomplete_action(False, partial, result))
        self.assertFalse(legacy._may_store_incomplete_action(True, partial,
                          dict(result, category="SUCCESS")))
        for reason in ("LINE_LIMIT", "BYTE_LIMIT", "PROCESS_INCOMPLETE", "UNKNOWN"):
            self.assertFalse(legacy._may_store_incomplete_action(
                True, dict(partial, reason=reason), result))
        self.assertFalse(legacy._may_store_incomplete_action(
            True, dict(partial, lines=0), result))
        self.assertFalse(legacy._may_store_incomplete_action(
            True, dict(partial, lines=legacy.MAX_RETAINED_LINES), result))
        self.assertFalse(legacy._may_store_incomplete_action(
            True, dict(partial, lines=True), result))

    def test_rejects_unmarked_prefix(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)
            with self.assertRaises(ValueError):
                legacy.set_legacy_winver(path / "wine", path / "prefix")


if __name__ == "__main__":
    unittest.main()
