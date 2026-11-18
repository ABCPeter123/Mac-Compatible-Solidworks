"""Prove original signed .NET4.8 MSI experiments cannot fabricate 4.8 or 4.8.1."""
import os
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase, mock
import json

from scripts import netfx40_to_48_signed_msi as p


class OriginalSignedMSITests(TestCase):
    def test_private_extracted_packages_require_both_exact_ole_files(self):
        with TemporaryDirectory() as td:
            root = Path(td) / p.TARGET
            self.assertEqual(p.verify_extracted_media(root), "FILES_MISSING")
            root.mkdir()
            msi = root / p.MSI
            msp = root / p.MSP
            msi.write_bytes(b"MZ" * 4096)
            self.assertEqual(p.verify_extracted_media(root), "INVALID_PACKAGE")
            msp.write_bytes(p.OLE_HEADER + b"x" * 8192)
            self.assertEqual(p.verify_extracted_media(root), "INVALID_PACKAGE")
            msi.write_bytes(p.OLE_HEADER + b"x" * 8192)
            self.assertEqual(p.verify_extracted_media(root), "VERIFIED")
            msp.unlink()
            msp.symlink_to(root / "outside.msp")
            self.assertEqual(p.verify_extracted_media(root), "UNSAFE")
            msp.unlink()
            msp.write_bytes(p.OLE_HEADER + b"x" * 8192)
            self.assertEqual(p.verify_extracted_media(root), "VERIFIED")

    def fixture(self, root):
        wine = root / "wine"
        installer = root / "NDP48-x86-x64-AllOS-ENU.exe"
        digest = root / "netfx48.sha256"
        loader = root / "netfx481_clr_load.exe"
        managed = root / "netfx481_runtime_probe.exe"
        prefix = root / "prefix"
        prefix.mkdir()
        (prefix / "drive_c").mkdir()
        for path in (wine, installer, digest, loader, managed):
            path.write_bytes(b"synthetic (NEVER vendor media)")
        wine.chmod(0o700)
        return wine, prefix, installer, digest, loader, managed

    def run_case(self, paths, *, extract="SUCCESS", install="SUCCESS",
                 patch="SUCCESS", changed=True, release="NETFX48_RANGE",
                 valid_media=True, verified_native40=True):
        calls = []
        def fake_run(cmd, env, cwd, timeout):
            calls.append((cmd, timeout))
            if cmd[1] != "msiexec.exe":
                if extract == "SUCCESS" and valid_media:
                    root = paths[1] / "drive_c" / p.TARGET
                    root.mkdir()
                    for filename in (p.MSI, p.MSP):
                        (root / filename).write_bytes(p.OLE_HEADER + b"V" * 8192)
                return extract
            if "/i" in cmd:
                return install
            return patch

        before = {"CLR64": ("PE_AMD64", "original40")}
        after = {"CLR64": ("PE_AMD64", "original48" if changed else "original40")}
        with (mock.patch.object(p, "validate_prefix"),
              mock.patch.object(p, "verify_original_media"),
              mock.patch.object(p, "valid_native40", return_value=True),
              mock.patch.object(p, "snapshot", side_effect=[before, after]),
              mock.patch.object(p, "load_clr", return_value="LOADED"),
              mock.patch.object(p, "probe", return_value={
                  "clr_family": "MICROSOFT_CLR_CANDIDATE", "managed": "PASS"}),
              mock.patch.object(p, "_env", return_value={}),
              mock.patch.object(p, "_set_winver", return_value="APPLIED"),
              mock.patch.object(p, "_release", return_value=release),
              mock.patch.object(p, "wineboot_restart", return_value="COMPLETED"),
              mock.patch.object(p, "private_run", side_effect=fake_run)):
            result = p.inspect(*paths, {"persistent_native_managed": verified_native40})
        self.assertTrue(p.validate(result))
        self.assertEqual(result["solidworks_compatibility"], "NOT_DEMONSTRATED")
        self.assertFalse(result["framework481_confirmed"])
        self.assertNotIn(str(paths[1]), json.dumps(result))
        return result, calls

    def test_only_complete_authentic_msi_and_msp_can_verify_native48(self):
        with TemporaryDirectory() as td:
            result, calls = self.run_case(self.fixture(Path(td)))
            self.assertTrue(result["native48_candidate"])
            self.assertEqual(result["media"], "VERIFIED")
            self.assertEqual(len(calls), 3)
            self.assertIn("/x:C:", calls[0][0][2])
            self.assertEqual(calls[1][0][1:3], ["msiexec.exe", "/i"])
            self.assertEqual(calls[2][0][1:3], ["msiexec.exe", "/p"])
            self.assertIn("EXTUI=1", calls[2][0])
            self.assertIn("/L*v", calls[1][0])
            self.assertEqual(calls[1][1], 420)
            self.assertEqual(result["install_log"]["status"], "NO_LOG")
            self.assertEqual(calls[2][1], 420)
            self.assertFalse(p.validate(dict(result, native48_candidate=False)))
            self.assertFalse(p.validate(dict(result, private_vendor_log="forbidden")))

    def test_failed_original_msi_and_patch_never_upgrade(self):
        for params, want_install, want_patch in (
            ({"extract": "EXIT_NONZERO"}, "NOT_RUN", "NOT_RUN"),
            ({"extract": "TIMED_OUT"}, "NOT_RUN", "NOT_RUN"),
            ({"valid_media": False}, "NOT_RUN", "NOT_RUN"),
            ({"install": "EXIT_NONZERO"}, "EXIT_NONZERO", "NOT_RUN"),
            ({"install": "TIMED_OUT_CLEANUP_DENIED"}, "TIMED_OUT_CLEANUP_DENIED", "NOT_RUN"),
            ({"patch": "TIMED_OUT"}, "SUCCESS", "TIMED_OUT"),
            ({"changed": False}, "SUCCESS", "SUCCESS"),
            ({"release": "NOT_FOUND"}, "SUCCESS", "SUCCESS"),
        ):
            with self.subTest(params=params), TemporaryDirectory() as td:
                result, _ = self.run_case(self.fixture(Path(td)), **params)
                self.assertFalse(result["native48_candidate"])
                self.assertEqual(result["install"], want_install)
                self.assertEqual(result["patch"], want_patch)
        self.assertFalse(p.validate(dict(p.blank(), native48_candidate=True)))
        self.assertFalse(p.validate(dict(p.blank(), media="PRIVATE")))
        self.assertFalse(p.validate(dict(p.blank(), patch="5100 from private path")))

    def test_failed_verification_does_not_execute_installer(self):
        with TemporaryDirectory() as td:
            files = self.fixture(Path(td))
            with (mock.patch.object(p, "validate_prefix"),
                  mock.patch.object(p, "verify_original_media"),
                  mock.patch.object(p, "valid_native40", return_value=True),
                  mock.patch.object(p, "private_run") as run):
                result = p.inspect(*files, {"persistent_native_managed": False})
            self.assertEqual(result, p.blank())
            run.assert_not_called()

    def test_private_original_msi_log_never_escapes_root(self):
        with TemporaryDirectory() as td:
            root = Path(td)
            self.assertEqual(p.classify_private_msi_log(root)["status"], "NO_LOG")
            log = root / p.PRIVATE_LOG
            log.write_bytes(
                b"Action ended 11:01:02: InstallServices. Return value 3.\\n"
                b"Error 1722\\n"
                b"some vendor name and private installation path\\n")
            result = p.classify_private_msi_log(root)
            self.assertEqual(result, {"status": "CLASSIFIED", "failure": True,
                                      "action": "SERVICE", "errors": ["EXTERNAL_ACTION_FAILURE"]})
            self.assertTrue(p.valid_msi_log(result))
            self.assertFalse(log.exists())
            self.assertNotIn("private installation path", str(result))
            self.assertNotIn("some vendor name", str(result))

            log.write_bytes(b"z" * (p.MAX_FILE_BYTES + 1))
            self.assertEqual(p.classify_private_msi_log(root)["status"], "TOO_LARGE")
            self.assertFalse(log.exists())
            fake_target = root / "some-other-file"
            fake_target.write_bytes(b"never read")
            log.symlink_to(fake_target)
            self.assertEqual(p.classify_private_msi_log(root)["status"], "UNSAFE")
            self.assertEqual(fake_target.read_bytes(), b"never read")
            self.assertFalse(p.valid_msi_log({**p.blank_msi_log(),
                                             "status": "CLASSIFIED",
                                             "action": "PRIVATE_SYSTEM_PATH"}))
            self.assertFalse(p.valid_msi_log({**p.blank_msi_log(),
                                             "status": "CLASSIFIED",
                                             "errors": ["PRIVATE_ERROR"]}))

    def test_cleanup_denied_never_runs_more_wine_commands(self):
        with TemporaryDirectory() as td:
            paths = self.fixture(Path(td))
            before = {"CLR64": ("PE_AMD64", "original40")}
            events = []
            def installer(cmd, env, cwd, timeout):
                events.append(cmd[1])
                if cmd[1] != "msiexec.exe":
                    media = paths[1] / "drive_c" / p.TARGET
                    media.mkdir()
                    for name in (p.MSI, p.MSP):
                        (media / name).write_bytes(p.OLE_HEADER + b"x" * 8192)
                    return "SUCCESS"
                return "TIMED_OUT_CLEANUP_DENIED"
            with (mock.patch.object(p, "validate_prefix"),
                  mock.patch.object(p, "verify_original_media"),
                  mock.patch.object(p, "valid_native40", return_value=True),
                  mock.patch.object(p, "snapshot", return_value=before) as snapshots,
                  mock.patch.object(p, "load_clr", return_value="LOADED") as loader,
                  mock.patch.object(p, "probe", return_value={
                      "clr_family": "MICROSOFT_CLR_CANDIDATE", "managed": "PASS"}) as managed,
                  mock.patch.object(p, "_env", return_value={}),
                  mock.patch.object(p, "_set_winver", return_value="APPLIED") as winver,
                  mock.patch.object(p, "_release") as release,
                  mock.patch.object(p, "wineboot_restart") as restart,
                  mock.patch.object(p, "private_run", side_effect=installer)):
                result = p.inspect(*paths, {"persistent_native_managed": True})
            self.assertTrue(p.validate(result))
            self.assertEqual(result["install"], "TIMED_OUT_CLEANUP_DENIED")
            self.assertEqual(result["win10"], "NOT_RUN")
            self.assertFalse(result["native48_candidate"])
            self.assertEqual(events.count("msiexec.exe"), 1)
            self.assertEqual(snapshots.call_count, 1)
            self.assertEqual(loader.call_count, 1)
            self.assertEqual(managed.call_count, 1)
            self.assertEqual(winver.call_count, 1)
            release.assert_not_called()
            restart.assert_not_called()

    def test_private_run_discards_all_original_output(self):
        with TemporaryDirectory() as td:
            fake = mock.Mock()
            fake.wait.return_value = 1603
            with mock.patch.object(p.subprocess, "Popen", return_value=fake) as open_proc:
                self.assertEqual(p.private_run(["wine", "msiexec.exe"],
                                                {}, Path(td), 20), "EXIT_NONZERO")
                self.assertEqual(fake.wait.call_args.kwargs["timeout"], 20)
                self.assertEqual(open_proc.call_args.kwargs["stdin"], p.subprocess.DEVNULL)
                self.assertTrue(open_proc.call_args.kwargs["start_new_session"])
                self.assertNotEqual(open_proc.call_args.kwargs["stdout"], p.subprocess.PIPE)
            fake.wait.side_effect = p.subprocess.TimeoutExpired("wine", 1)
            with (mock.patch.object(p.subprocess, "Popen", return_value=fake),
                  mock.patch.object(p, "_terminate_group") as cleanup):
                self.assertEqual(p.private_run(["wine"], {}, Path(td), 5), "TIMED_OUT")
                cleanup.assert_called_once_with(fake)
            with mock.patch.object(p.subprocess, "Popen", side_effect=OSError):
                self.assertEqual(p.private_run(["wine"], {}, Path(td), 5), "START_FAILED")
            fake.wait.side_effect = [
                p.subprocess.TimeoutExpired("wine", 2), 0,
            ]
            with (mock.patch.object(p.subprocess, "Popen", return_value=fake),
                  mock.patch.object(p, "_terminate_group",
                                    side_effect=PermissionError(1, "Operation not permitted"))):
                self.assertEqual(p.private_run(["wine"], {}, Path(td), 5),
                                 "TIMED_OUT_CLEANUP_DENIED")
                fake.kill.assert_called_once()
