"""Prove original signed .NET4.8 MSI experiments cannot fabricate 4.8 or 4.8.1."""
import os
import subprocess
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
        (prefix / "drive_c" / "windows").mkdir(parents=True)
        for path in (wine, installer, digest, loader, managed):
            path.write_bytes(b"synthetic (NEVER vendor media)")
        wine.chmod(0o700)
        return wine, prefix, installer, digest, loader, managed

    def run_case(self, paths, *, extract="SUCCESS", install="SUCCESS",
                 patch="SUCCESS", changed=True, release="NETFX48_RANGE",
                 valid_media=True, verified_native40=True, scm=False,
                 post_scm=None, prepare_cache=False, ngen_bytes=None,
                 msi_timeout_seconds=420, pause_queue=False,
                 pause_failure=None, resume_failure=None,
                 patch_log_bytes=None, patch_process_code=67):
        calls = []
        if pause_queue:
            prefix = paths[1]
            (prefix / ".swcompat-netfx481-disposable").touch()
            (prefix / "system.reg").write_text("synthetic")
            for arch in ("Framework64", "Framework"):
                ngen = prefix / "drive_c" / "windows" / "Microsoft.NET" / arch / "v4.0.30319" / "ngen.exe"
                ngen.parent.mkdir(parents=True, exist_ok=True)
                ngen.write_bytes(b"MZ" + b"x" * 4998)
        def fake_run(cmd, env, cwd, timeout, *, progress=None,
                     on_exit_code=None):
            calls.append((cmd, timeout))
            if len(cmd) >= 4 and cmd[2] == "queue":
                if cmd[3] == "pause" and pause_failure is not None and "Framework/" in cmd[1]:
                    return pause_failure
                if cmd[3] == "continue" and resume_failure is not None and "Framework/" in cmd[1]:
                    return resume_failure
                return "SUCCESS"
            if cmd[1] != "msiexec.exe":
                if extract == "SUCCESS" and valid_media:
                    root = paths[1] / "drive_c" / p.TARGET
                    root.mkdir()
                    for filename in (p.MSI, p.MSP):
                        (root / filename).write_bytes(p.OLE_HEADER + b"V" * 8192)
                return extract
            if "/i" in cmd:
                if ngen_bytes is not None:
                    ngen_log = paths[1] / "drive_c" / "windows" / "Microsoft.NET" / "Framework64" / "v4.0.30319" / "ngen.log"
                    ngen_log.parent.mkdir(parents=True, exist_ok=True)
                    ngen_log.write_bytes(ngen_bytes)
                if progress is not None:
                    progress()
                return install
            if patch_log_bytes is not None:
                (paths[1] / "drive_c" / p.TARGET / p.PATCH_PRIVATE_LOG).write_bytes(
                    patch_log_bytes)
            if on_exit_code is not None and patch in {"SUCCESS", "EXIT_NONZERO"}:
                on_exit_code(0 if patch == "SUCCESS" else patch_process_code)
            return patch

        before = {"CLR64": ("PE_AMD64", "original40")}
        after = {"CLR64": ("PE_AMD64", "original48" if changed else "original40")}
        scm_before = {"status": "COMPLETE", "services": {
            k: ("PRESENT" if k == "MSISERVER" else "ABSENT")
            for k in p.blank_scm()["services"]},
            "states": {
                k: ("STOPPED" if k == "MSISERVER" else "NOT_APPLICABLE")
                for k in p.blank_scm()["services"]}}
        scm_after = post_scm if post_scm is not None else scm_before
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
              mock.patch.object(p, "private_run", side_effect=fake_run),
              mock.patch.object(p, "selftest_scm", return_value="PASS"),
              mock.patch.object(p, "measure_scm",
                                side_effect=[scm_before, scm_after])):
            service_path = paths[0].parent / "netfx48_scm_service_probe.exe"
            if scm:
                service_path.write_bytes(b"self authored original fixture")
            result = p.inspect(
                *paths, {"persistent_native_managed": verified_native40},
                service_fixture=service_path if scm else None,
                prepare_assembly_cache=prepare_cache,
                msi_timeout_seconds=msi_timeout_seconds,
                pause_native_ngen_queue=pause_queue)
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
            self.assertEqual(result["patch_log"]["status"], "NO_LOG")
            self.assertEqual(result["patch_exit_lowbyte"], 0)
            self.assertIn("/L*v", calls[2][0])
            self.assertEqual(calls[2][1], 420)
            self.assertFalse(p.validate(dict(result, native48_candidate=False)))
            self.assertFalse(p.validate(dict(result, private_vendor_log="forbidden")))

    def test_nonzero_original_msp_lowbyte_and_private_verbose_log_are_classified(self):
        with TemporaryDirectory() as td:
            prefix = self.fixture(Path(td))
            private_bytes = (
                b"Action start 12:03:22: CA_Ngen_x86.36\n"
                b"Error 1642, original-private-patch-target path\n"
            )
            result, calls = self.run_case(
                prefix, patch="EXIT_NONZERO", patch_process_code=106,
                patch_log_bytes=private_bytes)
            self.assertEqual(result["install"], "SUCCESS")
            self.assertEqual(result["patch"], "EXIT_NONZERO")
            # Runtime must be checked after a clean Wine reboot even if
            # the original signed patch failed and cannot authorize 4.8.
            self.assertEqual(result["restart"], "COMPLETED")
            self.assertEqual(result["loader"], "LOADED")
            self.assertEqual(result["native_only_managed"], "PASS")
            # POSIX status 106 is also 1642 modulo 256. Do NOT claim
            # Windows Installer's full 1642 without an independent source.
            self.assertEqual(result["patch_exit_lowbyte"], 106)
            self.assertEqual(result["patch_log"]["status"], "CLASSIFIED")
            self.assertEqual(result["patch_log"]["custom_action_detail"], "NGEN")
            self.assertEqual(result["patch_log"]["ngen_custom_action_arch"], "X86")
            self.assertFalse(result["native48_candidate"])
            self.assertTrue(p.validate(result))
            self.assertFalse((prefix[1] / "drive_c" / p.TARGET /
                              p.PATCH_PRIVATE_LOG).exists())
            self.assertNotIn("original-private-patch-target", str(result))
            self.assertFalse(p.validate({**result, "native48_candidate": True}))
            self.assertFalse(p.validate({**result, "patch_exit_lowbyte": 0}))
            self.assertEqual(len(calls), 3)

    def test_original_msp_target_not_found_from_private_engine_status_only(self):
        with TemporaryDirectory() as td:
            paths = self.fixture(Path(td))
            result, calls = self.run_case(
                paths, patch="EXIT_NONZERO", patch_process_code=106,
                patch_log_bytes=(
                    b"MSI (s): MainEngineThread is returning 1642\\n"
                    b"PRIVATE_ORIGINAL_PATCH_TARGET_INFORMATION\\n"
                ))
            self.assertEqual(result["patch"], "EXIT_NONZERO")
            self.assertEqual(result["patch_exit_lowbyte"], 106)
            self.assertEqual(result["patch_log"]["errors"],
                             ["PATCH_TARGET_NOT_FOUND"])
            self.assertTrue(p.validate(result))
            self.assertFalse(result["native48_candidate"])
            self.assertNotIn("PRIVATE_ORIGINAL_PATCH_TARGET_INFORMATION",
                             str(result))
            self.assertFalse((paths[1] / "drive_c" / p.TARGET /
                              p.PATCH_PRIVATE_LOG).exists())

    def test_untrusted_msp_lowbyte_and_unrun_patch_report_fail_closed(self):
        clean = p.blank()
        for value in (-1, 256, True, None, [], {}, "1642", "PRIVATE"):
            with self.subTest(value=value):
                self.assertFalse(p.validate({**clean, "patch_exit_lowbyte": value}))
        self.assertFalse(p.validate({
            **clean, "patch_log": {**p.blank_msi_log(), "status": "NO_LOG"}}))
        self.assertFalse(p.validate({
            **clean, "patch": "EXIT_NONZERO",
            "patch_exit_lowbyte": 106,
            "patch_log": p.blank_msi_log()}))

    def test_private_msp_log_requires_allowlisted_filename(self):
        with TemporaryDirectory() as td:
            root = Path(td)
            real = root / "vendor-private.msp"
            real.write_bytes(b"do not read")
            with self.assertRaises(ValueError):
                p.classify_private_msi_log(root, filename=real.name)
            self.assertEqual(real.read_bytes(), b"do not read")
            patch_log = root / p.PATCH_PRIVATE_LOG
            patch_log.write_bytes(
                b"Action start 11:12:34: CA_Ngen_x64.36\n"
                b"Error 1603, PII-PATH-NOT-TO-BE-EXPORTED\n")
            result = p.classify_private_msi_log(
                root, filename=p.PATCH_PRIVATE_LOG)
            self.assertEqual(result["status"], "CLASSIFIED")
            self.assertEqual(result["ngen_custom_action_arch"], "X64")
            self.assertNotIn("PII-PATH", str(result))
            self.assertFalse(patch_log.exists())
            other = root / "unrelated-private"
            other.write_bytes(b"not deleted")
            patch_log.symlink_to(other)
            blocked = p.classify_private_msi_log(
                root, filename=p.PATCH_PRIVATE_LOG)
            self.assertEqual(blocked["status"], "UNSAFE")
            self.assertEqual(other.read_bytes(), b"not deleted")

    def test_patch_exit_callback_observes_only_host_process_code(self):
        with TemporaryDirectory() as td:
            fake = mock.Mock()
            fake.wait.return_value = 106
            lowbytes = []
            with mock.patch.object(p.subprocess, "Popen", return_value=fake):
                outcome = p.private_run(
                    ["wine", "msiexec.exe", "/p", "ORIGINAL.msp"],
                    {}, Path(td), 15, on_exit_code=lowbytes.append)
            self.assertEqual(outcome, "EXIT_NONZERO")
            self.assertEqual(lowbytes, [106])

    def test_native_original_scm_measurement_cannot_fabricate_48_success(self):
        with TemporaryDirectory() as td:
            data, _ = self.run_case(
                self.fixture(Path(td)), scm=True, install="TIMED_OUT",
                changed=True, release="NETFX48_RANGE")
            self.assertTrue(p.validate(data))
            self.assertEqual(data["scm_startup"], "PASS")
            self.assertEqual(data["scm_preflight"]["status"], "COMPLETE")
            self.assertEqual(data["scm_preflight"]["services"]["MSISERVER"], "PRESENT")
            self.assertEqual(data["scm_preflight"]["states"]["MSISERVER"], "STOPPED")
            self.assertEqual(data["scm_preflight"]["services"]["CLR_OPTIMIZATION_64"], "ABSENT")
            self.assertEqual(data["scm_postflight"]["status"], "COMPLETE")
            self.assertEqual(data["scm_postflight"]["services"]["CLR_OPTIMIZATION_64"], "ABSENT")
            self.assertFalse(data["native48_candidate"])
            self.assertFalse(p.validate(dict(data, scm_startup="PRIVATE")))
            self.assertFalse(p.validate(dict(data, scm_preflight={"service": "private"})))
            self.assertFalse(p.validate(dict(data, scm_postflight={"service": "private"})))

    def test_authentic_msi_service_transition_is_observed_not_install_success(self):
        with TemporaryDirectory() as td:
            services = {k: "ABSENT" for k in p.blank_scm()["services"]}
            services["MSISERVER"] = "PRESENT"
            services["CLR_OPTIMIZATION_64"] = "PRESENT"
            after = {"status": "COMPLETE", "services": services,
                     "states": {k: ("STOPPED" if v == "PRESENT" else "NOT_APPLICABLE")
                                for k, v in services.items()}}
            result, _ = self.run_case(
                self.fixture(Path(td)), scm=True, install="TIMED_OUT",
                changed=True, release="NETFX48_RANGE", post_scm=after)
            self.assertEqual(result["scm_preflight"]["services"]["CLR_OPTIMIZATION_64"], "ABSENT")
            self.assertEqual(result["scm_postflight"]["services"]["CLR_OPTIMIZATION_64"], "PRESENT")
            self.assertFalse(result["native48_candidate"])
            self.assertTrue(p.validate(result))
            self.assertFalse(p.validate(dict(result, scm_postflight={"status": "COMPLETE", "services": {"PRIVATE": "PRESENT"}})))
            self.assertFalse(p.validate(dict(result, scm_postflight={**result["scm_postflight"], "states": {**result["scm_postflight"]["states"], "CLR_OPTIMIZATION_64": "NOT_APPLICABLE"}})))

    def test_denied_installer_cleanup_forbids_postflight_wine_probe(self):
        with TemporaryDirectory() as td:
            result, _ = self.run_case(
                self.fixture(Path(td)), scm=True,
                install="TIMED_OUT_CLEANUP_DENIED")
            self.assertEqual(result["scm_preflight"]["status"], "COMPLETE")
            self.assertEqual(result["scm_postflight"], p.blank_scm())
            self.assertFalse(result["native48_candidate"])
            self.assertFalse(p.validate(dict(result, scm_postflight=result["scm_preflight"])))

    def test_reaped_msi_timeout_allows_read_only_postflight_but_not_patch(self):
        with TemporaryDirectory() as td:
            result, calls = self.run_case(
                self.fixture(Path(td)), scm=True,
                install="TIMED_OUT_PREFIX_REAPED",
                changed=True, release="NETFX48_RANGE")
            self.assertEqual(result["install"], "TIMED_OUT_PREFIX_REAPED")
            self.assertEqual(result["patch"], "NOT_RUN")
            self.assertEqual(result["restart"], "NOT_RUN")
            self.assertEqual(result["scm_postflight"]["status"], "COMPLETE")
            self.assertEqual(result["win10"], "APPLIED")
            self.assertFalse(result["native48_candidate"])
            self.assertTrue(p.validate(result))
            self.assertEqual(len([command for command in calls
                                  if command[0][1] == "msiexec.exe"]), 1)
            self.assertFalse(p.validate({
                **result, "native48_candidate": True}))

    def test_patch_cleanup_denial_preserves_prior_msi_observation(self):
        with TemporaryDirectory() as td:
            result, _ = self.run_case(
                self.fixture(Path(td)), scm=True,
                patch="TIMED_OUT_CLEANUP_DENIED")
            self.assertEqual(result["install"], "SUCCESS")
            self.assertEqual(result["scm_postflight"]["status"], "COMPLETE")
            self.assertFalse(result["native48_candidate"])
            self.assertTrue(p.validate(result))

    def test_opt_in_ngen_cache_creates_only_directory_not_success(self):
        with TemporaryDirectory() as td:
            paths = self.fixture(Path(td))
            result, _ = self.run_case(
                paths, prepare_cache=True, install="TIMED_OUT",
                changed=True, release="NETFX48_RANGE")
            self.assertEqual(result["cache_policy"], "PREPARE")
            self.assertEqual(result["cache_state"], "CREATED")
            self.assertTrue((paths[1] / "drive_c" / "windows" / "assembly").is_dir())
            self.assertFalse(result["native48_candidate"])
            self.assertTrue(p.validate(result))
            self.assertFalse(p.validate(dict(result, cache_policy="OBSERVE")))

    def test_observation_only_does_not_modify_cache(self):
        with TemporaryDirectory() as td:
            paths = self.fixture(Path(td))
            result, _ = self.run_case(paths, install="TIMED_OUT")
            self.assertEqual(result["cache_policy"], "OBSERVE")
            self.assertEqual(result["cache_state"], "MISSING")
            self.assertFalse((paths[1] / "drive_c" / "windows" / "assembly").exists())
            self.assertFalse(result["native48_candidate"])

    def test_signed_msi_ngen_errors_are_finite_not_proof_of_success(self):
        with TemporaryDirectory() as td:
            result, _ = self.run_case(
                self.fixture(Path(td)), install="TIMED_OUT",
                changed=True, release="NETFX48_RANGE",
                ngen_bytes=b"Compiling assembly PRIVATE_PATH\\n"
                           b"Ngen failed to generate native code 0x80070003\\n")
            self.assertEqual(result["ngen_log"]["x64"], "CLASSIFIED")
            self.assertEqual(result["ngen_log"]["signals"], [
                "NGEN_COMPILE", "NGEN_FAILURE", "PATH_NOT_FOUND"])
            self.assertTrue(p.validate(result))
            self.assertFalse(result["native48_candidate"])
            self.assertNotIn("PRIVATE_PATH", str(result))
            self.assertFalse(p.validate(dict(result, ngen_log={
                **result["ngen_log"], "signals": ["VENDOR_LOG"]})))

    def test_long_ngen_budget_is_opt_in_and_never_proves_msi_completion(self):
        with TemporaryDirectory() as td:
            result, calls = self.run_case(
                self.fixture(Path(td)), install="TIMED_OUT",
                changed=True, release="NETFX48_RANGE",
                msi_timeout_seconds=1200)
            self.assertEqual(result["msi_timeout_seconds"], 1200)
            self.assertEqual(calls[1][1], 1200)
            self.assertEqual(result["install"], "TIMED_OUT")
            self.assertFalse(result["native48_candidate"])
            self.assertTrue(p.validate(result))
            self.assertFalse(p.validate(dict(result, msi_timeout_seconds=1500)))
            self.assertFalse(p.validate(dict(result, msi_timeout_seconds=True)))

    def test_bad_original_msi_budgets_fail_before_media_or_wine(self):
        with TemporaryDirectory() as td:
            paths = self.fixture(Path(td))
            for timeout in (60, 719, 1800, True, "1200"):
                with self.subTest(timeout=timeout):
                    with self.assertRaises(ValueError):
                        p.inspect(*paths, {"persistent_native_managed": True},
                                  msi_timeout_seconds=timeout)

    def test_authenticated_msi_samples_only_finite_private_ngen_growth(self):
        with TemporaryDirectory() as td:
            result, _ = self.run_case(
                self.fixture(Path(td)), install="TIMED_OUT",
                ngen_bytes=b"Original private assembly name and user path",
                msi_timeout_seconds=1200)
            self.assertEqual(result["ngen_progress"]["status"], "OBSERVED")
            self.assertEqual(result["ngen_progress"]["samples"], 2)
            self.assertEqual(result["ngen_progress"]["x64_growth_windows"], 1)
            self.assertEqual(result["ngen_progress"]["x64_last"], "UNCHANGED")
            self.assertEqual(result["ngen_progress"]["x86_growth_windows"], 0)
            self.assertTrue(p.validate(result))
            self.assertFalse(result["native48_candidate"])
            self.assertNotIn("Original private assembly", str(result))
            self.assertFalse(p.validate(dict(result, ngen_progress={
                **result["ngen_progress"], "x86_last": "PRIVATE"})))

    def test_real_ngen_queue_pause_resumes_without_bypassing_signed_msi(self):
        with TemporaryDirectory() as td:
            data, calls = self.run_case(self.fixture(Path(td)), pause_queue=True)
            self.assertEqual(data["ngen_queue_policy"], "PAUSE")
            self.assertEqual(data["ngen_queue"]["status"], "COMPLETE")
            self.assertTrue(data["native48_candidate"])
            operations = [c[0][-1] if len(c[0]) >= 4 and c[0][2] == "queue"
                          else Path(c[0][1]).name for c in calls]
            self.assertEqual(operations, [
                "NDP48-x86-x64-AllOS-ENU.exe", "pause", "pause",
                "msiexec.exe", "msiexec.exe", "continue", "continue"])
            self.assertEqual(len(calls), 7)

    def test_failed_original_ngen_pause_aborts_signed_msi_and_restores(self):
        with TemporaryDirectory() as td:
            data, calls = self.run_case(
                self.fixture(Path(td)), pause_queue=True,
                pause_failure="EXIT_NONZERO")
            self.assertEqual(data["ngen_queue"]["status"], "INCOMPLETE")
            self.assertEqual(data["install"], "NOT_RUN")
            self.assertEqual(data["patch"], "NOT_RUN")
            self.assertFalse(data["native48_candidate"])
            self.assertFalse(any("msiexec.exe" in c[0] for c in calls))
            self.assertTrue(p.validate(data))

    def test_original_ngen_resume_failure_blocks_verified_runtime(self):
        with TemporaryDirectory() as td:
            data, calls = self.run_case(
                self.fixture(Path(td)), pause_queue=True,
                resume_failure="EXIT_NONZERO")
            self.assertEqual(data["install"], "SUCCESS")
            self.assertEqual(data["ngen_queue"]["status"], "INCOMPLETE")
            self.assertEqual(data["patch"], "SUCCESS")
            self.assertFalse(data["native48_candidate"])
            self.assertTrue(p.validate(data))
            self.assertFalse(p.validate({**data, "native48_candidate": True}))

    def test_original_ngen_denied_cleanup_forbids_more_wine_commands(self):
        with TemporaryDirectory() as td:
            data, calls = self.run_case(
                self.fixture(Path(td)), pause_queue=True,
                install="TIMED_OUT_CLEANUP_DENIED")
            self.assertEqual(data["ngen_queue"]["status"], "DIRTY")
            self.assertEqual(data["win10"], "NOT_RUN")
            self.assertEqual(data["patch"], "NOT_RUN")
            self.assertFalse(data["native48_candidate"])
            self.assertEqual(len([c for c in calls if c[0][1] == "msiexec.exe"]), 1)
            self.assertFalse(any(len(c[0]) >= 4 and c[0][2] == "queue"
                                 and c[0][3] == "continue" for c in calls))
            self.assertTrue(p.validate(data))

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
                b"Action ended 11:01:02: InstallServices. Return value 3.\n"
                b"Error 1722\n"
                b"some vendor name and private installation path\n")
            result = p.classify_private_msi_log(root)
            self.assertEqual(result, {"status": "CLASSIFIED", "failure": True,
                                      "action": "SERVICE",
                                      "last_started_action": "UNKNOWN",
                                      "errors": ["EXTERNAL_ACTION_FAILURE"],
                                      **p.blank_service_evidence()})
            self.assertTrue(p.valid_msi_log(result))
            self.assertFalse(log.exists())
            self.assertNotIn("private installation path", str(result))
            self.assertNotIn("some vendor name", str(result))

            log.write_bytes(
                b"Action start 12:22:23: InstallFiles.\n"
                b"Action start 12:23:10: InstallServices.\n")
            pending = p.classify_private_msi_log(root)
            self.assertEqual(pending["action"], "UNKNOWN")
            self.assertEqual(pending["last_started_action"], "SERVICE")
            self.assertFalse(pending["failure"])
            self.assertTrue(p.valid_msi_log(pending))
            self.assertEqual(p.last_started_action(
                b"Doing action: MsiInstallService"), "SERVICE")
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
            def installer(cmd, env, cwd, timeout, *, progress=None):
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
            self.assertEqual(result["ngen_log"], p.blank_ngen())
            self.assertEqual(result["ngen_progress"], p.blank_progress())
            self.assertEqual(events.count("msiexec.exe"), 1)
            self.assertEqual(snapshots.call_count, 1)
            self.assertEqual(loader.call_count, 1)
            self.assertEqual(managed.call_count, 1)
            self.assertEqual(winver.call_count, 1)
            release.assert_not_called()
            restart.assert_not_called()

    def test_private_run_samples_at_timeout_without_exposing_child_output(self):
        with TemporaryDirectory() as td:
            fake = mock.Mock()
            fake.wait.side_effect = p.subprocess.TimeoutExpired("wine", 60)
            callback = mock.Mock()
            with (mock.patch.object(p.subprocess, "Popen", return_value=fake),
                  mock.patch.object(p, "_terminate_group") as cleanup,
                  mock.patch.object(p.time, "monotonic",
                                    side_effect=[0, 0, 61])):
                outcome = p.private_run(["wine"], {}, Path(td), 60,
                                        progress=callback)
            self.assertEqual(outcome, "TIMED_OUT")
            self.assertEqual(callback.call_count, 1)
            cleanup.assert_called_once_with(fake)
            self.assertEqual(fake.wait.call_args.kwargs["timeout"], 60)

    def test_real_msi_timeout_reaps_the_isolated_wineserver_before_reading_logs(self):
        with TemporaryDirectory() as td:
            prefix = Path(td)
            engine = prefix / "engine" / "wine"
            fake = mock.Mock()
            fake.wait.side_effect = subprocess.TimeoutExpired("msiexec.exe", 420)
            received = []
            def safe_scan(data):
                # Raw vendor text is visible only inside a private callback,
                # never as an installer result or published report.
                received.append(len(data))
            with (mock.patch.object(p.subprocess, "Popen", return_value=fake),
                  mock.patch.object(p, "_terminate_group",
                                    side_effect=PermissionError("group denied")) as group,
                  mock.patch.object(p, "_terminate_private_setup_wineserver",
                                    return_value=True) as server):
                outcome = p.private_run(
                    [str(engine), "msiexec.exe", "/i", "ORIGINAL_SIGNED.msi"],
                    {"WINEPREFIX": str(prefix)}, prefix, 420,
                    on_diagnostic=safe_scan)
            self.assertEqual(outcome, "TIMED_OUT_PREFIX_REAPED")
            group.assert_called_once_with(fake)
            server.assert_called_once_with(engine, prefix)
            fake.kill.assert_called_once()
            self.assertEqual(received, [0])
            self.assertIn("TIMED_OUT_PREFIX_REAPED", p.STEPS)
            self.assertNotIn("ORIGINAL_SIGNED.msi", outcome)

    def test_msi_timeout_requires_wineserver_reap_even_if_group_kill_succeeds(self):
        with TemporaryDirectory() as td:
            prefix = Path(td)
            wine = prefix / "engine" / "wine"
            fake = mock.Mock()
            fake.wait.side_effect = subprocess.TimeoutExpired("msiexec.exe", 420)
            callback = mock.Mock()
            for server_clean, expected in (
                (False, "TIMED_OUT_CLEANUP_DENIED"),
                (True, "TIMED_OUT_PREFIX_REAPED"),
            ):
                with (mock.patch.object(p.subprocess, "Popen", return_value=fake),
                      mock.patch.object(p, "_terminate_group") as group,
                      mock.patch.object(p, "_terminate_private_setup_wineserver",
                                        return_value=server_clean) as stop):
                    actual = p.private_run(
                        [str(wine), "msiexec.exe", "/i", "ORIGINAL_SIGNED.msi"],
                        {"WINEPREFIX": str(prefix)}, prefix, 420,
                        on_diagnostic=callback)
                self.assertEqual(actual, expected)
                group.assert_called_once_with(fake)
                stop.assert_called_once_with(wine, prefix)
            self.assertEqual(callback.call_count, 1)
            self.assertNotIn("ORIGINAL_SIGNED.msi", actual)

    def test_msi_timeout_refuses_wrong_prefix_without_wineserver_action(self):
        with TemporaryDirectory() as td:
            prefix = Path(td)
            fake = mock.Mock()
            fake.wait.side_effect = subprocess.TimeoutExpired("msiexec.exe", 420)
            with (mock.patch.object(p.subprocess, "Popen", return_value=fake),
                  mock.patch.object(p, "_terminate_group"),
                  mock.patch.object(p, "_terminate_private_setup_wineserver") as stop):
                actual = p.private_run(
                    ["wine", "msiexec.exe", "/p", "original.msp"],
                    {"WINEPREFIX": str(prefix / "other-prefix")}, prefix, 420)
            self.assertEqual(actual, "TIMED_OUT_CLEANUP_DENIED")
            stop.assert_not_called()

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
