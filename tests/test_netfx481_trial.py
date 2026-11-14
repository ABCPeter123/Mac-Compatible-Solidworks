"""Synthetic checks for .NET 4.8.1 evidence. No Microsoft payloads or licenses."""
import json
from pathlib import Path
import tempfile
from unittest import mock
import unittest

from scripts import netfx481_trial as trial


def state(*, registry="AT_LEAST_481", runtime="MICROSOFT_CLR_CANDIDATE",
          managed="PASS"):
    return {"registry": registry, "clr_family": runtime, "managed": managed}


def raw(*, registry="AT_LEAST_481", runtime="MICROSOFT_CLR_CANDIDATE",
        managed="PASS"):
    return ("\n".join([
        "SWCOMPAT_NETFX481_SCHEMA=1",
        "SWCOMPAT_NETFX481_REGISTRY=" + registry,
        "SWCOMPAT_NETFX481_CLR_FAMILY=" + runtime,
        "SWCOMPAT_NETFX481_MANAGED=" + managed,
    ]) + "\n").encode("ascii")


class DotNet481Tests(unittest.TestCase):
    def test_strict_probe_parser(self):
        self.assertEqual(trial.parse_probe(raw(), 0), state())
        self.assertEqual(trial.parse_probe(raw(managed="FAIL"), 1)["managed"], "FAIL")

    def test_duplicate_unknown_or_truncated_fails_closed(self):
        bad = [raw() + raw(), raw() + b"SWCOMPAT_NETFX481_SCHEMA=1\n",
               raw() + b"SWCOMPAT_NETFX481_REGISTRY=HACKED\n",
               raw() + b"\0", b"SWCOMPAT_NETFX481_SCHEMA=1\n", raw() * 50]
        for evidence in bad:
            with self.subTest(evidence=evidence[:32]):
                self.assertEqual(trial.parse_probe(evidence, 0)["registry"], "NOT_VERIFIED")

    def test_failed_process_cannot_claim_pass(self):
        self.assertEqual(trial.parse_probe(raw(), 1)["managed"], "NOT_VERIFIED")
        self.assertEqual(trial.parse_probe(raw(managed="FAIL"), 0)["managed"], "NOT_VERIFIED")
        self.assertEqual(trial.parse_probe(raw(), 124)["managed"], "NOT_VERIFIED")

    def test_wine_mono_and_registry_spoof_are_not_native_framework(self):
        self.assertFalse(trial.runtime_ready(state(runtime="MONO")))
        self.assertFalse(trial.runtime_ready(state(managed="FAIL")))
        self.assertFalse(trial.runtime_ready(state(registry="NOT_FOUND")))
        self.assertFalse(trial.runtime_ready(state(registry="BELOW_481")))
        self.assertTrue(trial.runtime_ready(state()))

    def test_native_loading_can_explain_mono_default_but_never_overclaim(self):
        result = trial.combine(
            state(registry="NOT_FOUND"), state(runtime="MONO"),
            "EXIT_ZERO", 0,
            native_first=state(runtime="MONO"), native_only=state(),
        )
        self.assertFalse(result["framework_runtime_ready"])
        self.assertFalse(result["native_first_runtime_ready"])
        self.assertTrue(result["native_only_runtime_ready"])
        self.assertTrue(result["runtime_ready_with_controlled_override"])
        self.assertTrue(result["new_framework_installation_confirmed"])
        self.assertEqual(result["after"]["clr_family"], "MONO")

    def test_invalid_dll_override_rejected_before_execution(self):
        with self.assertRaisesRegex(ValueError, "Unknown controlled"):
            trial.probe(Path("wine"), Path("prefix"), Path("probe.exe"), override="UNSAFE")

    def test_native_preference_does_not_change_process_wine_environment_globally(self):
        before = dict(trial.os.environ)
        payload = raw()
        def fake_run(args, **kwargs):
            self.assertEqual(kwargs["env"]["WINEDLLOVERRIDES"], "mscoree=n,b;clr=n,b")
            kwargs["stdout"].write(payload)
            return mock.Mock(returncode=0)
        with mock.patch.object(trial.subprocess, "run", side_effect=fake_run):
            result = trial.probe(Path("wine"), Path("prefix"), Path("fixture.exe"),
                                 override="native_first")
        self.assertEqual(result["managed"], "PASS")
        self.assertEqual(dict(trial.os.environ), before)

    def test_exit_zero_is_not_runtime_success(self):
        result = trial.combine(state(runtime="MONO"), state(runtime="MONO"), "EXIT_ZERO", 0)
        self.assertFalse(result["framework_runtime_ready"])
        self.assertFalse(result["new_framework_installation_confirmed"])
        self.assertTrue(result["registry_signal_only"])

    def test_real_transition_does_require_runtime_and_successful_install(self):
        result = trial.combine(state(registry="NOT_FOUND"), state(), "EXIT_ZERO", 0)
        self.assertTrue(result["new_framework_installation_confirmed"])
        result = trial.combine(state(registry="NOT_FOUND"), state(), "EXIT_NONZERO", 1603)
        self.assertFalse(result["new_framework_installation_confirmed"])

    def test_disposable_prefix_required(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)
            with self.assertRaises(ValueError):
                trial.validate_prefix(path)
            (path / trial.SENTINEL).write_text("")
            (path / "drive_c").mkdir()
            (path / "system.reg").write_text("")
            trial.validate_prefix(path)

    def test_sanitized_report_copies_no_private_paths(self):
        report = trial.combine(state(), state(runtime="MONO"), "EXIT_NONZERO", 1603)
        content = json.dumps(report)
        self.assertNotIn("C:\\Users", content)
        self.assertNotIn("/Users/", content)
        self.assertNotIn("sha256", content.lower().replace("media_sha256_verified", ""))

    def test_failed_installer_process_is_classified(self):
        with mock.patch("scripts.netfx481_trial.subprocess.Popen", side_effect=OSError):
            self.assertEqual(trial.run_installer(Path("wine"), Path("prefix"),
                                                  Path("installer"), 90), ("START_FAILED", None))

    def test_clear_false_release_changes_only_disposable_wine_registry(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "drive_c").mkdir()
            (root / "system.reg").write_text("")
            (root / trial.SENTINEL).write_text("")
            operations = []
            def run(command, **kwargs):
                operations.append((command, kwargs))
                return mock.Mock(returncode=0 if command[2] == "delete" else 1)
            with mock.patch.object(trial.subprocess, "run", side_effect=run):
                result = trial.clear_false_release(Path("wine"), root, state(runtime="MONO"))
            self.assertEqual(result, "CLEARED")
            self.assertEqual(len(operations), 2)
            self.assertEqual(operations[0][0][2:], [
                "delete", trial.NETFX_FULL_KEY, "/v", "Release", "/f"
            ])
            self.assertEqual(operations[1][0][2:], [
                "query", trial.NETFX_FULL_KEY, "/v", "Release"
            ])
            for _, options in operations:
                self.assertEqual(options["env"]["WINEPREFIX"], str(root))
                self.assertNotIn("shell", options)

    def test_wow6432_release_requires_proven_mono_and_disposable_prefix(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "drive_c").mkdir()
            (root / "system.reg").write_text("")
            with mock.patch.object(trial, "reg_code") as reg:
                with self.assertRaises(ValueError):
                    trial.clear_false_wow6432_release(Path("wine"), root, state(runtime="MONO"))
                (root / trial.SENTINEL).write_text("")
                result = trial.clear_false_wow6432_release(Path("wine"), root, state())
                self.assertEqual(result["action"], "NOT_APPLICABLE")
                reg.assert_not_called()

    def test_wow6432_release_present_is_deleted_and_readback_verified(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "drive_c").mkdir()
            (root / "system.reg").write_text("")
            (root / trial.SENTINEL).write_text("")
            with mock.patch.object(trial, "reg_code", side_effect=[0, 0, 1]) as reg:
                result = trial.clear_false_wow6432_release(
                    Path("wine"), root, state(runtime="MONO"))
            self.assertEqual(result, {
                "before": "PRESENT", "action": "CLEARED", "after": "ABSENT"
            })
            self.assertEqual(reg.call_count, 3)
            self.assertEqual(reg.call_args_list[0].args[2:], (
                "query", trial.NETFX_WOW6432_FULL_KEY, "/v", "Release"
            ))
            self.assertEqual(reg.call_args_list[1].args[2:], (
                "delete", trial.NETFX_WOW6432_FULL_KEY, "/v", "Release", "/f"
            ))
            self.assertEqual(reg.call_args_list[2].args[2:], reg.call_args_list[0].args[2:])

    def test_wow6432_absent_skips_deletion(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "drive_c").mkdir()
            (root / "system.reg").write_text("")
            (root / trial.SENTINEL).write_text("")
            with mock.patch.object(trial, "reg_code", return_value=1) as reg:
                result = trial.clear_false_wow6432_release(
                    Path("wine"), root, state(runtime="MONO"))
            self.assertEqual(result["action"], "NOT_NEEDED")
            reg.assert_called_once()

    def test_wow6432_delete_failure_stops_before_real_installer(self):
        if trial.os.name == "nt":
            self.skipTest("This is an intentional real-Wine-only operation")
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            prefix = root / "prefix"
            (prefix / "drive_c").mkdir(parents=True)
            (prefix / "system.reg").write_text("")
            (prefix / trial.SENTINEL).write_text("")
            wine = root / "wine"
            wine.write_bytes(b"synthetic")
            wine.chmod(0o755)
            installer = root / "NDP481-x86-x64-AllOS-ENU.exe"
            installer.write_bytes(b"synthetic")
            manifest = root / "hash.txt"
            manifest.write_text("0" * 64)
            fixture = root / "netfx481_runtime_probe.exe"
            fixture.write_bytes(b"synthetic")
            bad = {"before": "PRESENT", "action": "DELETE_FAILED", "after": "UNVERIFIED"}
            with mock.patch.object(trial, "verify_media", return_value=True), \
                 mock.patch.object(trial, "probe", return_value=state(runtime="MONO")), \
                 mock.patch.object(trial, "clear_false_release", return_value="CLEARED"), \
                 mock.patch.object(trial, "clear_false_wow6432_release", return_value=bad), \
                 mock.patch.object(trial, "run_installer") as install:
                result = trial.trial(
                    wine, prefix, installer, manifest, fixture,
                    experiment_clear_false_release=True,
                    experiment_clear_wow6432_release=True,
                )
            self.assertEqual(result["wow6432_release"], bad)
            self.assertEqual(result["install_execution"], "SKIPPED_REGISTRY_NOT_CORRECTED")
            install.assert_not_called()

    def test_wow6432_override_requires_explicit_64bit_opt_in(self):
        if trial.os.name == "nt":
            self.skipTest("Native Windows execution intentionally rejected")
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "drive_c").mkdir()
            (root / "system.reg").write_text("")
            (root / trial.SENTINEL).write_text("")
            wine = root / "wine"
            wine.write_bytes(b"synthetic")
            wine.chmod(0o755)
            installer = root / "NDP481-x86-x64-AllOS-ENU.exe"
            installer.write_bytes(b"synthetic")
            manifest = root / "hash.txt"
            manifest.write_text("0" * 64)
            fixture = root / "netfx481_runtime_probe.exe"
            fixture.write_bytes(b"synthetic")
            with mock.patch.object(trial, "verify_media", return_value=True), \
                 mock.patch.object(trial, "probe") as managed:
                with self.assertRaisesRegex(ValueError, "requires 64-bit"):
                    trial.trial(wine, root, installer, manifest, fixture,
                                experiment_clear_wow6432_release=True)
                managed.assert_not_called()

    def test_no_registry_deletion_without_mono_false_release_or_marker(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "drive_c").mkdir()
            (root / "system.reg").write_text("")
            with mock.patch.object(trial.subprocess, "run") as proc:
                with self.assertRaises(ValueError):
                    trial.clear_false_release(Path("wine"), root, state(runtime="MONO"))
                (root / trial.SENTINEL).write_text("")
                self.assertEqual(
                    trial.clear_false_release(Path("wine"), root, state()), "NOT_APPLICABLE"
                )
                proc.assert_not_called()

    def test_false_release_cannot_lead_to_official_setup_if_not_cleared(self):
        if trial.os.name == "nt":
            self.skipTest("Real Wine trial intentionally refuses native Windows; Linux/macOS test covers this gate")
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            prefix = root / "prefix"
            (prefix / "drive_c").mkdir(parents=True)
            (prefix / "system.reg").write_text("")
            (prefix / trial.SENTINEL).write_text("")
            wine = root / "wine"
            wine.write_bytes(b"synthetic")
            wine.chmod(0o755)
            installer = root / "NDP481-x86-x64-AllOS-ENU.exe"
            installer.write_bytes(b"synthetic")
            manifest = root / "hash.txt"
            manifest.write_text("0" * 64)
            fixture = root / "netfx481_runtime_probe.exe"
            fixture.write_bytes(b"synthetic")
            with mock.patch.object(trial, "verify_media", return_value=True), \
                 mock.patch.object(trial, "probe", return_value=state(runtime="MONO")), \
                 mock.patch.object(trial, "clear_false_release", return_value="STILL_PRESENT_OR_UNVERIFIED"), \
                 mock.patch.object(trial, "run_installer") as installer_runner:
                result = trial.trial(wine, prefix, installer, manifest, fixture,
                                     experiment_clear_false_release=True)
            self.assertEqual(result["registry_adjustment"], "STILL_PRESENT_OR_UNVERIFIED")
            self.assertEqual(result["install_execution"], "SKIPPED_REGISTRY_NOT_CORRECTED")
            installer_runner.assert_not_called()

    def test_mono_removal_is_required_before_native_framework_setup(self):
        if trial.os.name == "nt":
            self.skipTest("Native Windows cannot run the isolated Wine installer")
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            prefix = root / "prefix"
            (prefix / "drive_c").mkdir(parents=True)
            (prefix / "system.reg").write_text("")
            (prefix / trial.SENTINEL).write_text("")
            wine = root / "wine"
            wine.write_bytes(b"synthetic")
            wine.chmod(0o755)
            installer = root / "NDP481-x86-x64-AllOS-ENU.exe"
            installer.write_bytes(b"synthetic")
            manifest = root / "sha.txt"
            manifest.write_text("0" * 64)
            fixture = root / "netfx481_runtime_probe.exe"
            fixture.write_bytes(b"synthetic")
            wow = {"before": "ABSENT", "action": "NOT_NEEDED", "after": "ABSENT"}
            mono = {"before": 1, "after": None, "action": "REMOVE_FAILED"}
            with mock.patch.object(trial, "verify_media", return_value=True), \
                 mock.patch.object(trial, "probe", return_value=state(runtime="MONO")), \
                 mock.patch.object(trial, "clear_false_release", return_value="CLEARED"), \
                 mock.patch.object(trial, "clear_false_wow6432_release", return_value=wow), \
                 mock.patch("scripts.wine_mono_removal.remove_mono", return_value=mono), \
                 mock.patch.object(trial, "run_installer") as installer_runner:
                result = trial.trial(
                    wine, prefix, installer, manifest, fixture,
                    experiment_clear_false_release=True,
                    experiment_clear_wow6432_release=True,
                    experiment_remove_wine_mono=True,
                )
            self.assertEqual(result["wine_mono_removal"]["action"], "REMOVE_FAILED")
            self.assertEqual(result["install_execution"], "SKIPPED_MONO_NOT_REMOVED")
            installer_runner.assert_not_called()

    def test_possible_windows_3010_needs_completed_wine_reboot_and_real_clr(self):
        self.assertEqual(3010 % 256, trial.POSSIBLE_3010_UNIX_CODE)
        prior = state(runtime="MONO")
        unknown = trial.combine(prior, prior, "EXIT_NONZERO", 194,
                                wine_restart={"reason": "UNIX_194_POSSIBLE_3010",
                                              "action": "COMPLETED"})
        self.assertFalse(unknown["new_framework_installation_confirmed"])
        good = trial.combine(prior, state(), "EXIT_NONZERO", 194,
                             wine_restart={"reason": "UNIX_194_POSSIBLE_3010",
                                           "action": "COMPLETED"})
        self.assertTrue(good["new_framework_installation_confirmed"])
        failed = trial.combine(prior, state(), "EXIT_NONZERO", 194,
                               wine_restart={"reason": "UNIX_194_POSSIBLE_3010",
                                             "action": "TIMED_OUT"})
        self.assertFalse(failed["new_framework_installation_confirmed"])
        other = trial.combine(prior, state(), "EXIT_NONZERO", 67)
        self.assertFalse(other["new_framework_installation_confirmed"])

    def test_wineboot_restart_requires_disposable_prefix_and_sibling_binary(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            prefix = root / "prefix"
            (prefix / "drive_c").mkdir(parents=True)
            (prefix / "system.reg").write_text("")
            boot = root / "wineboot"
            boot.write_text("synthetic boot")
            boot.chmod(0o755)
            wine = root / "wine"
            wine.write_text("synthetic Wine")
            wine.chmod(0o755)
            with mock.patch.object(trial.subprocess, "run") as invoked:
                with self.assertRaises(ValueError):
                    trial.wineboot_restart(wine, prefix)
                invoked.assert_not_called()
            (prefix / trial.SENTINEL).write_text("")
            with mock.patch.object(trial.subprocess, "run", return_value=mock.Mock(returncode=0)) as invoked:
                self.assertEqual(trial.wineboot_restart(wine, prefix), "COMPLETED")
                self.assertEqual(invoked.call_args.args[0], [str(boot), "--restart"])
                self.assertEqual(invoked.call_args.kwargs["env"]["WINEPREFIX"], str(prefix))
                self.assertEqual(invoked.call_args.kwargs["timeout"], 100)

    def test_wineboot_uses_builtin_windows_program_if_macos_bundle_has_no_wrapper(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            prefix = root / "prefix"
            (prefix / "drive_c").mkdir(parents=True)
            (prefix / "system.reg").write_text("")
            (prefix / trial.SENTINEL).write_text("")
            wine = root / "wine"
            wine.write_text("synthetic")
            wine.chmod(0o755)
            with mock.patch.object(trial.subprocess, "run", return_value=mock.Mock(returncode=0)) as runner:
                self.assertEqual(trial.wineboot_restart(wine, prefix), "COMPLETED")
                self.assertEqual(runner.call_args.args[0],
                                 [str(wine), "wineboot.exe", "--restart"])
                self.assertEqual(runner.call_args.kwargs["env"]["WINEPREFIX"], str(prefix))
                self.assertNotIn("shell", runner.call_args.kwargs)

    def test_wineboot_symlink_uses_builtin_program_instead_of_failing(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            prefix = root / "prefix"
            (prefix / "drive_c").mkdir(parents=True)
            (prefix / "system.reg").write_text("")
            (prefix / trial.SENTINEL).write_text("")
            wine = root / "wine"
            wine.write_text("synthetic")
            wine.chmod(0o755)
            boot = root / "wineboot"
            try:
                boot.symlink_to(wine)
            except (OSError, NotImplementedError):
                self.skipTest("symlinks unavailable")
            with mock.patch.object(trial.subprocess, "run", return_value=mock.Mock(returncode=0)) as run:
                self.assertEqual(trial.wineboot_restart(wine, prefix), "COMPLETED")
                self.assertEqual(run.call_args.args[0],
                                 [str(wine), "wineboot.exe", "--restart"])

    def test_wineboot_exit_failure_not_treated_as_reboot(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            prefix = root / "prefix"
            (prefix / "drive_c").mkdir(parents=True)
            (prefix / "system.reg").write_text("")
            (prefix / trial.SENTINEL).write_text("")
            boot = root / "wineboot"
            boot.write_text("synthetic")
            boot.chmod(0o755)
            wine = root / "wine"
            wine.write_text("synthetic")
            wine.chmod(0o755)
            with mock.patch.object(trial.subprocess, "run", return_value=mock.Mock(returncode=1)):
                self.assertEqual(trial.wineboot_restart(wine, prefix), "EXIT_NONZERO")
            with mock.patch.object(trial.subprocess, "run", side_effect=trial.subprocess.TimeoutExpired(["wineboot"], 1)):
                self.assertEqual(trial.wineboot_restart(wine, prefix), "TIMED_OUT")

    def test_real_run_requires_manifest_digest(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            file = root / "NDP481-x86-x64-AllOS-ENU.exe"
            manifest = root / "file.sha256"
            file.write_bytes(b"not genuine")
            manifest.write_text("0" * 64)
            with self.assertRaises(ValueError):
                trial.verify_media(file, manifest)

if __name__ == "__main__":
    unittest.main()
