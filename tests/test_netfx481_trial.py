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
