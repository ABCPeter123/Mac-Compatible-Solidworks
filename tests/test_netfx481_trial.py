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
