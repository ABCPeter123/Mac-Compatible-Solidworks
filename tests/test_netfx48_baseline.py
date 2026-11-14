"""Synthetic, zero-vendor-binary tests for the .NET 4.8 control experiment."""
import hashlib
import json
from pathlib import Path
import tempfile
from unittest import TestCase, mock
from scripts import netfx48_baseline as baseline


class NetFx48BaselineTests(TestCase):
    def test_native_candidate_requires_all_independent_signals(self):
        before = {"CLR64": "ABSENT"}
        after = {"registry": "BELOW_481",
                 "clr_family": "MICROSOFT_CLR_CANDIDATE", "managed": "PASS"}
        args = (before, after, "CREATED", "PE_AMD64", "LOADED", "ZERO", "NOT_NEEDED")
        self.assertTrue(baseline.native_48_candidate(*args))
        for i, replacement in [
            (0, {"CLR64": "PE_AMD64"}), (1, {**after, "managed": "FAIL"}),
            (1, {**after, "clr_family": "MONO"}),
            (1, {**after, "registry": "AT_LEAST_481"}),
            (2, "UNCHANGED"), (3, "PE_I386"), (4, "NOT_FOUND"),
            (5, "OTHER"),
        ]:
            changed = list(args)
            changed[i] = replacement
            with self.subTest(index=i, replacement=replacement):
                self.assertFalse(baseline.native_48_candidate(*changed))
        self.assertFalse(baseline.native_48_candidate(
            before, after, "CREATED", "PE_AMD64", "LOADED",
            "POSSIBLE_3010_UNIX_194", "NOT_NEEDED"))
        self.assertTrue(baseline.native_48_candidate(
            before, after, "CREATED", "PE_AMD64", "LOADED",
            "POSSIBLE_3010_UNIX_194", "COMPLETED"))

    def test_signed_media_name_and_sha256_required(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            installer = root / "NDP48-x86-x64-AllOS-ENU.exe"
            installer.write_bytes(b"synthetic" * (2 * 1024 * 1024))
            digest = hashlib.sha256(installer.read_bytes()).hexdigest()
            manifest = root / "netfx48.sha256"
            manifest.write_text(digest, encoding="ascii")
            baseline.verify_official_media(installer, manifest)
            manifest.write_text("0" * 64, encoding="ascii")
            with self.assertRaisesRegex(ValueError, "digest mismatch"):
                baseline.verify_official_media(installer, manifest)
            manifest.write_text(digest, encoding="ascii")
            renamed = root / "NOT_MICROSOFT.exe"
            renamed.write_bytes(installer.read_bytes())
            with self.assertRaisesRegex(ValueError, "Expected original"):
                baseline.verify_official_media(renamed, manifest)

    def test_report_rejects_arbitrary_private_fields_and_false_481(self):
        report = {
            "schema": 1, "scope": "ORIGINAL_NETFX48_DISPOSABLE_WINE_BASELINE",
            "status": "MEASURED", "before_family": "MONO",
            "registry64_adjustment": "CLEARED",
            "registry32_adjustment": "NOT_NEEDED", "mono_removal": "REMOVED",
            "installer_execution": "EXIT_NONZERO",
            "unix_exit_category": "POSSIBLE_3010_UNIX_194",
            "wine_restart": "COMPLETED",
            "clr64_before": "ABSENT", "clr64_after": "ABSENT",
            "clr64_change": "UNCHANGED", "clr_loader": "NOT_FOUND",
            "managed_identity": "UNKNOWN", "managed_functionality": "FAIL",
            "registry_indicator": "NOT_FOUND",
            "native_48_candidate": False, "netfx481_ready": False,
            "solidworks_compatibility": "NOT_DEMONSTRATED",
        }
        self.assertTrue(baseline.validate(report))
        self.assertNotIn("NDP48", json.dumps(report))
        for key, value in [
            ("netfx481_ready", True), ("before_family", "PRIVATE_USERNAME"),
            ("scope", "SOME_OTHER_PREFIX"), ("native_48_candidate", 1),
            ("clr64_after", "/Users/private/clr.dll"),
        ]:
            invalid = dict(report)
            invalid[key] = value
            with self.subTest(key=key):
                self.assertFalse(baseline.validate(invalid))
        invalid = {**report, "raw_installer_log": "private"}
        self.assertFalse(baseline.validate(invalid))


    def test_clear_unbacked_release_uses_only_approved_key_and_verified_query(self):
        with mock.patch.object(baseline, "validate_prefix"), mock.patch.object(
            baseline, "reg_code", side_effect=[0, 0, 1]
        ) as reg:
            result = baseline.clear_unbacked_release(
                Path("/fake/wine"), Path("/fake/disposable"), baseline.NETFX_FULL_KEY)
            self.assertEqual(result, "CLEARED")
            self.assertEqual(reg.call_count, 3)
        with mock.patch.object(baseline, "validate_prefix"), mock.patch.object(
            baseline, "reg_code", return_value=1
        ) as reg:
            self.assertEqual(baseline.clear_unbacked_release(
                Path("/fake/wine"), Path("/fake/disposable"),
                baseline.NETFX_WOW6432_FULL_KEY), "NOT_NEEDED")
            self.assertEqual(reg.call_count, 1)
        with mock.patch.object(baseline, "validate_prefix"):
            with self.assertRaisesRegex(ValueError, "Unexpected registry key"):
                baseline.clear_unbacked_release(
                    Path("/fake/wine"), Path("/fake/disposable"), "HKLM\\Unrelated")

    def test_unverified_preflight_still_executes_original_installer(self):
        # An absent managed runtime is exactly why the official setup is needed.
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            wine = root / "wine"
            wine.write_bytes(b"mock executable")
            wine.chmod(0o700)
            fixture = root / baseline.PROBE_NAME
            loader = root / baseline.LOADER_NAME
            installer = root / baseline.INSTALLER_NAME
            manifest = root / "netfx48.sha256"
            for path in (fixture, loader, installer, manifest):
                path.write_bytes(b"synthetic")
            prefix = root / "prefix"
            prefix.mkdir()
            before = {"clr_family": "NOT_VERIFIED", "registry": "NOT_VERIFIED",
                      "managed": "NOT_VERIFIED"}
            after = {"clr_family": "UNKNOWN", "registry": "NOT_FOUND",
                     "managed": "FAIL"}
            from scripts.netfx481_payload_audit import ITEMS
            absent = {key: ("ABSENT", None) for key in ITEMS}
            with (
                mock.patch.object(baseline, "validate_prefix"),
                mock.patch.object(baseline, "verify_official_media"),
                mock.patch.object(baseline, "probe", side_effect=[before, after]),
                mock.patch.object(baseline, "snapshot", return_value=absent),
                mock.patch.object(baseline, "clear_unbacked_release", return_value="NOT_NEEDED"),
                mock.patch.object(baseline, "inventory", return_value=()),
                mock.patch.object(baseline, "run_installer", return_value=("EXIT_ZERO", 0)) as setup,
                mock.patch.object(baseline, "load_clr", return_value="NOT_FOUND"),
            ):
                report = baseline.inspect(
                    wine, prefix, installer, manifest, fixture, loader)
            setup.assert_called_once()
            self.assertEqual(report["status"], "MEASURED")
            self.assertEqual(report["mono_removal"], "MONO_NOT_REGISTERED")
            self.assertEqual(report["installer_execution"], "EXIT_ZERO")
            self.assertFalse(report["native_48_candidate"])
            self.assertTrue(baseline.validate(report))
