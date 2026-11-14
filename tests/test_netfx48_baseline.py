"""Synthetic, zero-vendor-binary tests for the .NET 4.8 control experiment."""
import hashlib
import json
from pathlib import Path
import tempfile
from unittest import TestCase
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
