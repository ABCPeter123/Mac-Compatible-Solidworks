"""Vendor-free tests for reversible authentic .NET 4.8 CLR hosting experiments."""
from __future__ import annotations

import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest import mock

from scripts import netfx48_core_host_trial as t


def pe(seed: int = 0) -> bytes:
    data = bytearray([seed % 256] * 8192)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3c, 0x80)
    data[0x80:0x84] = b"PE\x00\x00"
    struct.pack_into("<H", data, 0x84, 0x8664)
    struct.pack_into("<H", data, 0x94, 240)
    struct.pack_into("<H", data, 0x98, 0x20b)
    return bytes(data)


def native_prefix(base: Path) -> tuple[Path, Path]:
    prefix = base / "wineprefix"
    root = prefix / t.FRAMEWORK
    root.mkdir(parents=True)
    (prefix / ".swcompat-netfx481-disposable").write_text("")
    (prefix / "system.reg").write_text("")
    (root / "clr.dll").write_bytes(pe(1))
    (root / "mscorlib.dll").write_bytes(pe(2))
    return prefix, root


class CoreHostTrialTests(unittest.TestCase):
    def test_bounded_fixed_schema_cannot_claim_installed_48_or_solidworks(self):
        self.assertTrue(t.valid(t.blank()))
        self.assertFalse(t.valid(dict(t.blank(), framework48_installed=True)))
        self.assertTrue(t.valid(dict(t.blank(), status="INTERNAL_ERROR", error_phase="ELIGIBILITY")))
        self.assertFalse(t.valid(dict(t.blank(), status="INTERNAL_ERROR", error_phase="Z:\\private")))
        self.assertFalse(t.valid(dict(t.blank(), status="MEASURED", error_phase="EXTRACTION")))
        self.assertFalse(t.valid(dict(t.blank(), framework481_installed=True)))
        self.assertFalse(t.valid(dict(t.blank(), path="C:\\private")))
        self.assertFalse(t.valid(dict(t.blank(), original48_core_staged=99)))
        report = dict(t.blank(), status="MEASURED",
                      native40_before="MANAGED_ORIGINAL_PASS",
                      native40_after="MANAGED_ORIGINAL_PASS",
                      original48_sha256_verified=True,
                      original48_clr="PE_AMD64",
                      original48_mscorlib_staged=True,
                      original40_restored=True,
                      clr_only="HOST_START_FAILED",
                      clr_and_mscorlib="MANAGED_ORIGINAL_PASS")
        self.assertTrue(t.valid(report))
        self.assertFalse(t.valid(dict(report, original40_restored=False)))
        self.assertFalse(t.valid(dict(report, original48_mscorlib_staged=False)))
        self.assertNotIn("C:\\", json.dumps(report))
        self.assertNotIn(".exe", json.dumps(report))
        self.assertNotIn("sha256", json.dumps(report).replace(
            "original48_sha256_verified", ""))

    def test_restores_existing_and_removes_new_payloads(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            _, root = native_prefix(base)
            private = base / "private"
            private.mkdir()
            source = private / "clr.dll"
            source.write_bytes(pe(3))
            extra = private / "clrjit.dll"
            extra.write_bytes(pe(4))
            original = (root / "clr.dll").read_bytes()
            switch = t.ReversibleFramework(root, private)
            switch.replace(source, "clr.dll")
            switch.replace(extra, "clrjit.dll")
            self.assertEqual((root / "clr.dll").read_bytes(), pe(3))
            self.assertEqual((root / "clrjit.dll").read_bytes(), pe(4))
            switch.restore()
            self.assertEqual((root / "clr.dll").read_bytes(), original)
            self.assertFalse((root / "clrjit.dll").exists())

    def test_mixed_case_original_framework_does_not_create_duplicate_backup(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            _, root = native_prefix(base)
            original = root / "System.Core.dll"
            original.write_bytes(pe(9))
            private = base / "private"
            private.mkdir()
            payload = private / "system.core.dll"
            payload.write_bytes(pe(10))
            switch = t.ReversibleFramework(root, private)
            # Earlier optional "extra native" arm uses lowercase.
            switch.replace(payload, "system.core.dll")
            self.assertEqual(original.read_bytes(), pe(10))
            self.assertEqual(set(switch.saved), {"System.Core.dll"})
            self.assertFalse((root / "system.core.dll").exists()
                             and (root / "system.core.dll") != original
                             and len([p for p in root.iterdir()
                                      if p.name.casefold() == "system.core.dll"]) > 1)
            # Coherent x64 Framework64 arm reuses original Microsoft casing.
            switch.replace(payload, "System.Core.dll")
            self.assertEqual(set(switch.saved), {"System.Core.dll"})
            self.assertEqual(len(list(private.glob("saved-*"))), 1)
            self.assertEqual(original.read_bytes(), pe(10))
            switch.restore()
            self.assertEqual(original.read_bytes(), pe(9))
            self.assertEqual(len([p for p in root.iterdir()
                                  if p.name.casefold() == "system.core.dll"]), 1)

    def test_refuse_ambiguous_case_variants_on_case_sensitive_filesystems(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            _, root = native_prefix(base)
            (root / "System.Core.dll").write_bytes(pe(9))
            (root / "system.core.dll").write_bytes(pe(8))
            if len([p for p in root.iterdir()
                    if p.name.casefold() == "system.core.dll"]) < 2:
                self.skipTest("The host filesystem is case-insensitive")
            private = base / "private"
            private.mkdir()
            payload = private / "system.core.dll"
            payload.write_bytes(pe(10))
            switch = t.ReversibleFramework(root, private)
            with self.assertRaisesRegex(ValueError, "Ambiguous"):
                switch.replace(payload, "system.core.dll")
            self.assertFalse(switch.saved)
            self.assertEqual((root / "System.Core.dll").read_bytes(), pe(9))
            self.assertEqual((root / "system.core.dll").read_bytes(), pe(8))

    def test_rejects_traversal_links_and_wrong_architecture(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            _, root = native_prefix(base)
            private = base / "private"
            private.mkdir()
            source = private / "clr.dll"
            source.write_bytes(pe(3))
            switch = t.ReversibleFramework(root, private)
            with self.assertRaises(ValueError):
                switch.replace(source, "../clr.dll")
            with self.assertRaises(ValueError):
                switch.replace(source, "mscorlib.dll")
            source.write_bytes(b"bad" * 300)
            with self.assertRaises(ValueError):
                switch.replace(source, "clr.dll")
            source.unlink()
            source.symlink_to(root / "clr.dll")
            with self.assertRaises(ValueError):
                switch.replace(source, "clr.dll")
            switch.restore()

    def test_no_original48_payload_does_not_touch_native40(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            prefix, root = native_prefix(base)
            args = self._args(base, prefix)
            original = (root / "clr.dll").read_bytes()
            with mock.patch.object(t, "validate_prefix"), \
                 mock.patch.object(t, "valid_restart", return_value=True), \
                 mock.patch.object(t, "valid_host", return_value=True), \
                 mock.patch.object(t, "verify_original"), \
                 mock.patch.object(t, "host_execute", return_value="MANAGED_ORIGINAL_PASS"), \
                 mock.patch.object(t, "extract_clr", return_value=("NO_MZZ", None)):
                report = t.trial(**args)
            self.assertTrue(t.valid(report))
            self.assertEqual(report["status"], "EXTRACTION_FAILED")
            self.assertEqual(report["original48_clr"], "NO_MZZ")
            self.assertEqual((root / "clr.dll").read_bytes(), original)

    def test_relative_media_and_fixtures_resolve_before_child_working_directory(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            prefix, root = native_prefix(base)
            args = self._args(base, prefix)
            for key in ("installer", "fixture", "managed"):
                args[key] = Path(__import__("os").path.relpath(args[key], Path.cwd()))
            def check_original(installer, digest):
                self.assertTrue(installer.is_absolute())
                self.assertTrue(installer.is_file())
            def check_extract(installer, sevenzip, private):
                self.assertTrue(installer.is_absolute())
                self.assertTrue(sevenzip.is_absolute())
                return "NO_MZZ", None
            def check_host(wine, prefix, fixture, managed, mode, *,
                           precheck=False, disable_native_images=False):
                self.assertTrue(wine.is_absolute())
                self.assertTrue(prefix.is_absolute())
                self.assertTrue(fixture.is_absolute())
                self.assertTrue(managed.is_absolute())
                self.assertTrue(fixture.is_file())
                return ("PRECHECK_LOADABLE_NOT_STARTED" if precheck
                        else "MANAGED_ORIGINAL_PASS")
            with mock.patch.object(t, "validate_prefix"), \
                 mock.patch.object(t, "valid_restart", return_value=True), \
                 mock.patch.object(t, "valid_host", return_value=True), \
                 mock.patch.object(t, "verify_original", side_effect=check_original), \
                 mock.patch.object(t, "host_execute", side_effect=check_host), \
                 mock.patch.object(t, "extract_clr", side_effect=check_extract):
                report = t.trial(**args)
            self.assertEqual(report["status"], "EXTRACTION_FAILED")
            self.assertTrue(t.valid(report))

    def test_homebrew_symlinked_archive_reader_is_allowed_after_resolution(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            prefix, root = native_prefix(base)
            args = self._args(base, prefix)
            reader = args["sevenzip"]
            link = base / "homebrew-7zz"
            link.symlink_to(reader)
            args["sevenzip"] = link
            seen = []
            def check_extract(installer, sevenzip, private):
                seen.append(sevenzip)
                self.assertTrue(sevenzip.is_absolute())
                self.assertFalse(sevenzip.is_symlink())
                self.assertEqual(sevenzip, reader.resolve())
                return "NO_MZZ", None
            progress = ["INPUT"]
            with mock.patch.object(t, "validate_prefix"), \
                 mock.patch.object(t, "valid_restart", return_value=True), \
                 mock.patch.object(t, "valid_host", return_value=True), \
                 mock.patch.object(t, "verify_original"), \
                 mock.patch.object(t, "host_execute", return_value="MANAGED_ORIGINAL_PASS"), \
                 mock.patch.object(t, "extract_clr", side_effect=check_extract):
                report = t.trial(**args, progress=progress)
            self.assertEqual(report["status"], "EXTRACTION_FAILED")
            self.assertEqual(progress, ["EXTRACTION"])
            self.assertEqual(seen, [reader.resolve()])
            self.assertTrue(t.valid(report))

    def test_three_staged_variants_and_restored_native40(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            prefix, root = native_prefix(base)
            args = self._args(base, prefix)
            original = (root / "clr.dll").read_bytes()
            original_lib = (root / "mscorlib.dll").read_bytes()
            calls = []

            def extract(installer, sevenzip, private):
                (private / "archives").mkdir()
                (private / "clr.dll").write_bytes(pe(3))
                return "PE_AMD64", private / "clr.dll"

            def stage(private, sevenzip, names):
                for name in names:
                    (private / name).write_bytes(pe(4))
                return {"staged": len(names)}

            def execute(wine, prefix, fixture, managed, mode, *,
                        precheck=False, disable_native_images=False):
                self.assertEqual(mode, "n")
                if precheck:
                    return "PRECHECK_LOADABLE_NOT_STARTED"
                clr = (root / "clr.dll").read_bytes()
                if disable_native_images:
                    return ("MANAGED_ORIGINAL_PASS" if clr == original
                            else "HOST_START_E_FAIL")
                calls.append(clr)
                if clr == original:
                    return "MANAGED_ORIGINAL_PASS"
                if (root / "mscorlib.dll").read_bytes() == original_lib:
                    return "HOST_START_FAILED"
                if not (root / "mscoreei.dll").exists():
                    return "MANAGED_EXECUTION_FAILED"
                return "MANAGED_ORIGINAL_PASS"

            with mock.patch.object(t, "validate_prefix"), \
                 mock.patch.object(t, "valid_restart", return_value=True), \
                 mock.patch.object(t, "valid_host", return_value=True), \
                 mock.patch.object(t, "verify_original"), \
                 mock.patch.object(t, "host_execute", side_effect=execute), \
                 mock.patch.object(t, "extract_clr", side_effect=extract), \
                 mock.patch.object(t, "parse_pe", return_value={
                     "pe": "PE_AMD64", "import_table": "READABLE"}), \
                 mock.patch.object(t, "stage", side_effect=stage), \
                 mock.patch.object(t, "valid_stage", return_value=True), \
                 mock.patch.object(t, "trace_probe", return_value=t.trace_blank()):
                report = t.trial(**args)
            self.assertTrue(t.valid(report))
            self.assertEqual(report["status"], "MEASURED")
            self.assertEqual(report["clr_only"], "HOST_START_FAILED")
            self.assertEqual(report["clr_and_mscorlib"], "MANAGED_EXECUTION_FAILED")
            self.assertEqual(report["additional_core"], "MANAGED_ORIGINAL_PASS")
            self.assertEqual(report["extra_native"], "MANAGED_ORIGINAL_PASS")
            self.assertEqual(report["original48_extra_staged"], len(t.EXTRA_NATIVE))
            self.assertEqual(report["native40_after"], "MANAGED_ORIGINAL_PASS")
            self.assertEqual(report["native40_zap_disabled_before"],
                             "MANAGED_ORIGINAL_PASS")
            self.assertEqual(report["original48_zap_disabled"],
                             "HOST_START_E_FAIL")
            self.assertEqual(report["native40_zap_disabled_after"],
                             "MANAGED_ORIGINAL_PASS")
            self.assertEqual(report["native40_precheck_before"],
                             "PRECHECK_LOADABLE_NOT_STARTED")
            self.assertEqual(report["original48_precheck"],
                             "PRECHECK_LOADABLE_NOT_STARTED")
            self.assertEqual(report["native40_precheck_after"],
                             "PRECHECK_LOADABLE_NOT_STARTED")
            self.assertEqual(len(calls), 6)
            self.assertEqual((root / "clr.dll").read_bytes(), original)
            self.assertEqual((root / "mscorlib.dll").read_bytes(), original_lib)
            self.assertFalse((root / "mscoreei.dll").exists())
            self.assertFalse((root / "clrjit.dll").exists())

    def test_coherence_failures_are_private_and_preserve_original_files(self):
        for message, expected in (
            ("Backup collision", "COHERENCE_BACKUP_COLLISION"),
            ("Original signed payload is not x64-compatible",
             "COHERENCE_INVALID_PE"),
            ("Ambiguous original runtime target casing",
             "COHERENCE_CASE_AMBIGUITY"),
        ):
            with self.subTest(expected=expected), tempfile.TemporaryDirectory() as td:
                base = Path(td)
                prefix, root = native_prefix(base)
                args = self._args(base, prefix)
                original = (root / "clr.dll").read_bytes()
                original_lib = (root / "mscorlib.dll").read_bytes()
                progress = ["INPUT"]

                def extract(installer, sevenzip, private):
                    (private / "archives").mkdir()
                    (private / "clr.dll").write_bytes(pe(3))
                    return "PE_AMD64", private / "clr.dll"

                def stage(private, sevenzip, names, **kwargs):
                    for name in names:
                        (private / name).write_bytes(pe(4))
                    return {"staged": len(names)}

                def matching(root, private, sevenzip):
                    (private / "system.core.dll").write_bytes(pe(5))
                    return (
                        dict(t.coherent_blank(), status="STAGED", candidates=1,
                             additional=0, staged=0),
                        {"system.core.dll": "System.Core.dll"},
                    )

                original_replace = t.ReversibleFramework.replace

                def replaced(self, source, name, *, allow_managed_anycpu=False):
                    if allow_managed_anycpu:
                        raise ValueError(message)
                    return original_replace(self, source, name,
                                            allow_managed_anycpu=False)

                with mock.patch.object(t, "validate_prefix"), \
                     mock.patch.object(t, "valid_restart", return_value=True), \
                     mock.patch.object(t, "valid_host", return_value=True), \
                     mock.patch.object(t, "verify_original"), \
                     mock.patch.object(t, "host_execute",
                                       return_value="MANAGED_ORIGINAL_PASS"), \
                     mock.patch.object(t, "extract_clr", side_effect=extract), \
                     mock.patch.object(t, "parse_pe", return_value={
                         "pe": "PE_AMD64", "import_table": "READABLE"}), \
                     mock.patch.object(t, "stage", side_effect=stage), \
                     mock.patch.object(t, "stage_matching", side_effect=matching), \
                     mock.patch.object(t, "valid_stage", return_value=True), \
                     mock.patch.object(t, "trace_probe",
                                       return_value=t.trace_blank()), \
                     mock.patch.object(t, "activation_probe",
                                       return_value=t.activation_blank()), \
                     mock.patch.object(t.ReversibleFramework, "replace",
                                       new=replaced):
                    with self.assertRaises(ValueError):
                        t.trial(**args, progress=progress)
                self.assertEqual(progress, [expected])
                self.assertEqual((root / "clr.dll").read_bytes(), original)
                self.assertEqual((root / "mscorlib.dll").read_bytes(),
                                 original_lib)
                self.assertFalse((root / "clrjit.dll").exists())
                self.assertNotIn(message, expected)

    @staticmethod
    def _args(base: Path, prefix: Path) -> dict:
        def f(name):
            p = base / name
            p.write_bytes(b"fixture")
            return p
        wine = f("wine")
        wine.chmod(0o755)
        sevenzip = f("7zz")
        sevenzip.chmod(0o755)
        return dict(
            installer=f("NDP48-x86-x64-AllOS-ENU.exe"),
            signed_sha="a" * 64, wine=wine, prefix=prefix,
            sevenzip=sevenzip, fixture=f("netfx48_host_activation.exe"),
            managed=f("netfx48_managed_host_check.dll"),
            restart={"persistent_native_managed": True,
                     "native_only_managed": "PASS"},
            host={"status": "MEASURED", "native_managed_pass": True},
        )


if __name__ == "__main__":
    unittest.main()
