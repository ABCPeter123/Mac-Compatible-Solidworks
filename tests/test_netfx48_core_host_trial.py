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
            def check_host(wine, prefix, fixture, managed, mode):
                self.assertTrue(wine.is_absolute())
                self.assertTrue(prefix.is_absolute())
                self.assertTrue(fixture.is_absolute())
                self.assertTrue(managed.is_absolute())
                self.assertTrue(fixture.is_file())
                return "MANAGED_ORIGINAL_PASS"
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
                self.assertEqual(sevenzip, reader)
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
            self.assertEqual(seen, [reader])
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

            def execute(wine, prefix, fixture, managed, mode):
                self.assertEqual(mode, "n")
                clr = (root / "clr.dll").read_bytes()
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
                 mock.patch.object(t, "valid_stage", return_value=True):
                report = t.trial(**args)
            self.assertTrue(t.valid(report))
            self.assertEqual(report["status"], "MEASURED")
            self.assertEqual(report["clr_only"], "HOST_START_FAILED")
            self.assertEqual(report["clr_and_mscorlib"], "MANAGED_EXECUTION_FAILED")
            self.assertEqual(report["additional_core"], "MANAGED_ORIGINAL_PASS")
            self.assertEqual(report["native40_after"], "MANAGED_ORIGINAL_PASS")
            self.assertEqual(len(calls), 5)
            self.assertEqual((root / "clr.dll").read_bytes(), original)
            self.assertEqual((root / "mscorlib.dll").read_bytes(), original_lib)
            self.assertFalse((root / "mscoreei.dll").exists())
            self.assertFalse((root / "clrjit.dll").exists())

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
