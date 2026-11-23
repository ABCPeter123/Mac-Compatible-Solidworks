"""Fail-closed tests for original Microsoft .NET4 Core x64 MSI after setup 1603."""
from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from scripts import netfx40_original_core_msi_recovery as core


def _synthetic_fixture(root: Path):
    wine = root / "wine"
    wine.write_bytes(b"self authored wine test stub")
    wine.chmod(0o755)
    prefix = root / "netfx40-msxml3-prefix"
    (prefix / "drive_c").mkdir(parents=True)
    (prefix / "system.reg").write_text("synthetic Wine registry")
    (prefix / ".swcompat-netfx481-disposable").touch()
    archive = root / "dotnetfx40_full_x86_x64.exe"
    archive.write_bytes(b"synthetic original media placeholder")
    managed = root / "netfx481_runtime_probe.exe"
    managed.write_bytes(b"self-authored probe")
    loader = root / "netfx481_clr_load.exe"
    loader.write_bytes(b"self-authored loader")
    extract = {"process": "ZERO", "status": "PARTIAL_SCAN",
               "core_x64_ole_candidate": True}
    setup = {"installer_status": "EXIT_CAPTURED",
             "installer_exit": "MSI_FATAL_ERROR",
             "installer_exit_hex": "00000643", "clr64_after": "ABSENT"}
    restart = {"status": "NOT_ELIGIBLE",
               "persistent_native_managed": False}
    return (wine, prefix, archive, extract, setup, restart, managed, loader)


def _core_media(prefix: Path):
    directory = prefix / "drive_c" / core.EXTRACT_FOLDER
    directory.mkdir(parents=True)
    msi = directory / "netfx_Core_x64.msi"
    msi.write_bytes(core.OLE_SIGNATURE + bytes(4096))
    mzz = directory / "netfx_Core.mzz"
    mzz.write_bytes(bytes(128 * 1024))
    return msi


class OriginalCoreMSITests(unittest.TestCase):
    def setup_patches(self):
        return [
            mock.patch.object(core, "valid_legacy", return_value=True),
            mock.patch.object(core, "valid_extract", return_value=True),
            mock.patch.object(core, "valid_restart", return_value=True),
            mock.patch.object(core, "verify_media"),
        ]

    def inspect(self, args, td, *, more=()):
        patches = self.setup_patches() + list(more)
        with mock.patch.dict(os.environ, {"RUNNER_TEMP": td}), (
            __import__("contextlib").ExitStack()
        ) as stack:
            for patch in patches:
                stack.enter_context(patch)
            return core.inspect(*args)

    def test_strict_schema_no_framework_success_from_core_msi_only(self):
        self.assertTrue(core.valid(core.blank()))
        self.assertFalse(core.valid(dict(core.blank(), framework40_installed=True)))
        self.assertFalse(core.valid(dict(core.blank(), framework48_installed=True)))
        self.assertFalse(core.valid(dict(core.blank(), native_only_managed="C:/private")))
        self.assertFalse(core.valid(dict(core.blank(), core_msi_candidate=True)))
        expected = dict(core.blank(), status="MEASURED",
                        media="VERIFIED_EXTRACTED_CORE", install="SUCCESS",
                        restart="COMPLETED", clr64_added=True,
                        loader="LOADED", native_only_managed="PASS",
                        core_msi_candidate=True)
        self.assertTrue(core.valid(expected))
        self.assertFalse(core.valid(dict(expected, install="EXIT_NONZERO")))
        self.assertFalse(core.valid(dict(expected, core_msi_candidate=False)))
        self.assertNotIn(".msi", str(expected))
        self.assertNotIn("C:", str(expected))

    def test_only_exact_core_msi_and_adjacent_original_mzz_are_allowed(self):
        with tempfile.TemporaryDirectory() as td:
            args = _synthetic_fixture(Path(td))
            prefix = args[1]
            self.assertEqual(core._original_core(prefix)[1], "UNSAFE")
            msi = _core_media(prefix)
            located, state = core._original_core(prefix)
            self.assertEqual(located, msi)
            self.assertEqual(state, "VERIFIED_EXTRACTED_CORE")
            (msi.parent / "netfx_Core.mzz").unlink()
            self.assertEqual(core._original_core(prefix)[1], "COMPANION_MISSING")
            (msi.parent / "netfx_Core.mzz").write_bytes(bytes(128 * 1024))
            msi.write_bytes(b"NOT_A_REAL_MSI" + bytes(4096))
            self.assertEqual(core._original_core(prefix)[1], "BAD_OLE")
            msi.unlink()
            msi.symlink_to(Path(td) / "external")
            self.assertEqual(core._original_core(prefix)[1], "UNSAFE")

    def test_private_msi_log_only_exports_fixed_category_without_vendor_content(self):
        with tempfile.TemporaryDirectory() as td:
            args = _synthetic_fixture(Path(td))
            _core_media(args[1])
            private = args[1] / "drive_c" / core.EXTRACT_FOLDER / core.LOG_NAME
            private.write_bytes(
                b"Private installation paths and customer secret\n"
                b"Error 1723: A DLL required for install could not be run\n"
                b"Action ended 12:00:01: CA_PrivateVendorThing. Return value 3\n")
            data = core.private_log(args[1])
            self.assertEqual(data, {
                "status": "SCANNED", "action": "CUSTOM_ACTION",
                "errors": ["CUSTOM_DLL_ACTION_FAILURE"]})
            self.assertTrue(core.valid_log(data))
            self.assertNotIn("Private", str(data))
            self.assertNotIn("VendorThing", str(data))
            private.write_bytes(b"x" * (core.MAX_FILE_BYTES + 1))
            self.assertEqual(core.private_log(args[1])["status"], "TRUNCATED")
            private.unlink()
            private.symlink_to(Path(td) / "private-other-log")
            self.assertEqual(core.private_log(args[1])["status"], "UNSAFE")
            self.assertFalse(core.valid_log({
                "status": "SCANNED", "action": "secret script", "errors": []}))

    def test_actual_extraction_branch_count_no_longer_blocks_signed_core(self):
        # The genuine run 44990034092 reported 17 dirs and 74 file
        # entries. The old scanner rejected even a directory with >16
        # immediate children, without ever trying the original MSI.
        with tempfile.TemporaryDirectory() as td:
            args = _synthetic_fixture(Path(td))
            prefix = args[1]
            found = _core_media(prefix)
            root = prefix / "drive_c" / core.EXTRACT_FOLDER
            for idx in range(17):
                folder = root / f"original-extract-branch-{idx:02d}"
                folder.mkdir()
                for num in range(4):
                    (folder / f"original-extra-{num}.dat").write_bytes(b"original placeholder")
            self.assertEqual(len(list(root.rglob("*.dat"))), 68)
            result, status = core._original_core(prefix)
            self.assertEqual(result, found)
            self.assertEqual(status, "VERIFIED_EXTRACTED_CORE")

    def test_nested_original_core_can_be_found_beyond_old_depth_limit(self):
        with tempfile.TemporaryDirectory() as td:
            args = _synthetic_fixture(Path(td))
            prefix = args[1]
            root = prefix / "drive_c" / core.EXTRACT_FOLDER
            subdir = root
            for idx in range(7):
                subdir = subdir / f"level-{idx}"
            subdir.mkdir(parents=True)
            package = subdir / "netfx_Core_x64.msi"
            package.write_bytes(core.OLE_SIGNATURE + bytes(4096))
            (subdir / "netfx_Core.mzz").write_bytes(bytes(128 * 1024))
            self.assertEqual(core._original_core(prefix),
                             (package, "VERIFIED_EXTRACTED_CORE"))

    def test_excessive_original_extraction_fanout_fails_with_fixed_status(self):
        with tempfile.TemporaryDirectory() as td:
            args = _synthetic_fixture(Path(td))
            prefix = args[1]
            _core_media(prefix)
            root = prefix / "drive_c" / core.EXTRACT_FOLDER
            for idx in range(core.MAX_BRANCH + 1):
                (root / f"branch-{idx:03d}").mkdir()
            self.assertEqual(core._original_core(prefix),
                             (None, "SCAN_BRANCH_LIMIT"))

    def test_no_original_msi_if_first_setup_worked_or_not_1603(self):
        with tempfile.TemporaryDirectory() as td:
            args = list(_synthetic_fixture(Path(td)))
            with mock.patch.object(core, "private_run") as start:
                args[5] = dict(args[5], persistent_native_managed=True)
                report = self.inspect(args, td)
                self.assertEqual(report["status"], "SKIPPED_ALREADY_NATIVE")
                args[5] = dict(args[5], persistent_native_managed=False)
                args[4] = dict(args[4], installer_exit_hex="00000000")
                report = self.inspect(args, td)
                self.assertEqual(report["status"], "SKIPPED_NOT_1603")
                start.assert_not_called()
            self.assertTrue(core.valid(report))

    def test_not_run_when_original_microsoft_cabinet_is_missing(self):
        with tempfile.TemporaryDirectory() as td:
            args = _synthetic_fixture(Path(td))
            msi = _core_media(args[1])
            (msi.parent / "netfx_Core.mzz").unlink()
            with mock.patch.object(core, "private_run") as start:
                result = self.inspect(args, td)
                start.assert_not_called()
            self.assertEqual(result["status"], "BLOCKED_MEDIA")
            self.assertEqual(result["media"], "COMPANION_MISSING")
            self.assertTrue(core.valid(result))

    def test_authentic_core_x64_install_attempt_cannot_fabricate_netfx40(self):
        with tempfile.TemporaryDirectory() as td:
            args = _synthetic_fixture(Path(td))
            _core_media(args[1])
            seen = []
            def launch(cmd, env, cwd, timeout):
                seen.append((cmd, env, cwd, timeout))
                self.assertEqual(cmd[1:3], ["msiexec.exe", "/i"])
                self.assertEqual(cmd[3], r"C:\\swcompat-netfx40-original-extract\\netfx_Core_x64.msi")
                self.assertEqual(cmd[-5:], ["/qn", "/norestart", "EXTUI=1", "/L*v", core.LOG_WINDOWS])
                self.assertEqual(env["WINEDLLOVERRIDES"], "fusion=b")
                self.assertEqual(cwd, args[1])
                self.assertEqual(timeout, 420)
                return "EXIT_NONZERO"
            with (
                mock.patch.object(core, "snapshot", return_value={"CLR64": ("ABSENT", None)}),
                mock.patch.object(core, "windows_media_path",
                                  return_value=r"C:\\swcompat-netfx40-original-extract\\netfx_Core_x64.msi"),
                mock.patch.object(core, "private_run", side_effect=launch),
                mock.patch.object(core, "wineboot_restart") as restart,
            ):
                result = self.inspect(args, td)
                restart.assert_not_called()
            self.assertEqual(len(seen), 1)
            self.assertEqual(result["status"], "MEASURED")
            self.assertEqual(result["install"], "EXIT_NONZERO")
            self.assertFalse(result["core_msi_candidate"])
            self.assertTrue(core.valid(result))

    def test_successful_core_proves_only_x64_core_candidate_not_full_framework(self):
        with tempfile.TemporaryDirectory() as td:
            args = _synthetic_fixture(Path(td))
            _core_media(args[1])
            snapshots = iter([
                {"CLR64": ("ABSENT", None)},
                {"CLR64": ("PE_AMD64", "signed original digest")}
            ])
            with (
                mock.patch.object(core, "snapshot", side_effect=lambda *_: next(snapshots)),
                mock.patch.object(core, "windows_media_path", return_value="C:\\original.msi"),
                mock.patch.object(core, "private_run", return_value="SUCCESS"),
                mock.patch.object(core, "wineboot_restart", return_value="COMPLETED"),
                mock.patch.object(core, "load_clr", return_value="LOADED"),
                mock.patch.object(core, "probe", return_value={
                    "managed": "PASS", "clr_family": "MICROSOFT_CLR_CANDIDATE"}),
            ):
                result = self.inspect(args, td)
            self.assertTrue(result["core_msi_candidate"])
            self.assertFalse(result["framework40_installed"])
            self.assertFalse(result["framework48_installed"])
            self.assertEqual(result["native_only_managed"], "PASS")
            self.assertTrue(core.valid(result))

    def test_unclean_timeout_never_runs_more_wine_commands(self):
        with tempfile.TemporaryDirectory() as td:
            args = _synthetic_fixture(Path(td))
            _core_media(args[1])
            with (
                mock.patch.object(core, "snapshot", return_value={"CLR64": ("ABSENT", None)}) as state,
                mock.patch.object(core, "windows_media_path", return_value="C:\\original.msi"),
                mock.patch.object(core, "private_run", return_value="TIMED_OUT_CLEANUP_DENIED"),
                mock.patch.object(core, "wineboot_restart") as restart,
                mock.patch.object(core, "load_clr") as load,
            ):
                result = self.inspect(args, td)
                self.assertEqual(state.call_count, 1)
                restart.assert_not_called()
                load.assert_not_called()
            self.assertEqual(result["restart"], "NOT_RUN")
            self.assertTrue(core.valid(result))

    def test_reject_non_disposable_paths_before_touching_vendor_media(self):
        with tempfile.TemporaryDirectory() as td:
            args = list(_synthetic_fixture(Path(td)))
            _core_media(args[1])
            with mock.patch.object(core, "verify_media") as verify:
                with self.assertRaises(ValueError):
                    core.inspect(*args)
                verify.assert_not_called()

    def test_ci_rejects_skipped_core_msi_even_when_original_clr_missing(self):
        project = Path(__file__).resolve().parents[1]
        workflow = (project / ".github/workflows/netfx40-legacy-ci.yml").read_text()
        validator = workflow.split(
            "- name: Validate that msxml3 cannot fabricate a CLR install", 1)[1]
        before_persistent, after_persistent = validator.split(
            '              if rr["persistent_native_managed"]:', 1)
        self.assertIn("core_requested =", before_persistent)
        self.assertIn("core_path.is_file() == core_requested", before_persistent)
        self.assertIn("genuine_1603 =", before_persistent)
        self.assertIn('and extracted["core_x64_ole_candidate"]', before_persistent)
        self.assertIn('assert core["status"] == "MEASURED"', before_persistent)
        self.assertIn('assert core["install"] != "NOT_RUN"', before_persistent)
        self.assertNotIn("core_requested =", after_persistent)
        self.assertIn("assert valid_core(core)", before_persistent)
        self.assertIn("assert valid_extract(extracted)", before_persistent)

    def test_ci_original_core_is_strictly_host_only_and_uploads_no_vendor_bytes(self):
        project = Path(__file__).resolve().parents[1]
        workflow = (project / ".github/workflows/netfx40-legacy-ci.yml").read_text()
        caller = (project / ".github/workflows/netfx40-wiage-core-msi-once-ci.yml").read_text()
        self.assertIn("inputs.try_40_core_msi_recovery && (!inputs.host_provenance_only", workflow)
        self.assertIn("inputs.wine_baseline != 'wiage-11.13'", workflow)
        self.assertIn("python3 -m scripts.netfx40_original_core_msi_recovery", workflow)
        self.assertIn("build/netfx40-original-core-msi-recovery.json", workflow)
        self.assertIn('assert core["framework40_installed"] is False', workflow)
        self.assertIn("host_provenance_only: true", caller)
        self.assertIn("try_40_core_msi_recovery: true", caller)
        self.assertIn("branches: [main]", caller)
        self.assertNotIn("actions/upload-artifact", caller)
        self.assertNotIn("workflow_dispatch", caller)


if __name__ == "__main__":
    unittest.main()
