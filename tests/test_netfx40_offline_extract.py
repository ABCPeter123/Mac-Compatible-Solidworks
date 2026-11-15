"""Do not confuse original Microsoft extraction with native CLR installation."""
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest import mock

from scripts import netfx40_offline_extract as ex


class MicrosoftOfflineExtractTests(unittest.TestCase):
    def test_source_authored_ole_msi_reference_is_only_format_candidate(self):
        with TemporaryDirectory() as td:
            root = Path(td)
            (root / "netfx_Core_x64.msi").write_bytes(
                ex.OLE_SIGNATURE + b"\0" * 6000)
            (root / "netfx_Core_x86.msi").write_bytes(b"not MSI" * 850)
            r = ex.scan(root)
            self.assertEqual(r["status"], "EXTRACTED_MSI_CANDIDATES")
            self.assertEqual(r["msi_entries"], 2)
            self.assertEqual(r["ole_msi_candidates"], 1)
            self.assertTrue(r["core_x64_ole_candidate"])
            self.assertTrue(ex.validate(r))
            for token in ("netfx_Core_x64.msi", td):
                self.assertNotIn(token, str(r))
            self.assertFalse(ex.validate(dict(r, original_msi_path=td)))
            self.assertFalse(ex.validate(dict(r, status="NATIVE_CLR_READY")))

    def test_no_ole_headers_is_not_original_msi_proof(self):
        with TemporaryDirectory() as td:
            root = Path(td)
            (root / "netfx_Core_x64.msi").write_bytes(b"corrupt" * 900)
            r = ex.scan(root)
            self.assertEqual(r["status"], "NO_OLE_MSI_CANDIDATES")
            self.assertEqual(r["msi_entries"], 1)
            self.assertEqual(r["ole_msi_candidates"], 0)
            self.assertFalse(r["core_x64_ole_candidate"])
            self.assertTrue(ex.validate(r))

    def test_symlinked_candidate_does_not_qualify(self):
        with TemporaryDirectory() as td:
            root = Path(td)
            outside = root.parent / "netfx_untrusted.msi"
            (root / "netfx_Core_x64.msi").symlink_to(outside)
            r = ex.scan(root)
            self.assertEqual(r["msi_entries"], 0)
            self.assertTrue(ex.validate(r))

    def test_limits_fail_closed_and_exclude_private_content(self):
        with TemporaryDirectory() as td:
            root = Path(td)
            for i in range(ex.MAX_MSIS + 3):
                (root / f"netfx_{i:03d}.msi").write_bytes(
                    ex.OLE_SIGNATURE + b"*" * 7000)
            r = ex.scan(root)
            self.assertEqual(r["status"], "PARTIAL_SCAN")
            self.assertEqual(r["msi_entries"], ex.MAX_MSIS)
            self.assertTrue(ex.validate(r))
            self.assertFalse(ex.validate(dict(r, msi_entries=999)))
            self.assertFalse(ex.validate(dict(r, core_x64_ole_candidate=1)))

    @unittest.skipIf(os.name == "nt", "Source-authored Wine invocation is POSIX only")
    def test_original_signed_installer_scoped_x_argument_without_install(self):
        with TemporaryDirectory() as td:
            prefix = Path(td) / "prefix"
            (prefix / "drive_c").mkdir(parents=True)
            wine = Path(td) / "wine"
            wine.write_bytes(b"wine")
            wine.chmod(0o700)
            installer = Path(td) / "dotNetFx40_Full_x86_x64.exe"
            installer.write_bytes(b"stub")
            core = prefix / "drive_c" / ex.EXTRACT_FOLDER / "netfx_Core_x64.msi"

            def fake_extract(*args, **kwargs):
                self.assertIn("/x:" + ex.EXTRACT_WINDOWS, args[0])
                self.assertIn("/q", args[0])
                self.assertNotIn("/c:install.exe", str(args[0]))
                self.assertIs(kwargs["stdout"], ex.subprocess.DEVNULL)
                core.write_bytes(ex.OLE_SIGNATURE + b"!" * 7000)
                return mock.Mock(returncode=0)

            with (
                mock.patch.object(ex, "validate_prefix"),
                mock.patch.object(ex, "verify_media"),
                mock.patch.object(ex.subprocess, "run",
                                  side_effect=fake_extract) as runner,
            ):
                r = ex.inspect(wine, prefix, installer, timeout=35)
            self.assertEqual(r["status"], "EXTRACTED_MSI_CANDIDATES")
            self.assertEqual(r["ole_msi_candidates"], 1)
            self.assertTrue(r["core_x64_ole_candidate"])
            self.assertTrue(ex.validate(r))
            self.assertNotIn("install.exe", str(r))
            self.assertEqual(runner.call_args.kwargs["stderr"], ex.subprocess.DEVNULL)

    @unittest.skipIf(os.name == "nt", "Wine-only failure path")
    def test_extract_nonzero_does_not_claim_payload(self):
        with TemporaryDirectory() as td:
            prefix = Path(td) / "prefix"
            (prefix / "drive_c").mkdir(parents=True)
            wine = Path(td) / "wine"
            wine.write_bytes(b"wine")
            wine.chmod(0o700)
            installer = Path(td) / "dotNetFx40_Full_x86_x64.exe"
            installer.write_bytes(b"stub")
            with (
                mock.patch.object(ex, "validate_prefix"),
                mock.patch.object(ex, "verify_media"),
                mock.patch.object(ex.subprocess, "run",
                                  return_value=mock.Mock(returncode=1603)),
            ):
                r = ex.inspect(wine, prefix, installer)
            self.assertEqual(r["status"], "EXTRACTION_NONZERO")
            self.assertEqual(r["process"], "NONZERO")
            self.assertEqual(r["msi_entries"], 0)
            self.assertTrue(ex.validate(r))


if __name__ == "__main__":
    unittest.main()
