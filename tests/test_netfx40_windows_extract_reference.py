"""Source-authored fixtures for the native Windows /x differential."""
from pathlib import Path
from tempfile import TemporaryDirectory
import subprocess
import unittest
from unittest import mock

from scripts import netfx40_windows_extract_reference as reference
from scripts.netfx40_offline_extract import OLE_SIGNATURE, validate


class NativeWindowsExtractReferenceTests(unittest.TestCase):
    def _media(self, parent):
        installer = parent / "dotNetFx40_Full_x86_x64.exe"
        installer.write_bytes(b"synthetic-microsoft-reference-stub")
        return installer

    def test_successful_reference_reports_only_finite_metadata_and_cleans(self):
        with TemporaryDirectory() as td:
            base = Path(td)
            installer = self._media(base)
            root = base / reference.ROOT_NAME

            def fake_run(argv, **kwargs):
                # Temp roots may use /var vs /private/var on macOS and
                # long vs 8.3 short paths on Windows. Compare actual files.
                self.assertTrue(Path(argv[0]).samefile(installer))
                self.assertEqual(argv[2], "/q")
                self.assertTrue(argv[1].startswith("/x:"))
                self.assertTrue(Path(argv[1][3:]).samefile(root))
                self.assertIs(kwargs["stdout"], subprocess.DEVNULL)
                self.assertIs(kwargs["stderr"], subprocess.DEVNULL)
                self.assertTrue(root.is_dir())
                (root / "netfx_Core_x64.msi").write_bytes(OLE_SIGNATURE + b"x" * 7000)
                return mock.Mock(returncode=0)

            with (mock.patch.object(reference, "_is_windows", return_value=True),
                  mock.patch.object(reference, "verify_media"),
                  mock.patch.object(reference.subprocess, "run", side_effect=fake_run)):
                result = reference.inspect(installer, timeout=50)
            self.assertTrue(validate(result))
            self.assertEqual(result["status"], "EXTRACTED_MSI_CANDIDATES")
            self.assertTrue(result["core_x64_ole_candidate"])
            self.assertNotIn(td, str(result))
            self.assertFalse(root.exists())

    def test_nonzero_reference_never_claims_original_package(self):
        with TemporaryDirectory() as td:
            base = Path(td)
            installer = self._media(base)
            root = base / reference.ROOT_NAME
            with (mock.patch.object(reference, "_is_windows", return_value=True),
                  mock.patch.object(reference, "verify_media"),
                  mock.patch.object(reference.subprocess, "run",
                                    return_value=mock.Mock(returncode=1603))):
                result = reference.inspect(installer)
            self.assertEqual(result["status"], "EXTRACTION_NONZERO")
            self.assertEqual(result["ole_msi_candidates"], 0)
            self.assertFalse(root.exists())
            self.assertTrue(validate(result))

    def test_timed_out_extraction_cleans_private_files(self):
        with TemporaryDirectory() as td:
            base = Path(td)
            installer = self._media(base)
            root = base / reference.ROOT_NAME
            with (mock.patch.object(reference, "_is_windows", return_value=True),
                  mock.patch.object(reference, "verify_media"),
                  mock.patch.object(reference.subprocess, "run",
                                    side_effect=subprocess.TimeoutExpired("setup", 30))):
                result = reference.inspect(installer)
            self.assertEqual(result["status"], "EXTRACTION_TIMEOUT")
            self.assertFalse(root.exists())
            self.assertTrue(validate(result))

    def test_existing_or_linked_output_never_overwritten(self):
        with TemporaryDirectory() as td:
            base = Path(td)
            installer = self._media(base)
            root = base / reference.ROOT_NAME
            root.mkdir()
            (root / "sentinel").write_text("do not erase")
            with (mock.patch.object(reference, "_is_windows", return_value=True),
                  mock.patch.object(reference, "verify_media")):
                with self.assertRaises(ValueError):
                    reference.inspect(installer)
            self.assertEqual((root / "sentinel").read_text(), "do not erase")

    def test_nonwindows_runtime_refuses_execution(self):
        with TemporaryDirectory() as td:
            installer = self._media(Path(td))
            with mock.patch.object(reference, "_is_windows", return_value=False):
                with self.assertRaises(ValueError):
                    reference.inspect(installer)


if __name__ == "__main__":
    unittest.main()
