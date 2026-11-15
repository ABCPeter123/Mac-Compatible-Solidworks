"""Original CBS manifest semantic inspection must never copy Microsoft XML."""
import subprocess
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase, main, mock
from scripts import netfx481_mum_semantics as sem

MUM = (b'<?xml version="1.0" encoding="utf-8"?>'
       b'<assembly xmlns="urn:schemas-microsoft-com:asm.v3">'
       b'<assemblyIdentity processorArchitecture="amd64" name="PRIVATE-ENTITY"/>'
       b'<package><update name="PRIVATE_UPDATE"><package><assemblyIdentity '
       b'processorArchitecture="x86" name="INTERNAL"/></package></update></package>'
       b'<dependency><dependentAssembly/></dependency>'
       b'<registryKeys><registryKey name="SECRET_KEY"><registryValue '
       b'name="SECRET_VALUE"/></registryKey></registryKeys>'
       b'</assembly>')


class OriginalMumTests(TestCase):
    def test_count_package_update_dependency_arch_and_registry_without_xml_leak(self):
        r = sem.summarize_mum(MUM)
        self.assertEqual(r["tags"]["assembly"], 1)
        self.assertEqual(r["tags"]["package"], 2)
        self.assertEqual(r["tags"]["update"], 1)
        self.assertEqual(r["tags"]["dependency"], 1)
        self.assertEqual(r["tags"]["registryValue"], 1)
        self.assertEqual(r["architectures"]["amd64"], 1)
        self.assertEqual(r["architectures"]["x86"], 1)
        self.assertTrue(r["with_update"])
        self.assertNotIn("SECRET", str(r))
        self.assertNotIn("PRIVATE", str(r))

    def test_dtd_malformed_or_oversize_never_counts_as_good(self):
        self.assertIsNone(sem.summarize_mum(b"<!DOCTYPE hostile><assembly/>"))
        self.assertIsNone(sem.summarize_mum(b"<assembly><unclosed>"))
        self.assertIsNone(sem.summarize_mum(b"X" * (sem.MAX_FILE + 1)))
        self.assertFalse(sem.valid(dict(sem.blank(), raw_mum="PRIVATE")))
        self.assertFalse(sem.valid(dict(sem.blank(), genuine_servicing_performed=True)))

    def test_extracted_mum_is_classified_but_never_exposed(self):
        with TemporaryDirectory() as td:
            root = Path(td)
            exe = root / "7z.exe"
            cab = root / "signed-candidate.cab"
            exe.write_bytes(b"fixture")
            cab.write_bytes(b"fixture")
            target = root / "private"
            def extraction(_args, **_kwargs):
                (target / "update.mum").write_bytes(MUM)
                return subprocess.CompletedProcess([], 0)
            with mock.patch.object(sem.subprocess, "run", side_effect=extraction):
                r = sem.inspect_cab_mums(exe, cab, target)
            self.assertTrue(sem.valid(r))
            self.assertEqual(r["status"], "PARSED")
            self.assertEqual(r["mums_seen"], 1)
            self.assertEqual(r["mums_parsed"], 1)
            self.assertEqual(r["mum_with_update"], 1)
            self.assertEqual(r["mum_with_dependency"], 1)
            self.assertFalse(r["genuine_servicing_performed"])
            self.assertNotIn("SECRET", str(r))

    def test_unexpected_existing_extract_folder_is_refused(self):
        with TemporaryDirectory() as td:
            p = Path(td)
            (p / "private").mkdir()
            r = sem.inspect_cab_mums(p / "7z.exe", p / "cab.cab", p / "private")
            self.assertEqual(r, sem.blank("UNSAFE_DIRECTORY"))


if __name__ == "__main__":
    main()
