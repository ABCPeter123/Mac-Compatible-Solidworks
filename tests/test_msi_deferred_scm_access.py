"""Strict read-only status classifications for source-authored MSI SCM control."""
import hashlib
import os
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory
import unittest
from unittest import mock
from scripts import msi_deferred_scm_access as p


class DeferredScmTests(unittest.TestCase):
    @unittest.skipIf(os.name == "nt", "Wine experiment POSIX only")
    def test_source_authored_happy_path(self):
        with TemporaryDirectory() as td:
            root = Path(td)
            wine = root / "wine"
            wine.write_bytes(b"fake")
            wine.chmod(0o755)
            msi = root / p.MSI_NAME
            msi.write_bytes(b"SELF_AUTHORED_FIXTURE")
            sha = root / "digest"
            sha.write_text(hashlib.sha256(msi.read_bytes()).hexdigest())
            folder = root / "drive_c" / "windows" / "Temp"
            folder.mkdir(parents=True)
            marker = root / "drive_c" / "Program Files" / "SWCompatDeferredScmProbe"
            marker.mkdir(parents=True)
            def run(*args, **kwargs):
                (folder / p.STATUS_FILE).write_bytes(b"PASS")
                (folder / p.CREATE_STATUS_FILE).write_bytes(b"PASS")
                (folder / p.REGISTRY_STATUS_FILE).write_bytes(b"PASS")
                (marker / "msi_deferred_scm_marker.txt").write_bytes(p.MARKER)
                return subprocess.CompletedProcess(args, 0)
            with mock.patch.object(p, "validate_prefix"), \
                 mock.patch.object(p, "windows_media_path", return_value="Z:\\fixture.msi"), \
                 mock.patch.object(p.subprocess, "run", side_effect=run):
                result = p.inspect(wine, root, msi, sha)
            self.assertTrue(p.valid(result))
            self.assertTrue(result["self_authored_transaction"])
            self.assertEqual(result["deferred_create"], "PASS")
            self.assertEqual(result["deferred_registry"], "PASS")
            self.assertFalse(result["native_microsoft_clr"])

    def test_no_success_on_missing_status_or_forged_clr(self):
        r = dict(process="ZERO", deferred_scm="NO_REPORT", deferred_create="NO_REPORT", deferred_registry="NO_REPORT", installed_file="PRESENT_MATCH",
                 self_authored_transaction=False, native_microsoft_clr=False,
                 solidworks_compatibility="NOT_DEMONSTRATED")
        self.assertTrue(p.valid(r))
        self.assertFalse(p.valid(dict(r, self_authored_transaction=True)))
        self.assertFalse(p.valid(dict(r, native_microsoft_clr=True)))
        self.assertFalse(p.valid(dict(r, deferred_registry="REGISTRY_FAKE_CLR_RELEASE")))
        self.assertFalse(p.valid(dict(r, extra_private_path="SECRETS")))
        self.assertFalse(p.valid(dict(r, deferred_scm="SERVICE_FOUND_OUTSIDE_FIXTURE")))

    def test_explicit_status_bounded(self):
        with TemporaryDirectory() as td:
            root = Path(td)
            path = root / "drive_c" / "windows" / "Temp"
            path.mkdir(parents=True)
            self.assertEqual(p._status(root), "NO_REPORT")
            f = path / p.STATUS_FILE
            f.write_bytes(b"PASS")
            self.assertEqual(p._status(root), "PASS")
            self.assertEqual(p._status(root, p.CREATE_STATUS_FILE), "NO_REPORT")
            self.assertEqual(p._status(root, p.REGISTRY_STATUS_FILE), "NO_REPORT")
            f.write_bytes(b"X" * 256)
            self.assertEqual(p._status(root), "INVALID_REPORT")
            with self.assertRaises(ValueError):
                p._status(root, "../PRIVATE")


if __name__ == "__main__":
    unittest.main()
