"""Only finite categories can leave an original signed NGen log observation."""
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase

from scripts import netfx48_ngen_log_evidence as ngen


class OriginalNGenLogEvidenceTests(TestCase):
    def setup(self, root, arch="X64"):
        prefix = root / "prefix"
        path = ngen._file(prefix, arch)
        path.parent.mkdir(parents=True, exist_ok=True)
        return prefix, path

    def test_only_appended_ngen_content_is_classified(self):
        with TemporaryDirectory() as td:
            prefix, path = self.setup(Path(td))
            path.write_bytes(b"Private installer and unrelated names.\n")
            before = ngen.baseline(prefix)
            self.assertEqual(ngen.inspect(prefix, before)["x64"], "UNCHANGED")
            with path.open("ab") as output:
                output.write(b"Compiling assembly SECRET.\nNgen failed to generate native code. "
                             b"Exception from HRESULT: 0x80070003\n")
            result = ngen.inspect(prefix, before)
            self.assertTrue(ngen.valid(result))
            self.assertEqual(result["x64"], "CLASSIFIED")
            self.assertEqual(result["x86"], "NO_LOG")
            self.assertEqual(result["signals"], [
                "NGEN_COMPILE", "NGEN_FAILURE", "PATH_NOT_FOUND"])
            self.assertNotIn("SECRET", str(result))
            self.assertNotIn("Private installer", str(result))

    def test_existing_unrelated_old_error_is_not_replayed(self):
        with TemporaryDirectory() as td:
            prefix, path = self.setup(Path(td))
            path.write_bytes(b"old 0x80070424\n")
            before = ngen.baseline(prefix)
            with path.open("ab") as output:
                output.write(b"new operation has no error\n")
            result = ngen.inspect(prefix, before)
            self.assertEqual(result["signals"], [])
            self.assertEqual(result["x64"], "CLASSIFIED")

    def test_new_utf16_log_is_classified_without_text_leak(self):
        with TemporaryDirectory() as td:
            prefix, path = self.setup(Path(td), "X86")
            before = ngen.baseline(prefix)
            path.write_bytes("Error compiling secret: 0x80070002".encode("utf-16"))
            result = ngen.inspect(prefix, before)
            self.assertEqual(result["signals"], ["FILE_NOT_FOUND", "NGEN_FAILURE"])
            self.assertEqual(result["x86"], "CLASSIFIED")
            self.assertNotIn("secret", str(result))

    def test_symlinks_and_oversize_are_rejected(self):
        with TemporaryDirectory() as td:
            root = Path(td)
            prefix, path = self.setup(root)
            outside = root / "outside"
            outside.write_text("0x80070003 secret", encoding="utf-8")
            path.symlink_to(outside)
            result = ngen.inspect(prefix, ngen.baseline(prefix))
            self.assertEqual(result["x64"], "UNSAFE")
            self.assertEqual(result["signals"], [])
            path.unlink()
            path.write_bytes(b"x" * (ngen.MAX_LOG_BYTES + 1))
            result = ngen.inspect(prefix, ngen.baseline(prefix))
            self.assertEqual(result["x64"], "TOO_LARGE")
            self.assertEqual(result["signals"], [])

    def test_invalid_public_report_rejected(self):
        self.assertTrue(ngen.valid(ngen.blank()))
        self.assertFalse(ngen.valid(dict(ngen.blank(), private_log="secret")))
        self.assertFalse(ngen.valid(dict(ngen.blank(), signals=["0x80070003"])))
        self.assertFalse(ngen.valid(dict(ngen.blank(), signals=["PATH_NOT_FOUND"])))
        self.assertFalse(ngen.valid(dict(ngen.blank(), x64="SECRET")))
