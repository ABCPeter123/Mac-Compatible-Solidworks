import hashlib
import io
from pathlib import Path
import tarfile
import tempfile
import unittest
from scripts.magevk_backend_trial import extract_library, wire_loader


class MageVKTests(unittest.TestCase):
    def archive(self, root, entries):
        p = root / "a.tar.gz"
        with tarfile.open(p, "w:gz") as f:
            for name, data in entries:
                member = tarfile.TarInfo(name)
                member.size = len(data)
                f.addfile(member, io.BytesIO(data))
        return p, hashlib.sha256(p.read_bytes()).hexdigest()

    def test_only_expected_library_extracted(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            p, digest = self.archive(root, [("libMoltenVK.dylib", b"x"*1024), ("extra", b"no")])
            dest = root / "isolated/libMoltenVK.dylib"
            extract_library(p, dest, digest=digest)
            self.assertEqual(dest.read_bytes(), b"x"*1024)
            self.assertFalse((dest.parent / "extra").exists())

    def test_bad_hash_and_traversal_refused(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            p, digest = self.archive(root, [("../libMoltenVK.dylib", b"x"*1024)])
            dest = root / "out"
            for expected in ("0"*64, digest):
                with self.assertRaises(ValueError):
                    extract_library(p, dest, digest=expected)
                self.assertFalse(dest.exists())

    def test_preserve_existing_regular_and_dangling_loader(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            engine = root / "wiage"
            a = engine / "lib"
            b = a / "wine/x86_64-unix"
            b.mkdir(parents=True)
            old = a / "libvulkan.1.dylib"
            old.write_bytes(b"original")
            dangling = b / old.name
            dangling.symlink_to("missing.dylib")
            new = root / "verified.dylib"
            new.write_bytes(b"new")
            wire_loader(engine, new)
            self.assertEqual(old.resolve(), new.resolve())
            self.assertEqual(dangling.resolve(), new.resolve())
            self.assertEqual((a / (old.name + ".swcompat-original")).read_bytes(), b"original")
            self.assertEqual(str((b / (old.name + ".swcompat-original")).readlink()), "missing.dylib")
