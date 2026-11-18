"""Only authenticated experimental Wine archive metadata can be extracted."""
import io
from pathlib import Path
import tarfile
from tempfile import TemporaryDirectory
from unittest import TestCase

from scripts import wine_engine_archive as w


def make_archive(path: Path, *, wine="wiage/bin/wine",
                 server="wiage/bin/wineserver", link=None, bad=None):
    with tarfile.open(path, "w:gz") as archive:
        for name in (wine, server):
            member = tarfile.TarInfo(name)
            if link is not None and name == wine:
                member.type = tarfile.SYMTYPE
                member.linkname = link
            else:
                member.size = 2
                member.mode = 0o755
            archive.addfile(member, None if member.issym() else io.BytesIO(b"MZ"))
        if bad:
            member = tarfile.TarInfo(bad)
            member.size = 2
            archive.addfile(member, io.BytesIO(b"MZ"))


class PinnedWineRuntimeArchiveTests(TestCase):
    def test_accepts_only_fixed_wine_and_wineserver_inside_wiage(self):
        with TemporaryDirectory() as td:
            path = Path(td) / "wiage-runtime.tar.gz"
            make_archive(path)
            self.assertEqual(w.verify(path), {
                "status": "SAFE", "files_checked": 2})
            make_archive(path, wine="./wiage/bin/wine",
                         server="./wiage/bin/wineserver")
            self.assertEqual(w.verify(path)["status"], "SAFE")

    def test_accepts_tar_dot_root_directory_but_no_root_level_payload(self):
        with TemporaryDirectory() as td:
            path = Path(td) / "wiage-runtime.tar.gz"
            with tarfile.open(path, "w:gz") as archive:
                root = tarfile.TarInfo("./")
                root.type = tarfile.DIRTYPE
                archive.addfile(root)
                for name in ("./wiage/bin/wine", "./wiage/bin/wineserver"):
                    member = tarfile.TarInfo(name)
                    member.size = 2
                    member.mode = 0o755
                    archive.addfile(member, io.BytesIO(b"MZ"))
            self.assertEqual(w.verify(path), {"status": "SAFE", "files_checked": 3})
            with tarfile.open(path, "w:gz") as archive:
                root = tarfile.TarInfo("./")
                root.size = 2
                archive.addfile(root, io.BytesIO(b"MZ"))
                for name in ("wiage/bin/wine", "wiage/bin/wineserver"):
                    member = tarfile.TarInfo(name)
                    member.size = 2
                    archive.addfile(member, io.BytesIO(b"MZ"))
            with self.assertRaises(ValueError):
                w.verify(path)
            with tarfile.open(path, "w:gz") as archive:
                root = tarfile.TarInfo("./")
                root.type = tarfile.SYMTYPE
                root.linkname = "wiage"
                archive.addfile(root)
                for name in ("wiage/bin/wine", "wiage/bin/wineserver"):
                    member = tarfile.TarInfo(name)
                    member.size = 2
                    archive.addfile(member, io.BytesIO(b"MZ"))
            with self.assertRaises(ValueError):
                w.verify(path)

    def test_rejects_traversal_absolute_special_and_escape_links(self):
        with TemporaryDirectory() as td:
            path = Path(td) / "wiage-runtime.tar.gz"
            for bad in ("wiage/../outside.txt", "/tmp/evil",
                        "evil/target", "wiage\\..\\evil",):
                with self.subTest(bad=bad):
                    make_archive(path, bad=bad)
                    with self.assertRaises(ValueError):
                        w.verify(path)
            for link in ("/etc/passwd", "../../../../etc/passwd",
                         "../../../outside"):
                with self.subTest(link=link):
                    make_archive(path, link=link)
                    with self.assertRaises(ValueError):
                        w.verify(path)
            make_archive(path, link="../lib/wine", bad=None)
            self.assertEqual(w.verify(path)["status"], "SAFE")
            with tarfile.open(path, "w:gz") as archive:
                member = tarfile.TarInfo("wiage/unsafe")
                member.type = tarfile.CHRTYPE
                archive.addfile(member)
            with self.assertRaises(ValueError):
                w.verify(path)

    def test_fails_closed_for_missing_wineserver_symlink_and_corrupt_archive(self):
        with TemporaryDirectory() as td:
            root = Path(td)
            path = root / "wiage-runtime.tar.gz"
            path.write_bytes(b"not a gzip")
            with self.assertRaises(ValueError):
                w.verify(path)
            make_archive(path, server="wiage/bin/other")
            with self.assertRaises(ValueError):
                w.verify(path)
            real = root / "real.tar.gz"
            make_archive(real)
            path.unlink()
            path.symlink_to(real)
            with self.assertRaises(ValueError):
                w.verify(path)

    def test_reject_duplicate_untrusted_member(self):
        with TemporaryDirectory() as td:
            path = Path(td) / "wiage.tar.gz"
            with tarfile.open(path, "w:gz") as archive:
                for _ in range(2):
                    member = tarfile.TarInfo("wiage/bin/wine")
                    member.size = 2
                    archive.addfile(member, io.BytesIO(b"MZ"))
                member = tarfile.TarInfo("wiage/bin/wineserver")
                member.size = 2
                archive.addfile(member, io.BytesIO(b"MZ"))
            with self.assertRaises(ValueError):
                w.verify(path)
