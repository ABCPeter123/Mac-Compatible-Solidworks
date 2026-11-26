"""Private staging tests using only self-authored synthetic data."""
from pathlib import Path
import tempfile
import unittest

from scripts.netfx481_ipd_stage import copy_verified_tree, digest_tree, inventory, safe_name


class StageTests(unittest.TestCase):
    def test_verified_tree_copy_and_digest(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d).resolve()
            a, b = root / "a", root / "b"
            a.write_bytes(b"test manifest")
            b.write_bytes(b"test payload")
            members = {"assembly.manifest": a, "assembly/payload.dll": b}
            expected = digest_tree(members)
            destination = root / "stage"
            report = copy_verified_tree(members, destination, 2, expected)
            self.assertTrue(report["stage_verified"])
            self.assertEqual(report["stage_root_manifests"], 1)
            self.assertEqual(report["stage_nested_files"], 1)
            self.assertEqual(digest_tree(inventory(destination)), expected)
            with self.assertRaises(ValueError):
                copy_verified_tree(members, destination, 2, expected)

    def test_reject_incomplete_or_wrong_tree_before_writing(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d).resolve()
            a = root / "a"
            a.write_bytes(b"payload")
            members = {"a": a}
            expected = digest_tree(members)
            for count, digest in [(2, expected), (1, "0" * 64)]:
                with self.assertRaises(ValueError):
                    copy_verified_tree(members, root / "stage", count, digest)
                self.assertFalse((root / "stage").exists())

    def test_reject_traversal_and_windows_aliases(self):
        for name in ["../a", "c:/a", "a//b", "A", "a/aux.dll", "a/b.", "a/b?", "a\\b"]:
            with self.subTest(name=name):
                with self.assertRaises(ValueError):
                    safe_name(name)

    def test_reject_file_directory_collision(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d).resolve()
            a = root / "a"
            a.write_bytes(b"payload")
            members = {"a": a, "a/b": a}
            with self.assertRaises(OSError):
                copy_verified_tree(members, root / "stage", 2, digest_tree(members))
            self.assertFalse((root / "stage").exists())

    def test_reject_links(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d).resolve()
            a = root / "a"
            a.write_bytes(b"payload")
            link = root / "link"
            try:
                link.symlink_to(a)
            except OSError:
                self.skipTest("Symlink creation unavailable")
            with self.assertRaises(ValueError):
                digest_tree({"a": link})


if __name__ == "__main__":
    unittest.main()
