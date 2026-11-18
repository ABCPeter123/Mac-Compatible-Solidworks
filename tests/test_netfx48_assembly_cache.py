"""Prove NGen cache preparation never fakes Microsoft runtime or escapes prefix."""
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase

from scripts.netfx48_assembly_cache import inspect_assembly_cache as check


class NativeNGenCacheTests(TestCase):
    def fixture(self, root):
        prefix = root / "prefix"
        windows = prefix / "drive_c" / "windows"
        windows.mkdir(parents=True)
        return prefix, windows

    def test_only_exact_missing_cache_directory_is_created_when_opted_in(self):
        with TemporaryDirectory() as td:
            prefix, windows = self.fixture(Path(td))
            self.assertEqual(check(prefix), "MISSING")
            self.assertFalse((windows / "assembly").exists())
            self.assertEqual(check(prefix, prepare=True), "CREATED")
            self.assertEqual(check(prefix, prepare=True), "PRESENT")
            self.assertEqual(check(prefix), "PRESENT")
            self.assertEqual(sorted(p.name for p in windows.iterdir()), ["assembly"])

    def test_parent_or_target_symlink_is_never_followed_or_mutated(self):
        with TemporaryDirectory() as td:
            root = Path(td)
            prefix, windows = self.fixture(root)
            outside = root / "outside"
            outside.mkdir()
            (windows / "assembly").symlink_to(outside, target_is_directory=True)
            self.assertEqual(check(prefix, prepare=True), "UNSAFE")
            self.assertEqual(list(outside.iterdir()), [])
            (windows / "assembly").unlink()
            windows.rmdir()
            windows.symlink_to(outside, target_is_directory=True)
            self.assertEqual(check(prefix, prepare=True), "UNSAFE")
            self.assertEqual(list(outside.iterdir()), [])

    def test_refuse_prefix_without_preexisting_windows_tree(self):
        with TemporaryDirectory() as td:
            root = Path(td)
            prefix = root / "prefix"
            prefix.mkdir()
            self.assertEqual(check(prefix, prepare=True), "UNSAFE")
            self.assertFalse((prefix / "drive_c").exists())
            self.assertRaises(ValueError, check, prefix, prepare="yes")

    def test_non_directory_cache_is_rejected(self):
        with TemporaryDirectory() as td:
            prefix, windows = self.fixture(Path(td))
            (windows / "assembly").write_text("unrelated", encoding="ascii")
            self.assertEqual(check(prefix, prepare=True), "UNSAFE")
