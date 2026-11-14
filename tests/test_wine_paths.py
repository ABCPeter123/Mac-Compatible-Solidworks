"""Windows programs must receive Win32 paths, not host macOS paths."""
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from swcompat.wine_paths import windows_media_path


class WinePathsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.media = root / "media with spaces" / "Prereq.msi"
        self.media.parent.mkdir()
        self.media.write_bytes(b"synthetic package")
        self.prefix = root / "prefix"
        (self.prefix / "dosdevices").mkdir(parents=True)
        self.wine = root / "wine"
        self.wine.write_text("#!/bin/sh\nexit 1\n")
        self.wine.chmod(0o755)

    def test_prefers_actual_winepath_mapping_and_same_prefix(self):
        run = mock.Mock(returncode=0, stdout=b"E:\\Windows Media\\Prereq.msi\n")
        with mock.patch("swcompat.wine_paths.shutil.which", return_value="/usr/bin/winepath"), \
             mock.patch("swcompat.wine_paths.subprocess.run", return_value=run) as call:
            output = windows_media_path(self.wine, self.prefix, self.media)
        self.assertEqual(output, "E:\\Windows Media\\Prereq.msi")
        self.assertEqual(call.call_args.kwargs["env"]["WINEPREFIX"], str(self.prefix))
        self.assertEqual(call.call_args.kwargs["timeout"], 15)
        self.assertNotIn("shell", call.call_args.kwargs)

    def test_rejects_unsafe_winepath_output(self):
        bad = mock.Mock(returncode=0, stdout=b"C:\\valid.msi\npassword:s:bad")
        with mock.patch("swcompat.wine_paths.shutil.which", return_value=None), \
             mock.patch("swcompat.wine_paths.subprocess.run", return_value=bad):
            with self.assertRaisesRegex(ValueError, "map installation media"):
                windows_media_path(self.wine, self.prefix, self.media)

    def test_validated_z_drive_fallback(self):
        if os.name == "nt":
            self.skipTest("Wine DOS symlinks only on Unix")
        (self.prefix / "dosdevices" / "z:").symlink_to("/")
        with mock.patch("swcompat.wine_paths.shutil.which", return_value=None), \
             mock.patch("swcompat.wine_paths.subprocess.run", side_effect=OSError):
            result = windows_media_path(self.wine, self.prefix, self.media)
        self.assertTrue(result.startswith("Z:\\"))
        self.assertTrue(result.endswith("\\media with spaces\\Prereq.msi"))

    def test_never_assume_unmapped_z_drive(self):
        with mock.patch("swcompat.wine_paths.shutil.which", return_value=None), \
             mock.patch("swcompat.wine_paths.subprocess.run", side_effect=OSError):
            with self.assertRaisesRegex(ValueError, "map installation media"):
                windows_media_path(self.wine, self.prefix, self.media)

    def test_reject_media_symlink(self):
        alias = self.media.parent / "linked.msi"
        try:
            alias.symlink_to(self.media)
        except (OSError, NotImplementedError):
            self.skipTest("symlink unavailable")
        with self.assertRaisesRegex(ValueError, "Linked media"):
            windows_media_path(self.wine, self.prefix, alias)


if __name__ == "__main__":
    unittest.main()
