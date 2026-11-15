"""Finite Win32 CreateProcessW diagnostic and private marker-file regression tests."""
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest import mock

from scripts import msi_action_spawn_trial as spawn


class Win32MsiProbeSpawnTests(unittest.TestCase):
    def test_exact_marker_schema(self):
        raw = (b"SWCOMPAT_SPAWN_STATUS=STARTED\n"
               b"SWCOMPAT_SPAWN_CHILD_EXIT=ZERO\n"
               b"SWCOMPAT_SPAWN_ERROR=NONE\n")
        r = spawn.parse(raw, 0)
        self.assertEqual(r, {"status": "STARTED",
                             "child_exit": "ZERO", "error": "NONE"})
        self.assertTrue(spawn.validate(r))
        for broken in (raw + b"SWCOMPAT_SPAWN_PATH=PRIVATE\n",
                       raw + raw, raw.replace(b"ZERO", b"PRIVATE")):
            self.assertEqual(spawn.parse(broken, 0)["status"], "MALFORMED")
        self.assertEqual(spawn.parse(raw, 1)["status"], "BAD_EXIT")
        self.assertFalse(spawn.validate(dict(r, private_path="C:\\Secret")))
        self.assertFalse(spawn.validate(dict(r, status="START_FAILED")))
        failure = spawn.parse(
            b"SWCOMPAT_SPAWN_STATUS=START_FAILED\n"
            b"SWCOMPAT_SPAWN_CHILD_EXIT=NOT_VERIFIED\n"
            b"SWCOMPAT_SPAWN_ERROR=FILE_NOT_FOUND\n", 0)
        self.assertTrue(spawn.validate(failure))
        self.assertEqual(failure["error"], "FILE_NOT_FOUND")

    @unittest.skipIf(os.name == "nt", "Wine-only process smoke")
    def test_win32_report_is_only_enumerated_markers_and_removed(self):
        with TemporaryDirectory() as td:
            root = Path(td)
            wine = root / "wine"
            wine.write_bytes(b"wine")
            probe = root / "msi_custom_action_table_probe.exe"
            probe.write_bytes(b"fixture")
            launcher = root / "msi_action_spawn_probe.exe"
            launcher.write_bytes(b"fixture")
            output = root / "drive_c" / "windows" / "temp" / "swcompat_ca_spawn.status"

            def run_fixture(*args, **kwargs):
                output.write_bytes(
                    b"SWCOMPAT_SPAWN_STATUS=STARTED\r\n"
                    b"SWCOMPAT_SPAWN_CHILD_EXIT=ZERO\r\n"
                    b"SWCOMPAT_SPAWN_ERROR=NONE\r\n")
                return mock.Mock(stdout=b"", returncode=0)

            with (
                mock.patch.object(spawn, "validate_prefix"),
                mock.patch.object(spawn, "windows_media_path",
                                  return_value=r"Z:\known\msi_custom_action_table_probe.exe"),
                mock.patch.object(spawn.subprocess, "run", side_effect=run_fixture) as runner,
            ):
                got = spawn.inspect(wine, root, launcher, probe)
            self.assertEqual(got["status"], "STARTED")
            self.assertFalse(output.exists())
            argv = runner.call_args.args[0]
            self.assertEqual(argv[1], str(launcher.resolve()))
            self.assertNotIn("PRIVATE", str(got))
            self.assertEqual(runner.call_args.kwargs["stderr"], spawn.subprocess.DEVNULL)

    def test_rejects_unsafe_enums(self):
        base = {"status": "TIMED_OUT", "child_exit": "NOT_VERIFIED", "error": "NONE"}
        self.assertTrue(spawn.validate(base))
        self.assertFalse(spawn.validate(dict(base, child_exit="ZERO")))
        self.assertFalse(spawn.validate(dict(base, status="C:\\PRIVATE")))
        self.assertFalse(spawn.validate(dict(base, error="INVALID_PRIVATE_PATH")))


if __name__ == "__main__":
    unittest.main()
