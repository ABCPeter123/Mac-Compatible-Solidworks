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

    @unittest.skipIf(os.name == "nt", "Wine-only private metadata query")
    def test_real_win32_child_query_uses_original_private_input_and_two_fixed_reports(self):
        with TemporaryDirectory() as td:
            root = Path(td)
            wine = root / "wine"
            wine.write_bytes(b"wine")
            launcher = root / "msi_action_spawn_probe.exe"
            launcher.write_bytes(b"launcher")
            probe = root / "msi_custom_action_table_probe.exe"
            probe.write_bytes(b"probe")
            msi = root / "swcompat_custom_action_type_control.msi"
            msi.write_bytes(b"source-authored")
            temp = root / "drive_c" / "windows" / "temp"
            input_file = temp / "swcompat_ca_action_private.input"
            spawn_file = temp / "swcompat_ca_spawn.status"
            table_file = temp / "swcompat_ca_table_probe.status"

            def invoke(*_args, **kwargs):
                self.assertEqual(input_file.read_bytes(), b"ServiceTypeControlSentinel")
                self.assertEqual(input_file.stat().st_mode & 0o777, 0o600)
                self.assertIs(kwargs["stdin"], spawn.subprocess.DEVNULL)
                spawn_file.write_bytes(
                    b"SWCOMPAT_SPAWN_STATUS=STARTED\n"
                    b"SWCOMPAT_SPAWN_CHILD_EXIT=ZERO\n"
                    b"SWCOMPAT_SPAWN_ERROR=NONE\n")
                table_file.write_bytes(
                    b"SWCOMPAT_CA_TABLE_STAGE=ENTRY\n"
                    b"SWCOMPAT_CA_TABLE_STAGE=ROW_FETCHED\n"
                    b"SWCOMPAT_CA_TABLE_STATUS=ACTION_FOUND\n"
                    b"SWCOMPAT_CA_TABLE_TYPE=3073\n")
                return mock.Mock(stdout=b"", returncode=0)

            with (
                mock.patch.object(spawn, "validate_prefix"),
                mock.patch.object(spawn, "windows_media_path",
                                  side_effect=[r"Z:\probe.exe", r"Z:\control.msi"]),
                mock.patch.object(spawn.subprocess, "run", side_effect=invoke) as ran,
            ):
                report = spawn.inspect_query(wine, root, launcher, probe, msi)
            self.assertEqual(report["spawn"]["status"], "STARTED")
            self.assertEqual(report["table"]["status"], "ACTION_FOUND")
            self.assertEqual(report["table"]["family"], "DLL_BINARY")
            self.assertEqual(report["table"]["stage"], "ROW_FETCHED")
            self.assertEqual(ran.call_args.args[0][1], str(launcher.resolve()))
            self.assertNotIn("ServiceTypeControlSentinel", str(report))
            for file in (input_file, spawn_file, table_file):
                self.assertFalse(file.exists())

    def test_rejects_unsafe_enums(self):
        base = {"status": "TIMED_OUT", "child_exit": "NOT_VERIFIED", "error": "NONE"}
        self.assertTrue(spawn.validate(base))
        self.assertFalse(spawn.validate(dict(base, child_exit="ZERO")))
        self.assertFalse(spawn.validate(dict(base, status="C:\\PRIVATE")))
        self.assertFalse(spawn.validate(dict(base, error="INVALID_PRIVATE_PATH")))


if __name__ == "__main__":
    unittest.main()
