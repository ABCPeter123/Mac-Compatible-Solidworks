"""MSI CustomAction table read-only native Windows probe strict schema tests."""
import io
from pathlib import Path
from tempfile import TemporaryDirectory
import os
import unittest
from unittest import mock

from scripts import msi_custom_action_table_type as table


class OriginalMsiActionTableTests(unittest.TestCase):
    def test_fixed_parser_and_untrusted_marker_rejection(self):
        found = b"SWCOMPAT_CA_TABLE_STATUS=ACTION_FOUND\nSWCOMPAT_CA_TABLE_TYPE=3073\n"
        r = table.parse(found, 0)
        self.assertEqual(r, {"status": "ACTION_FOUND", "base_type": 1,
                             "family": "DLL_BINARY"})
        self.assertTrue(table.validate(r))
        absent = table.parse(b"SWCOMPAT_CA_TABLE_STATUS=ACTION_ABSENT\n"
                             b"SWCOMPAT_CA_TABLE_TYPE=0\n", 0)
        self.assertEqual(absent["status"], "ACTION_ABSENT")
        self.assertTrue(table.validate(absent))
        self.assertEqual(table.parse(found + b"SWCOMPAT_CA_TABLE_NAME=PRIVATE\n", 0)["status"],
                         "MALFORMED")
        self.assertEqual(table.parse(found + found, 0)["status"], "MALFORMED")
        self.assertEqual(table.parse(found, 7)["status"], "BAD_EXIT")
        self.assertEqual(table.parse(found.replace(b"3073", b"999999"), 0)["status"],
                         "MALFORMED")
        self.assertFalse(table.validate(dict(r, family="WORKING_NETFX")))
        self.assertFalse(table.validate(dict(r, raw_action="PRIVATE")))

    @unittest.skipIf(os.name == "nt", "Wine-only guarded wrapper")
    def test_metadata_probe_receives_action_through_stdin_only(self):
        with TemporaryDirectory() as td:
            root = Path(td)
            probe = root / "msi_custom_action_table_probe.exe"
            probe.write_bytes(b"fixture")
            msi = root / "self-authored.msi"
            msi.write_bytes(b"fixture")
            completed = mock.Mock()
            completed.returncode = 0
            completed.stdout = (
                b"SWCOMPAT_CA_TABLE_STATUS=ACTION_FOUND\n"
                b"SWCOMPAT_CA_TABLE_TYPE=3073\n"
            )
            with (
                mock.patch.object(table, "validate_prefix"),
                mock.patch.object(table, "windows_media_path", return_value="Z:\\control.msi"),
                mock.patch.object(table.subprocess, "run", return_value=completed) as run,
            ):
                r = table.inspect(root / "wine", root, probe, msi)
            self.assertEqual(r["family"], "DLL_BINARY")
            args = run.call_args.args[0]
            self.assertNotIn("ServiceTypeControlSentinel", str(args))
            self.assertEqual(run.call_args.kwargs["input"], b"ServiceTypeControlSentinel")
            self.assertEqual(run.call_args.kwargs["stderr"], table.subprocess.DEVNULL)
            self.assertTrue(table.validate(r))
            with self.assertRaises(ValueError):
                table.inspect(root / "wine", root, probe, msi, action="PRIVATE_SECRET")


if __name__ == "__main__":
    unittest.main()
