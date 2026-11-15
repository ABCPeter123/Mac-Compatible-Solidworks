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
                             "family": "DLL_BINARY", "stage": "NOT_OBSERVED"})
        self.assertTrue(table.validate(r))
        absent = table.parse(b"SWCOMPAT_CA_TABLE_STATUS=ACTION_ABSENT\n"
                             b"SWCOMPAT_CA_TABLE_TYPE=0\n", 0)
        self.assertEqual(absent["status"], "ACTION_ABSENT")
        self.assertTrue(table.validate(absent))
        self.assertEqual(table.parse(found + b"SWCOMPAT_CA_TABLE_NAME=PRIVATE\n", 0)["status"],
                         "MALFORMED")
        self.assertEqual(table.parse(found + found, 0)["status"], "MALFORMED")
        self.assertEqual(table.parse(found, 7)["status"], "BAD_EXIT")
        stopped = table.parse(b"SWCOMPAT_CA_TABLE_STAGE=ENTRY\n"
                              b"SWCOMPAT_CA_TABLE_STAGE=INPUT_OK\n", 1)
        self.assertEqual(stopped["status"], "BAD_EXIT")
        self.assertEqual(stopped["stage"], "INPUT_OK")
        self.assertTrue(table.validate(stopped))
        dll_missing = table.parse(
            b"SWCOMPAT_CA_TABLE_STAGE=ENTRY\n"
            b"SWCOMPAT_CA_TABLE_STAGE=INPUT_OK\n"
            b"SWCOMPAT_CA_TABLE_STATUS=MSI_DLL_UNAVAILABLE\n"
            b"SWCOMPAT_CA_TABLE_TYPE=0\n", 0)
        self.assertEqual(dll_missing["status"], "MSI_DLL_UNAVAILABLE")
        self.assertEqual(dll_missing["stage"], "INPUT_OK")
        missing_input = table.parse(
            b"SWCOMPAT_CA_TABLE_STAGE=ENTRY\n"
            b"SWCOMPAT_CA_TABLE_STATUS=INPUT_UNAVAILABLE\n"
            b"SWCOMPAT_CA_TABLE_TYPE=0\n", 0)
        self.assertTrue(table.validate(missing_input))
        self.assertEqual(missing_input["status"], "INPUT_UNAVAILABLE")

        self.assertTrue(table.validate(dll_missing))
        selftest = table.parse(
            b"SWCOMPAT_CA_TABLE_STAGE=ENTRY\n"
            b"SWCOMPAT_CA_TABLE_STAGE=SELFTEST\n"
            b"SWCOMPAT_CA_TABLE_STATUS=SELFTEST_OK\n"
            b"SWCOMPAT_CA_TABLE_TYPE=0\n", 0)
        self.assertTrue(table.validate(selftest))
        self.assertEqual(selftest["status"], "SELFTEST_OK")
        self.assertEqual(selftest["stage"], "SELFTEST")

        self.assertFalse(table.validate(dict(stopped, stage="PRIVATE_PATH")))

        self.assertEqual(table.parse(found.replace(b"3073", b"999999"), 0)["status"],
                         "MALFORMED")
        self.assertFalse(table.validate(dict(r, family="WORKING_NETFX")))
        self.assertFalse(table.validate(dict(r, raw_action="PRIVATE")))

    @unittest.skipIf(os.name == "nt", "Wine-only temporary status file")
    def test_fixed_marker_file_overrides_missing_wine_console(self):
        with TemporaryDirectory() as td:
            root = Path(td)
            probe = root / "msi_custom_action_table_probe.exe"
            probe.write_bytes(b"fixture")
            msi = root / "control.msi"
            msi.write_bytes(b"fixture")
            wine = root / "wine"
            wine.write_bytes(b"fixture")
            completed = mock.Mock(returncode=0, stdout=b"")
            report_path = root / "drive_c" / "windows" / "temp" / "swcompat_ca_table_probe.status"

            def original_control(*_args, **_kwargs):
                secret_file = report_path.parent / "swcompat_ca_action_private.input"
                self.assertEqual(secret_file.read_bytes(), b"ServiceTypeControlSentinel")
                self.assertEqual(secret_file.stat().st_mode & 0o777, 0o600)
                report_path.write_bytes(
                    b"SWCOMPAT_CA_TABLE_STAGE=ENTRY\n"
                    b"SWCOMPAT_CA_TABLE_STAGE=INPUT_OK\n"
                    b"SWCOMPAT_CA_TABLE_STATUS=ACTION_FOUND\n"
                    b"SWCOMPAT_CA_TABLE_TYPE=3073\n")
                return completed

            with (
                mock.patch.object(table, "validate_prefix"),
                mock.patch.object(table, "windows_media_path", return_value="Z:\\control.msi"),
                mock.patch.object(table.subprocess, "run", side_effect=original_control),
            ):
                report = table.inspect(wine, root, probe, msi)
            self.assertTrue(table.validate(report))
            self.assertEqual(report["status"], "ACTION_FOUND")
            self.assertEqual(report["stage"], "INPUT_OK")
            self.assertEqual(report["family"], "DLL_BINARY")
            self.assertFalse(report_path.exists())

    def test_full_nine_stage_successful_msi_query_not_false_malformed(self):
        stages = [
            "ENTRY", "INPUT_OK", "MSI_DLL_LOADED", "MSI_EXPORTS_READY",
            "DATABASE_OPEN", "VIEW_OPEN", "PARAMETER_SET",
            "VIEW_EXECUTED", "ROW_FETCHED",
        ]
        raw = b"".join(
            f"SWCOMPAT_CA_TABLE_STAGE={stage}\r\n".encode("ascii")
            for stage in stages
        ) + (b"SWCOMPAT_CA_TABLE_STATUS=ACTION_FOUND\r\n"
             b"SWCOMPAT_CA_TABLE_TYPE=3073\r\n")
        report = table.parse(raw, 0)
        self.assertTrue(table.validate(report))
        self.assertEqual(report, {
            "status": "ACTION_FOUND", "base_type": 1,
            "family": "DLL_BINARY", "stage": "ROW_FETCHED",
        })
        doubled = raw.replace(
            b"SWCOMPAT_CA_TABLE_STAGE=VIEW_OPEN\r\n",
            b"SWCOMPAT_CA_TABLE_STAGE=VIEW_OPEN\r\n" * 2,
        )
        self.assertEqual(table.parse(doubled, 0)["status"], "MALFORMED")
        self.assertEqual(table.parse(doubled, 0)["stage"], "NOT_OBSERVED")

    def test_bootstrap_breadcrumb_parser_strict_and_erased(self):
        with TemporaryDirectory() as td:
            root = Path(td)
            file = root / "drive_c" / "swcompat_ca_bootstrap.status"
            file.parent.mkdir(parents=True)
            file.write_bytes(
                b"SWCOMPAT_CA_BOOT_ENTRY=YES\r\n"
                b"SWCOMPAT_CA_BOOT_ARGC=FOUR\r\n"
                b"SWCOMPAT_CA_BOOT_REPORT=OPEN\r\n"
            )
            with mock.patch.object(table, "validate_prefix"):
                result = table.read_bootstrap(root)
                self.assertEqual(result, {
                    "entry": "YES", "argc": "FOUR", "report": "OPEN",
                })
                self.assertFalse(file.exists())
                file.write_bytes(
                    b"SWCOMPAT_CA_BOOT_ENTRY=YES\r\n"
                    b"SWCOMPAT_CA_BOOT_ARGC=FOUR\r\n"
                    b"SWCOMPAT_CA_BOOT_REPORT=OPEN\r\n"
                    b"SWCOMPAT_CA_BOOT_PRIVATE_PATH=secret\r\n"
                )
                self.assertEqual(table.read_bootstrap(root)["entry"], "NOT_OBSERVED")
                self.assertFalse(file.exists())
                self.assertEqual(table.read_bootstrap(root)["entry"], "NOT_OBSERVED")

    @unittest.skipIf(os.name == "nt", "Wine-only selftest")
    def test_pre_msi_win32_selftest_cleans_fixed_wine_prefix_report(self):
        with TemporaryDirectory() as td:
            root = Path(td)
            wine = root / "wine"
            wine.write_bytes(b"fake")
            probe = root / "msi_custom_action_table_probe.exe"
            probe.write_bytes(b"fake")
            status_file = root / "drive_c" / "windows" / "temp" / "swcompat_ca_table_probe.status"

            def run_fixture(*_args, **_kwargs):
                status_file.write_bytes(
                    b"SWCOMPAT_CA_TABLE_STAGE=ENTRY\n"
                    b"SWCOMPAT_CA_TABLE_STAGE=SELFTEST\n"
                    b"SWCOMPAT_CA_TABLE_STATUS=SELFTEST_OK\n"
                    b"SWCOMPAT_CA_TABLE_TYPE=0\n"
                )
                return mock.Mock(stdout=b"", returncode=0)

            with (
                mock.patch.object(table, "validate_prefix"),
                mock.patch.object(table.subprocess, "run", side_effect=run_fixture) as runner,
            ):
                result = table.inspect_selftest(wine, root, probe)
            self.assertEqual(result["status"], "SELFTEST_OK")
            self.assertEqual(result["stage"], "SELFTEST")
            self.assertTrue(table.validate(result))
            self.assertFalse(status_file.exists())
            self.assertEqual(runner.call_args.args[0][1], str(probe.resolve()))
            self.assertNotIn("ServiceTypeControlSentinel", str(result))

    @unittest.skipIf(os.name == "nt", "Wine-only guarded wrapper")
    def test_metadata_probe_receives_action_through_stdin_only(self):
        with TemporaryDirectory() as td:
            root = Path(td)
            probe = root / "msi_custom_action_table_probe.exe"
            probe.write_bytes(b"fixture")
            wine = root / "wine"
            wine.write_bytes(b"fixture")
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
                # Intentionally pass a relative helper. The Wine subprocess
                # must receive an absolute executable even with cwd=prefix.
                relative_probe = Path(os.path.relpath(probe, Path.cwd()))
                relative_msi = Path(os.path.relpath(msi, Path.cwd()))
                r = table.inspect(wine, root, relative_probe, relative_msi)
            self.assertEqual(r["family"], "DLL_BINARY")
            args = run.call_args.args[0]
            self.assertEqual(args[1], str(probe.resolve()))
            self.assertTrue(Path(args[1]).is_absolute())
            self.assertNotIn("ServiceTypeControlSentinel", str(args))
            self.assertEqual(run.call_args.kwargs["stdin"], table.subprocess.DEVNULL)
            self.assertNotIn("input", run.call_args.kwargs)
            self.assertFalse((root / "drive_c" / "windows" / "temp" /
                              "swcompat_ca_action_private.input").exists())
            self.assertEqual(run.call_args.kwargs["stderr"], table.subprocess.DEVNULL)
            self.assertTrue(table.validate(r))
            with self.assertRaises(ValueError):
                table.inspect(wine, root, probe, msi, action="PRIVATE_SECRET")


if __name__ == "__main__":
    unittest.main()
