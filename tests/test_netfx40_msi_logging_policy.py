"""Reversible, opt-in Windows Installer verbose logging policy safety tests."""
from pathlib import Path
from tempfile import TemporaryDirectory
import os
import unittest
from unittest import mock

from scripts import netfx40_msi_logging_policy as policy
from scripts import netfx40_msi_evidence as evidence
from scripts import netfx40_legacy as legacy


class VerboseMsiLoggingTests(unittest.TestCase):
    def test_command_line_forwards_verbose_flag_to_install(self):
        # The initial CI run silently ignored the flag in main(), causing
        # the genuine setup to run without the requested logging policy.
        with TemporaryDirectory() as td:
            root = Path(td)
            dummy = root / "fixture.exe"
            fields = ("status", "winver", "mono", "selftest", "installer_status",
                      "installer_exit", "installer_child_seen",
                      "installer_child_lifecycle", "installer_child_exit",
                      "reboot", "clr64_before", "clr64_after", "clr32_after",
                      "mscorlib64_after", "native_loader", "runtime_family",
                      "managed_functionality", "candidate_native40")
            report = {field: "NOT_RUN" for field in fields}
            report.update({
                "inner_msi": evidence.empty(),
                "wine_msi_errors": __import__(
                    "scripts.netfx40_wine_msi_errors", fromlist=["empty"]).empty(),
                "msi_logging_policy": policy.blank(),
            })
            args = []
            for key in ("wine", "prefix", "installer", "launcher", "loader", "managed"):
                args += ["--" + key, str(dummy)]
            args += ["--output", str(root / "report.json"),
                     "--agree-disposable-prefix"]
            for enabled in (False, True):
                with self.subTest(enabled=enabled), (
                    mock.patch.object(legacy, "inspect", return_value=report) as inspect,
                    mock.patch.object(legacy, "validate", return_value=True),
                ):
                    rc = legacy.main(
                        args + (["--experiment-enable-verbose-msi"] if enabled else []))
                    self.assertEqual(rc, 0)
                    self.assertEqual(inspect.call_args.kwargs["enable_verbose_msi"],
                                     enabled)

    def test_policy_matches_microsoft_documented_value(self):
        self.assertEqual(policy.VALUE, "voicewarmupx")
        self.assertEqual(policy.KEY,
            r"HKLM\Software\Policies\Microsoft\Windows\Installer")

    @unittest.skipIf(os.name == "nt", "Never modify real native Windows registry")
    def test_apply_verify_restore_specific_value_only(self):
        with TemporaryDirectory() as td:
            prefix = Path(td)
            (prefix / "system.reg").touch()
            (prefix / ".swcompat-netfx481-disposable").touch()
            (prefix / "drive_c").mkdir()
            wine = prefix / "fake-wine"
            wine.write_bytes(b"x")
            wine.chmod(0o700)
            with mock.patch.object(policy, "_reg", side_effect=[
                (1,b""), (0,b""), (0,b"REG_SZ voicewarmupx"),
                (0,b""), (1,b"")
            ]) as run:
                action = policy.apply(wine, prefix)
                restoration = policy.restore(wine, prefix, action)
                self.assertEqual(action, "APPLIED")
                self.assertEqual(restoration, "REMOVED")
                self.assertTrue(policy.validate({
                    "activation": action, "restoration": restoration}))
                commands = [x.args[2][0] for x in run.call_args_list]
                self.assertEqual(commands, ["query", "add", "query", "delete", "query"])
                self.assertEqual(run.call_args_list[1].args[2][-1], "/f")
                self.assertEqual(run.call_args_list[3].args[2][-2:], ["Logging", "/f"])

    @unittest.skipIf(os.name == "nt", "Never modify real native Windows registry")
    def test_preexisting_value_is_not_modified_or_removed(self):
        with TemporaryDirectory() as td:
            prefix = Path(td)
            (prefix / "system.reg").touch()
            (prefix / ".swcompat-netfx481-disposable").touch()
            (prefix / "drive_c").mkdir()
            wine = prefix / "fake-wine"
            wine.write_bytes(b"x")
            with mock.patch.object(policy, "_reg", return_value=(0,b"other policy")) as run:
                action = policy.apply(wine, prefix)
                self.assertEqual(action, "PREEXISTING")
                self.assertEqual(policy.restore(wine, prefix, action), "NOT_REQUIRED")
                self.assertEqual(run.call_count, 1)

    def test_never_reach_unmarked_prefix(self):
        with TemporaryDirectory() as td:
            with self.assertRaises(ValueError):
                policy.apply(Path(td) / "wine", Path(td))

    def test_status_never_claims_success_without_cleanup(self):
        self.assertFalse(policy.validate({
            "activation": "APPLIED", "restoration": "NOT_REQUIRED"}))
        self.assertFalse(policy.validate({
            "activation": "PREEXISTING", "restoration": "REMOVED"}))
        self.assertFalse(policy.validate({
            "activation": "FAKE_SUCCESS", "restoration": "REMOVED"}))
        self.assertFalse(policy.validate({
            "activation": "APPLIED", "restoration": "REMOVED", "raw": "private"}))

    def test_verbose_msi_temp_log_first_failed_action(self):
        with TemporaryDirectory() as td:
            prefix = Path(td)
            (prefix / "system.reg").touch()
            (prefix / ".swcompat-netfx481-disposable").touch()
            temp = prefix / "drive_c" / "users" / "runner" / "AppData" / "Local" / "Temp"
            temp.mkdir(parents=True)
            msi = temp / "MSI123a4.LOG"
            msi.write_text(
                "Action ended 12:12:15: CA_RegisterCLR. Return value 3.\n"
                "Action ended 12:12:16: InstallFinalize. Return value 3.\n"
                "Error 1723. Private path C:\\Fake\\sensitive\n"
            )
            data = evidence.scan(prefix)
            self.assertTrue(evidence.validate(data))
            self.assertEqual(data["primary_source"], "VERBOSE_MSI")
            self.assertEqual(data["first_failed_action_class"], "CUSTOM_ACTION")
            self.assertEqual(data["msi_result"], "FAILURE_MARKER")
            self.assertNotIn(str(prefix), str(data))
            self.assertNotIn("RegisterCLR", str(data))

    def test_bounded_tail_of_large_log(self):
        with TemporaryDirectory() as td:
            prefix = Path(td)
            (prefix / "system.reg").touch()
            (prefix / ".swcompat-netfx481-disposable").touch()
            temp = prefix / "drive_c" / "windows" / "Temp"
            temp.mkdir(parents=True)
            with (temp / "MSI7aa1.log").open("wb") as f:
                f.write(b"x" * (evidence.MAX_FILE_BYTES + 128))
                f.write(b"\nAction ended 11:23:08: InstallServices. Return value 3.\n")
            data = evidence.scan(prefix)
            self.assertTrue(evidence.validate(data))
            self.assertEqual(data["status"], "PARTIAL_SCAN")
            self.assertEqual(data["primary_source"], "VERBOSE_MSI")
            self.assertEqual(data["first_failed_action_class"], "SERVICE")


if __name__ == "__main__":
    unittest.main()
