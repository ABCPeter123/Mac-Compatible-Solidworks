"""Synthetic tests for *actual* local interactive original-media Wine installation.

No SOLIDWORKS binaries, installers, license numbers, or proprietary payloads.
"""
import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from swcompat.native_install import COMPONENTS, scan_media, install_local, initialize_prefix
from swcompat.cli import main


class NativeMediaTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.media = self.root / "media"
        self.media.mkdir()
        self.wine = self.root / "wine"
        self.wine.write_text("#!/bin/sh\nexit 0\n")
        self.wine.chmod(0o755)
        self.prefix = self.root / "prefix"
        (self.prefix / "drive_c").mkdir(parents=True)
        (self.prefix / "system.reg").write_text("Wine registry")
        self.logs = self.root / "private-logs"

    def add_full_media(self):
        (self.media / "setup.exe").write_bytes(b"synthetic setup only")
        for _, filename in COMPONENTS:
            target = self.media / "prerequisites" / filename
            target.parent.mkdir(exist_ok=True)
            target.write_bytes(b"synthetic prerequisite only")

    def test_audit_reports_no_installed_runtime_claims(self):
        self.add_full_media()
        inv = scan_media(self.media)
        report = inv.public_report()
        self.assertEqual(report["launcher"], "INSTALLATION_MEDIA_CANDIDATE")
        self.assertTrue(report["prerequisite_files_complete"])
        self.assertEqual(report["installed_runtime_functionality"], "NOT_VERIFIED")
        self.assertEqual(report["full_solidworks_installation"], "NOT_VERIFIED")
        self.assertNotIn(str(self.root), json.dumps(report))
        self.assertEqual(len(report["prerequisite_media"]), 7)

    def test_bootstrapper_only_needs_explicit_permission(self):
        bootstrap = self.media / "SolidworksSetup.exe"
        bootstrap.write_bytes(b"synthetic")
        self.assertEqual(scan_media(bootstrap).launcher_kind, "BOOTSTRAPPER_ONLY")
        with self.assertRaisesRegex(ValueError, "Bootstrapper-only"):
            install_local(self.wine, self.prefix, self.logs, bootstrap)
        self.assertFalse(self.logs.exists())

    def test_missing_prereqs_fails_before_running_installer(self):
        (self.media / "setup.exe").write_bytes(b"synthetic")
        with self.assertRaisesRegex(ValueError, "visual_cpp_x64"):
            install_local(self.wine, self.prefix, self.logs, self.media, install_prerequisites=True)
        self.assertFalse(self.logs.exists())

    def test_duplicate_component_not_used_arbitrarily(self):
        self.add_full_media()
        duplicate = self.media / "second" / "vc_redist.x64.exe"
        duplicate.parent.mkdir()
        duplicate.write_bytes(b"synthetic duplicate")
        inv = scan_media(self.media)
        self.assertEqual(inv.public_report()["prerequisite_media"]["visual_cpp_x64"], "AMBIGUOUS")
        with self.assertRaisesRegex(ValueError, "visual_cpp_x64"):
            install_local(self.wine, self.prefix, self.logs, self.media, install_prerequisites=True)

    def test_reject_symlink_media_and_skip_linked_payload(self):
        self.add_full_media()
        symlink = self.root / "linked"
        try:
            symlink.symlink_to(self.media, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("Symlink not available")
        with self.assertRaises(ValueError):
            scan_media(symlink)
        original = self.media / "prerequisites" / "vc_redist.x64.exe"
        original.unlink()
        original.symlink_to(self.root / "wine")
        self.assertEqual(scan_media(self.media).public_report()["prerequisite_media"]["visual_cpp_x64"], "MISSING")

    def test_interactive_execution_order_cwd_and_no_timeout(self):
        self.add_full_media()
        runner = mock.Mock(return_value=0)
        with contextlib.redirect_stdout(io.StringIO()):
            rc = install_local(self.wine, self.prefix, self.logs, self.media,
                               install_prerequisites=True, runner=runner)
        self.assertEqual(rc, 0)
        self.assertEqual(runner.call_count, len(COMPONENTS) + 1)
        self.assertEqual([c.kwargs["label"] for c in runner.call_args_list],
                         [name for name, _ in COMPONENTS] + ["solidworks-setup"])
        for call in runner.call_args_list:
            self.assertEqual(call.kwargs["cwd"], Path(call.args[0][-1]).parent)
            self.assertNotIn("timeout", call.kwargs)
        self.assertEqual([Path(p).resolve() for p in runner.call_args.args[0]],
                         [self.wine.resolve(), (self.media / "setup.exe").resolve()])

    def test_msi_invoked_with_msiexec_not_as_plain_exe(self):
        self.add_full_media()
        runner = mock.Mock(return_value=0)
        with contextlib.redirect_stdout(io.StringIO()):
            install_local(self.wine, self.prefix, self.logs, self.media,
                          install_prerequisites=True, runner=runner)
        msi_calls = [x for x in runner.call_args_list if x.kwargs["label"] in
                     {"visual_basic", "visual_basic_en", "swcef"}]
        self.assertEqual(len(msi_calls), 3)
        for call in msi_calls:
            self.assertEqual(call.args[0][1:3], ["msiexec.exe", "/i"])

    def test_failed_dependency_prevents_solidworks_launch(self):
        self.add_full_media()
        runner = mock.Mock(side_effect=[0, 1603])
        with contextlib.redirect_stdout(io.StringIO()):
            code = install_local(self.wine, self.prefix, self.logs, self.media,
                                 install_prerequisites=True, runner=runner)
        self.assertEqual(code, 1)
        self.assertEqual(runner.call_count, 2)

    def test_existing_prefix_never_reinitialized(self):
        with mock.patch("swcompat.native_install.run_interactive") as called:
            self.assertEqual(initialize_prefix(self.wine, self.prefix, self.logs), "EXISTING")
            called.assert_not_called()

    def test_incomplete_existing_prefix_refused(self):
        (self.prefix / "system.reg").unlink()
        with self.assertRaisesRegex(ValueError, "initialized"):
            initialize_prefix(self.wine, self.prefix, self.logs)

    def test_audit_command_does_not_need_wine(self):
        self.add_full_media()
        with mock.patch("swcompat.cli.find_wine", return_value=None):
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                rc = main(["native-audit", str(self.media)])
        self.assertEqual(rc, 0)
        self.assertTrue(json.loads(stdout.getvalue())["prerequisite_files_complete"])

    def test_native_install_cli_with_existing_wine_prefix(self):
        self.add_full_media()
        with mock.patch("swcompat.native_install.run_interactive", return_value=0), \
             mock.patch("swcompat.cli.find_wine", return_value=self.wine):
            # The default local installer invokes the interactive original once.
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                rc = main(["--prefix", str(self.prefix), "--logs-dir", str(self.logs),
                           "native-install", str(self.media)])
        self.assertEqual(rc, 0)
        self.assertIn("NOT_VERIFIED", output.getvalue())

    def test_reject_unrecognized_single_file(self):
        path = self.media / "arbitrary.exe"
        path.write_bytes(b"fake")
        with self.assertRaises(ValueError):
            scan_media(path)


if __name__ == "__main__":
    unittest.main()
