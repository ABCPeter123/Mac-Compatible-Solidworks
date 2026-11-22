"""Synthetic Wineboot registry-settle controls for a marked disposable prefix."""
import os
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory
import unittest
from unittest import mock

from scripts import netfx40_prefix_readiness as ready


class WinePrefixReadinessTests(unittest.TestCase):
    def make_fixture(self, root):
        wine = root / "wine"
        wine.write_text("self-authored test executable", encoding="ascii")
        wine.chmod(0o755)
        prefix = root / ready.PREFIX_NAME
        prefix.mkdir()
        (prefix / ready.SENTINEL).touch()
        return wine, prefix

    def test_completed_initialization_never_invokes_wine_again(self):
        with TemporaryDirectory() as td:
            root = Path(td)
            wine, prefix = self.make_fixture(root)
            (prefix / "drive_c").mkdir()
            (prefix / "system.reg").write_text("real Wine registry fixture")
            with mock.patch.dict(os.environ, {"RUNNER_TEMP": td}), \
                 mock.patch.object(ready.subprocess, "run") as run:
                report = ready.inspect(wine, prefix)
            run.assert_not_called()
            self.assertTrue(ready.valid(report))
            self.assertEqual(report["status"], "READY_IMMEDIATE")
            self.assertTrue(report["ready"])

    def test_registry_flush_after_init_is_not_a_fabricated_registry(self):
        with TemporaryDirectory() as td:
            root = Path(td)
            wine, prefix = self.make_fixture(root)
            (prefix / "drive_c").mkdir()
            sleeps = []
            def genuine_registry_flush(delay):
                sleeps.append(delay)
                (prefix / "system.reg").write_text("Wine created in background")
            with mock.patch.dict(os.environ, {"RUNNER_TEMP": td}), \
                 mock.patch.object(ready.time, "sleep", side_effect=genuine_registry_flush), \
                 mock.patch.object(ready.subprocess, "run") as run:
                report = ready.inspect(wine, prefix)
            self.assertEqual(sleeps, [2])
            run.assert_not_called()
            self.assertEqual(report["status"], "READY_AFTER_SETTLE")
            self.assertEqual(report["initial"], "MISSING_REGISTRY")
            self.assertEqual(report["update"], "NOT_RUN")
            self.assertTrue(ready.valid(report))

    def test_genuine_bounded_wineboot_update_creates_registry(self):
        with TemporaryDirectory() as td:
            root = Path(td)
            wine, prefix = self.make_fixture(root)
            (prefix / "drive_c").mkdir()
            calls = []
            def true_wineboot(cmd, **kwargs):
                calls.append(cmd)
                self.assertEqual(cmd, [str(wine), "wineboot.exe", "--update"])
                self.assertEqual(kwargs["cwd"], prefix)
                self.assertIs(kwargs["stdout"], subprocess.DEVNULL)
                self.assertIs(kwargs["stderr"], subprocess.DEVNULL)
                self.assertEqual(kwargs["timeout"], 90)
                self.assertEqual(kwargs["env"]["WINEPREFIX"], str(prefix))
                self.assertEqual(kwargs["env"]["WINEARCH"], "win64")
                self.assertEqual(kwargs["env"]["WINE_SKIP_MONO_INSTALLATION"], "1")
                self.assertEqual(kwargs["env"]["WINE_SKIP_GECKO_INSTALLATION"], "1")
                (prefix / "system.reg").write_text("Wineboot wrote the real registry")
                return mock.Mock(returncode=0)
            with mock.patch.dict(os.environ, {"RUNNER_TEMP": td}), \
                 mock.patch.object(ready.time, "sleep"), \
                 mock.patch.object(ready.subprocess, "run", side_effect=true_wineboot):
                report = ready.inspect(wine, prefix)
            self.assertEqual(len(calls), 1)
            self.assertEqual(report["status"], "READY_AFTER_WINEBOOT")
            self.assertEqual(report["initial"], "MISSING_REGISTRY")
            self.assertTrue(report["ready"])
            self.assertTrue(ready.valid(report))

    def test_nonzero_timeout_and_missing_files_fail_closed(self):
        for simulated, status, update in [
            (mock.Mock(returncode=1603), "WINEBOOT_FAILED", "EXIT_NONZERO"),
            (subprocess.TimeoutExpired("wineboot.exe", 90), "WINEBOOT_TIMEOUT", "TIMEOUT"),
            (OSError("file missing"), "WINEBOOT_START_FAILED", "START_FAILED"),
            (mock.Mock(returncode=0), "PREFIX_INCOMPLETE", "EXIT_ZERO"),
        ]:
            with self.subTest(status=status), TemporaryDirectory() as td:
                root = Path(td)
                wine, prefix = self.make_fixture(root)
                (prefix / "drive_c").mkdir()
                callback = ({"side_effect": simulated} if isinstance(simulated, Exception)
                            else {"return_value": simulated})
                with mock.patch.dict(os.environ, {"RUNNER_TEMP": td}), \
                     mock.patch.object(ready.time, "sleep"), \
                     mock.patch.object(ready.subprocess, "run", **callback):
                    report = ready.inspect(wine, prefix)
                self.assertEqual(report["status"], status)
                self.assertEqual(report["update"], update)
                self.assertEqual(report["final"], "MISSING_REGISTRY")
                self.assertFalse(report["ready"])
                self.assertTrue(ready.valid(report))
                self.assertFalse((prefix / "system.reg").exists())

    def test_invalid_prefixes_and_symlinked_registry_refused(self):
        with TemporaryDirectory() as td:
            root = Path(td)
            wine, prefix = self.make_fixture(root)
            (prefix / "drive_c").mkdir()
            with mock.patch.dict(os.environ, {"RUNNER_TEMP": td}):
                (prefix / "system.reg").symlink_to(root / "elsewhere")
                with self.assertRaises(ValueError):
                    ready.inspect(wine, prefix)
                (prefix / "system.reg").unlink()
                (prefix / ready.SENTINEL).unlink()
                with self.assertRaises(ValueError):
                    ready.inspect(wine, prefix)
                (prefix / ready.SENTINEL).touch()
                other = root / "different"
                other.mkdir()
                (other / ready.SENTINEL).touch()
                with self.assertRaises(ValueError):
                    ready.inspect(wine, other)

    def test_report_cannot_contain_paths_or_false_ready(self):
        self.assertFalse(ready.valid({**ready.blank("MISSING_REGISTRY", "PREFIX_INCOMPLETE",
                                                  "MISSING_REGISTRY", "EXIT_ZERO"),
                                     "ready": True}))
        self.assertFalse(ready.valid({**ready.blank("READY", "READY_IMMEDIATE",
                                                  "READY", "NOT_RUN"),
                                     "secret_registry_content": "C:\\\\private"}))
        self.assertNotIn('(prefix / "system.reg").write_text', Path(ready.__file__).read_text())
        self.assertNotIn("touch(", Path(ready.__file__).read_text())


if __name__ == "__main__":
    unittest.main()
