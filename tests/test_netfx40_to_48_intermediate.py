"""Native .NET 4.8 intermediate never confuses a Winetricks marker with CLR."""
import os
import signal
import subprocess
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock
import unittest

from scripts import netfx40_to_48_intermediate as p


class Native40To48IntermediateTests(unittest.TestCase):
    def test_registry_release_strict_windows_output(self):
        self.assertEqual(p.parse_release(b" Release REG_DWORD 0x80ff4\r\n", 0),
                         "NETFX48_RANGE")
        self.assertEqual(p.parse_release(b" Release REG_DWORD 0x80eb1\n", 0),
                         "NETFX48_RANGE")
        self.assertEqual(p.parse_release(b" Release REG_DWORD 0x82348\n", 0),
                         "AT_LEAST_481")
        self.assertEqual(p.parse_release(b" Release REG_DWORD 0x1\n", 0),
                         "BELOW_48")
        self.assertEqual(p.parse_release(b" Release REG_DWORD 0x80be0\n", 0),
                         "BELOW_48")
        self.assertEqual(p.parse_release(b"", 1), "NOT_FOUND")
        self.assertEqual(p.parse_release(b"", 2), "UNAVAILABLE")
        self.assertEqual(p.parse_release(b"Release REG_DWORD 0x82660\n" * 2, 0),
                         "UNAVAILABLE")
        self.assertEqual(p.parse_release(b"PRIVATE REG_DWORD 0x80fff\n", 0),
                         "UNAVAILABLE")
        self.assertEqual(p.parse_release(b"x" * 5000, 0), "UNAVAILABLE")

    def _fixture(self, root):
        prefix = root / "prefix"
        prefix.mkdir()
        wine = root / "wine"
        winetricks = root / "winetricks"
        loader = root / "netfx481_clr_load.exe"
        managed = root / "netfx481_runtime_probe.exe"
        for file in (wine, root / "wineserver", winetricks, loader, managed):
            file.write_bytes(b"self-authored synthetic fixture")
            file.chmod(0o700)
        return wine, prefix, winetricks, loader, managed

    def _run_fixture(self, paths, winetricks="SUCCESS",
                     changed=True, release="NETFX48_RANGE",
                     progress="DOTNET48_VERB_SEEN"):
        hash_before = b"orig40"
        hash_after = b"orig48" if changed else hash_before
        before = {"CLR64": ("PE_AMD64", hash_before)}
        after = {"CLR64": ("PE_AMD64", hash_after)}
        def runner(args, env, cwd, timeout):
            self.assertEqual(args, ["bash", str(paths[2]), "-q", "dotnet48"])
            self.assertEqual(env["WINE"], str(paths[0]))
            self.assertEqual(env["WINE_BIN"], str(paths[0]))
            self.assertEqual(env["WINE_BINDIR"], str(paths[0].parent))
            self.assertEqual(env["WINESERVER"], str(paths[0].parent / "wineserver"))
            self.assertEqual(env["WINESERVER_BIN"], str(paths[0].parent / "wineserver"))
            self.assertEqual(env["WINEARCH"], "win64")
            self.assertEqual(env["WINEDEBUG"], "-all")
            self.assertNotIn("WINEDLLOVERRIDES", env)
            return winetricks, progress
        with (mock.patch.object(p, "validate_prefix"),
              mock.patch.object(p, "validate_native40", return_value=True),
              mock.patch.object(p, "snapshot", side_effect=[before, after]),
              mock.patch.object(p, "load_clr", return_value="LOADED"),
              mock.patch.object(p, "probe", return_value={"managed": "PASS"}),
              mock.patch.object(p, "_set_winver", return_value="APPLIED") as profile,
              mock.patch.object(p, "_run_winetricks", side_effect=runner),
              mock.patch.object(p, "wineboot_restart", return_value="COMPLETED"),
              mock.patch.object(p, "_release", return_value=release)):
            outcome = p.inspect(*paths, {"persistent_native_managed": True})
        self.assertTrue(p.validate(outcome))
        self.assertEqual([x.args[3] for x in profile.call_args_list],
                         ["win7", "win10"])
        self.assertFalse(outcome["framework481_confirmed"])
        self.assertEqual(outcome["verb_progress"], progress)
        self.assertEqual(outcome["solidworks_compatibility"], "NOT_DEMONSTRATED")
        return outcome

    @unittest.skipIf(os.name == "nt", "POSIX-only Wine wrapper")
    def test_true_requires_changed_native_clr_and_exact_48_release(self):
        with TemporaryDirectory() as td:
            paths = self._fixture(Path(td))
            result = self._run_fixture(paths)
            self.assertTrue(result["native48_candidate"])
            self.assertNotIn(td, str(result))
            for verb, changed, release in (
                ("EXIT_NONZERO", True, "NETFX48_RANGE"),
                ("SUCCESS", False, "NETFX48_RANGE"),
                ("SUCCESS", True, "BELOW_48"),
                ("SUCCESS", True, "AT_LEAST_481"),
            ):
                self.assertFalse(self._run_fixture(
                    paths, winetricks=verb, changed=changed,
                    release=release)["native48_candidate"])
            self.assertFalse(p.validate(dict(result, framework481_confirmed=True)))
            self.assertFalse(p.validate(dict(result, original_registry_text="PRIVATE")))
            self.assertFalse(p.validate(dict(result, native48_candidate=False)))

    @unittest.skipIf(os.name == "nt", "POSIX-only Wine wrapper")
    def test_existing_native_40_must_be_verified_before_any_action(self):
        with TemporaryDirectory() as td:
            paths = self._fixture(Path(td))
            with (mock.patch.object(p, "validate_prefix"),
                  mock.patch.object(p, "validate_native40", return_value=True),
                  mock.patch.object(p, "_run") as runner):
                result = p.inspect(*paths, {"persistent_native_managed": False})
            self.assertEqual(result, p.blank())
            runner.assert_not_called()


    def test_binary_identity_overrides_poisoned_inherited_environment(self):
        with TemporaryDirectory() as td:
            wine, prefix, *_ = self._fixture(Path(td))
            poisoned = {
                "WINE": "/tmp/foreign/wine", "WINE_BIN": "/tmp/foreign/wine",
                "WINESERVER": "/tmp/foreign/wineserver",
                "WINESERVER_BIN": "/tmp/foreign/wineserver",
                "WINE_BINDIR": "/tmp/foreign", "WINEDLLOVERRIDES": "mscoree=n",
            }
            with mock.patch.dict(os.environ, poisoned):
                env = p._env(wine, prefix)
            self.assertEqual(env["WINE_BIN"], str(wine))
            self.assertEqual(env["WINE_BINDIR"], str(wine.parent))
            self.assertEqual(env["WINESERVER_BIN"], str(wine.parent / "wineserver"))
            self.assertNotIn("WINEDLLOVERRIDES", env)
            (wine.parent / "wineserver").unlink()
            with mock.patch.dict(os.environ, poisoned):
                without_server = p._env(wine, prefix)
            self.assertNotIn("WINESERVER_BIN", without_server)
            self.assertNotIn("WINESERVER", without_server)

    def test_private_progress_never_contains_installer_output(self):
        self.assertEqual(p.classify_progress(b""), "NO_OUTPUT")
        self.assertEqual(p.classify_progress(b"Executing load_dotnet48\n"),
                         "DOTNET48_VERB_SEEN")
        self.assertEqual(p.classify_progress(
            b"Execute C:\\user\\private\\NDP48-x86-x64-AllOS-ENU.exe"),
            "DOTNET48_PACKAGE_MENTIONED")
        self.assertEqual(p.classify_progress(b"Starting Winetricks"),
                         "WINETRICKS_ACTIVE")
        self.assertEqual(p.classify_progress(b"x" * (p.MAX_PRIVATE_OUTPUT + 1)),
                         "OUTPUT_TOO_LARGE")
        self.assertNotIn("private", p.classify_progress(
            b"Execute C:\\user\\private\\NDP48-x86-x64-AllOS-ENU.exe"))

    @unittest.skipIf(os.name == "nt", "POSIX process group cleanup only")
    def test_winetricks_timeout_terminates_entire_process_group(self):
        with TemporaryDirectory() as td:
            command = ["/bin/sh", "-c", "sleep 30"]
            status, milestone = p._run_winetricks(
                command, os.environ.copy(), Path(td), timeout=1)
            self.assertEqual(status, "TIMED_OUT")
            self.assertEqual(milestone, "NO_OUTPUT")

    def test_group_cleanup_terminates_even_if_parent_exits_early(self):
        proc = mock.Mock()
        proc.pid = 56789
        proc.wait.return_value = 0
        with mock.patch.object(p.os, "killpg") as kill:
            p._terminate_group(proc)
        self.assertEqual(
            [call.args for call in kill.call_args_list],
            [(56789, signal.SIGTERM), (56789, signal.SIGKILL)])

    def test_progress_is_not_an_upgrade_success_signal(self):
        with TemporaryDirectory() as td:
            paths = self._fixture(Path(td))
            status = self._run_fixture(paths, winetricks="TIMED_OUT",
                                       changed=False, release="BELOW_48",
                                       progress="DOTNET48_PACKAGE_MENTIONED")
            self.assertFalse(status["native48_candidate"])
            self.assertTrue(p.validate(status))
            self.assertFalse(p.validate(dict(status, verb_progress="PRIVATE_LOG")))

    def test_invalid_privilege_and_explicit_profile_constraints(self):
        env = {"WINEARCH": "win64"}
        with self.assertRaises(ValueError):
            p._set_winver(Path("/wine"), Path("/tmp/prefix"), env, "winxp")
        self.assertFalse(p.validate(dict(p.blank(), native48_candidate=True)))


if __name__ == "__main__":
    unittest.main()
