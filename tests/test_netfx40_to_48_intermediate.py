"""Native .NET 4.8 intermediate never confuses a Winetricks marker with CLR."""
import os
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
        for file in (wine, winetricks, loader, managed):
            file.write_bytes(b"self-authored synthetic fixture")
            file.chmod(0o700)
        return wine, prefix, winetricks, loader, managed

    def _run_fixture(self, paths, winetricks="SUCCESS",
                     changed=True, release="NETFX48_RANGE"):
        hash_before = b"orig40"
        hash_after = b"orig48" if changed else hash_before
        before = {"CLR64": ("PE_AMD64", hash_before)}
        after = {"CLR64": ("PE_AMD64", hash_after)}
        def runner(args, env, cwd, timeout):
            self.assertEqual(args[1:], ["-q", "dotnet48"])
            self.assertEqual(env["WINEARCH"], "win64")
            self.assertEqual(env["WINEDEBUG"], "-all")
            self.assertNotIn("WINEDLLOVERRIDES", env)
            return winetricks
        with (mock.patch.object(p, "validate_prefix"),
              mock.patch.object(p, "validate_native40", return_value=True),
              mock.patch.object(p, "snapshot", side_effect=[before, after]),
              mock.patch.object(p, "load_clr", return_value="LOADED"),
              mock.patch.object(p, "probe", return_value={"managed": "PASS"}),
              mock.patch.object(p, "_set_winver", return_value="APPLIED") as profile,
              mock.patch.object(p, "_run", side_effect=runner),
              mock.patch.object(p, "wineboot_restart", return_value="COMPLETED"),
              mock.patch.object(p, "_release", return_value=release)):
            outcome = p.inspect(*paths, {"persistent_native_managed": True})
        self.assertTrue(p.validate(outcome))
        self.assertEqual([x.args[3] for x in profile.call_args_list],
                         ["win7", "win10"])
        self.assertFalse(outcome["framework481_confirmed"])
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

    def test_invalid_privilege_and_explicit_profile_constraints(self):
        env = {"WINEARCH": "win64"}
        with self.assertRaises(ValueError):
            p._set_winver(Path("/wine"), Path("/tmp/prefix"), env, "winxp")
        self.assertFalse(p.validate(dict(p.blank(), native48_candidate=True)))


if __name__ == "__main__":
    unittest.main()
