"""Synthetic finite-only Windows Service Control Manager API probe tests."""
from pathlib import Path
import os
import subprocess
import tempfile
import unittest
from unittest import mock

from scripts import netfx48_scm_service_probe as scm


def packet(*, status="COMPLETE", trusted="ABSENT", msi="PRESENT",
           update="PRESENT", bits="PRESENT",
           opt64="ABSENT", opt32="ABSENT") -> bytes:
    return ("\n".join([
        "SWCOMPAT_SCM_API_SCHEMA=1",
        "SWCOMPAT_SCM_API_STATUS=" + status,
        "SWCOMPAT_SCM_API_TRUSTEDINSTALLER=" + trusted,
        "SWCOMPAT_SCM_API_MSISERVER=" + msi,
        "SWCOMPAT_SCM_API_WUAUSERV=" + update,
        "SWCOMPAT_SCM_API_BITS=" + bits,
        "SWCOMPAT_SCM_API_CLR_OPTIMIZATION_64=" + opt64,
        "SWCOMPAT_SCM_API_CLR_OPTIMIZATION_32=" + opt32,
    ]) + "\n").encode("ascii")


class NativeSCMProbeTests(unittest.TestCase):
    def test_native_win32_missing_trustedinstaller_distinguished_from_msi(self):
        r = scm.parse(packet(), 0)
        self.assertTrue(scm.valid(r))
        self.assertEqual(r["status"], "COMPLETE")
        self.assertEqual(r["services"]["TRUSTEDINSTALLER"], "ABSENT")
        self.assertEqual(r["services"]["MSISERVER"], "PRESENT")
        self.assertEqual(r["services"]["CLR_OPTIMIZATION_64"], "ABSENT")
        self.assertEqual(r["services"]["CLR_OPTIMIZATION_32"], "ABSENT")
        self.assertNotIn("service path", str(r))
        denied = scm.parse(packet(trusted="ACCESS_DENIED"), 0)
        self.assertEqual(denied["services"]["TRUSTEDINSTALLER"], "ACCESS_DENIED")
        self.assertNotEqual(denied, r)

    def test_exact_schema_and_private_text_fail_closed(self):
        variants = (
            (packet() + b"PRIVATE=C:\\Users\\secret\n", "UNEXPECTED_TEXT"),
            (packet() + packet(), "INVALID_FIELD"),
            (packet().replace(b"SCHEMA=1", b"SCHEMA=2"), "MALFORMED"),
            (packet().replace(b"TRUSTEDINSTALLER=", b"TRUSTEDINSTALLER=PRIVATE"),
             "MALFORMED"),
            (packet().replace(b"MSISERVER=", b"OTHERSERVICE="), "INVALID_FIELD"),
            (packet().replace(b"SWCOMPAT_SCM_API_BITS=PRESENT\n", b""),
             "INCOMPLETE_FIELDS"),
            (packet().replace(b"SWCOMPAT_SCM_API_CLR_OPTIMIZATION_64=ABSENT\n", b""),
             "INCOMPLETE_FIELDS"),
            (packet() + b"\x00", "MALFORMED"),
            (b"\xff" + packet(), "NONASCII_OUTPUT"),
        )
        for value, expected in variants:
            with self.subTest(category=expected, value=value[:50]):
                self.assertEqual(scm.parse(value, 0), scm.blank(expected))
        self.assertEqual(scm.parse(packet(), 5), scm.blank("NONZERO_WITH_REPORT"))
        self.assertEqual(scm.parse(b"", 5), scm.blank("NONZERO_WITHOUT_REPORT"))
        self.assertEqual(scm.parse(b"WINE FAILED", 53),
                         scm.blank("NONZERO_WITHOUT_REPORT"))
        self.assertEqual(scm.parse(b"", 0), scm.blank("EMPTY_OUTPUT"))
        self.assertEqual(scm.parse(packet() + b"x" * 513, 0),
                         scm.blank("OVERSIZED_OUTPUT"))
        self.assertFalse(scm.valid(dict(scm.blank(), original_log="secret")))
        self.assertFalse(scm.valid(dict(scm.blank(), services={
            **scm.blank()["services"], "TRUSTEDINSTALLER": "private path"})))

    def test_finite_failure_categories_never_invent_service_presence(self):
        for status in ("NONZERO_EXIT", "EMPTY_OUTPUT", "OVERSIZED_OUTPUT",
                       "MALFORMED", "TIMEOUT", "PROCESS_FAILED", "NONASCII_OUTPUT",
                       "UNEXPECTED_TEXT", "INVALID_FIELD", "INCOMPLETE_FIELDS",
                       "NONZERO_WITH_REPORT", "NONZERO_WITHOUT_REPORT"):
            with self.subTest(status=status):
                outcome = scm.blank(status)
                self.assertTrue(scm.valid(outcome))
                self.assertTrue(all(v == "NOT_RUN"
                                    for v in outcome["services"].values()))
                modified = dict(outcome, services={**outcome["services"],
                                                  "TRUSTEDINSTALLER": "ABSENT"})
                self.assertFalse(scm.valid(modified))

    def test_unavailable_manager_never_invents_present(self):
        unavailable = scm.parse(packet(
            status="UNAVAILABLE", trusted="UNKNOWN", msi="UNKNOWN",
            update="UNKNOWN", bits="UNKNOWN",
            opt64="UNKNOWN", opt32="UNKNOWN"), 0)
        self.assertTrue(scm.valid(unavailable))
        self.assertEqual(unavailable["status"], "UNAVAILABLE")
        self.assertFalse(scm.valid(dict(
            unavailable, services={**unavailable["services"],
                                   "TRUSTEDINSTALLER": "PRESENT"})))

    def test_private_runner_invokes_only_self_authored_probe(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            wine = root / "wine"
            wine.write_bytes(b"wine")
            prefix = root / "prefix"
            prefix.mkdir()
            fixture = root / "netfx48_scm_service_probe.exe"
            fixture.write_bytes(b"fixture")

            def execute(args, **kwargs):
                self.assertEqual(args, [str(wine.resolve()), str(fixture.resolve())])
                self.assertEqual(kwargs["env"]["WINEPREFIX"], str(prefix))
                self.assertEqual(kwargs["env"]["WINEDEBUG"], "-all")
                self.assertEqual(kwargs["env"]["WINEARCH"], "win64")
                self.assertEqual(kwargs["timeout"], 20)
                self.assertNotIn("WINEDLLOVERRIDES", kwargs["env"])
                self.assertEqual(kwargs["stdin"], subprocess.DEVNULL)
                kwargs["stdout"].write(packet())
                return mock.Mock(returncode=0)

            with mock.patch.object(scm, "validate_prefix"), \
                 mock.patch.object(scm.subprocess, "run", side_effect=execute), \
                 mock.patch.dict(scm.os.environ, {"WINEDLLOVERRIDES": "mscoree=b"}):
                result = scm.measure(wine, prefix, fixture)
            self.assertEqual(result["services"]["TRUSTEDINSTALLER"], "ABSENT")
            self.assertTrue(scm.valid(result))
            fixture.rename(root / "user-binary.exe")
            with mock.patch.object(scm, "validate_prefix"), \
                 mock.patch.object(scm.subprocess, "run") as run:
                with self.assertRaises(ValueError):
                    scm.measure(wine, prefix, root / "user-binary.exe")
                run.assert_not_called()

    def test_relative_ci_fixture_is_absolute_when_wine_changes_cwd(self):
        # GitHub Actions passes 'build/netfx48_scm_service_probe.exe'.
        # Using cwd='build' without resolving argv[1] misaddresses the exe.
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            build = root / "build"
            build.mkdir()
            wine = root / "wine"
            wine.write_bytes(b"wine")
            prefix = root / "prefix"
            prefix.mkdir()
            fixture = build / "netfx48_scm_service_probe.exe"
            fixture.write_bytes(b"native Win32 fixture")
            relative = Path(os.path.relpath(fixture, Path.cwd()))
            self.assertFalse(relative.is_absolute())
            calls = []

            def execute(args, **kwargs):
                calls.append((args, kwargs))
                self.assertEqual(args[0], str(wine.resolve()))
                self.assertEqual(args[1], str(fixture.resolve()))
                self.assertEqual(kwargs["cwd"], build.resolve())
                self.assertNotIn("WINEDLLOVERRIDES", kwargs["env"])
                kwargs["stdout"].write(
                    scm.SELFTEST_MARKER if len(args) == 3 else packet())
                return mock.Mock(returncode=0)

            with mock.patch.object(scm, "validate_prefix"), \
                 mock.patch.object(scm.subprocess, "run", side_effect=execute):
                self.assertEqual(scm.selftest(wine, prefix, relative), "PASS")
                self.assertEqual(
                    scm.measure(wine, prefix, relative)["status"], "COMPLETE")
            self.assertEqual(len(calls), 2)

    def test_independent_selftest_has_no_service_claims(self):
        self.assertEqual(scm.parse_selftest(scm.SELFTEST_MARKER, 0), "PASS")
        self.assertEqual(scm.parse_selftest(
            scm.SELFTEST_MARKER[:-1] + b"\r\n", 0), "PASS")
        self.assertEqual(scm.parse_selftest(
            scm.SELFTEST_MARKER + b"PRIVATE", 0), "UNEXPECTED_OUTPUT")
        self.assertEqual(scm.parse_selftest(b"", 0), "EMPTY_OUTPUT")
        self.assertEqual(scm.parse_selftest(b"PRIVATE", 0), "UNEXPECTED_OUTPUT")
        self.assertEqual(scm.parse_selftest(scm.SELFTEST_MARKER, 53), "NONZERO_EXIT")

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            wine = root / "wine"
            wine.write_bytes(b"wine")
            prefix = root / "prefix"
            prefix.mkdir()
            fixture = root / "netfx48_scm_service_probe.exe"
            fixture.write_bytes(b"fixture")

            def execute(args, **kwargs):
                self.assertEqual(args, [str(wine.resolve()), str(fixture.resolve()), "--selftest"])
                self.assertEqual(kwargs["env"]["WINEPREFIX"], str(prefix))
                self.assertNotIn("WINEDLLOVERRIDES", kwargs["env"])
                self.assertIs(kwargs["stdin"], subprocess.DEVNULL)
                self.assertEqual(kwargs["timeout"], 20)
                kwargs["stdout"].write(scm.SELFTEST_MARKER)
                return mock.Mock(returncode=0)

            with mock.patch.object(scm, "validate_prefix"), \
                 mock.patch.object(scm.subprocess, "run", side_effect=execute), \
                 mock.patch.dict(scm.os.environ, {"WINEDLLOVERRIDES": "mscoree=b"}):
                self.assertEqual(scm.selftest(wine, prefix, fixture), "PASS")

    def test_independent_selftest_never_fabricates_success(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            wine = root / "wine"
            wine.write_bytes(b"wine")
            prefix = root / "prefix"
            prefix.mkdir()
            fixture = root / "netfx48_scm_service_probe.exe"
            fixture.write_bytes(b"fixture")
            with mock.patch.object(scm, "validate_prefix"), \
                 mock.patch.object(scm.subprocess, "run",
                                   side_effect=subprocess.TimeoutExpired("wine", 20)):
                self.assertEqual(scm.selftest(wine, prefix, fixture), "TIMEOUT")
            fixture.rename(root / "renamed.exe")
            with mock.patch.object(scm, "validate_prefix"), \
                 mock.patch.object(scm.subprocess, "run") as execute:
                with self.assertRaises(ValueError):
                    scm.selftest(wine, prefix, root / "renamed.exe")
                execute.assert_not_called()

    def test_timeout_returns_unknown_not_missing_service(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            wine = root / "wine"
            wine.write_bytes(b"w")
            prefix = root / "prefix"
            prefix.mkdir()
            fixture = root / "netfx48_scm_service_probe.exe"
            fixture.write_bytes(b"e")
            with mock.patch.object(scm, "validate_prefix"), \
                 mock.patch.object(scm.subprocess, "run",
                                   side_effect=subprocess.TimeoutExpired("wine", 20)):
                r = scm.measure(wine, prefix, fixture)
            self.assertEqual(r, scm.blank("TIMEOUT"))
            self.assertTrue(scm.valid(r))


if __name__ == "__main__":
    unittest.main()
