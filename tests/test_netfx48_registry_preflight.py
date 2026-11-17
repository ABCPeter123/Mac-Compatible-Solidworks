"""No-media, no-Wine tests for .NET Release registry-view differential."""
from pathlib import Path
import os
import subprocess
import tempfile
import unittest
from unittest import mock

from scripts import netfx48_registry_preflight as r


class RegistryPreflightTests(unittest.TestCase):
    def test_exact_release_bands(self):
        for value, category in (
            ("0x60267", "OLDER_RELEASE"),
            ("0x80ea8", "NETFX48_RANGE"),
            ("0x82348", "AT_LEAST_481"),
            ("533320", "AT_LEAST_481"),
            ("0", "OLDER_RELEASE"),
        ):
            with self.subTest(value=value):
                raw = ("HKEY_LOCAL_MACHINE\\Software\\Microsoft\n"
                       "    Release    REG_DWORD    " + value + "\n").encode()
                self.assertEqual(r.parse(raw, 0), category)

    def test_legacy_version_labels_both_views(self):
        examples = (
            ("4.0.30319", "V4_0"), ("4.6.01590", "V4_1_TO_4_6"),
            ("4.7", "V4_7_PLUS"), ("4.8.09032", "V4_7_PLUS"),
            ("3.5.30729", "OTHER_VERSION"),
        )
        for version, expected in examples:
            with self.subTest(version=version):
                raw = ("   Version    REG_SZ    " + version + "\n").encode()
                self.assertEqual(r.parse_version(raw, 0), expected)
        self.assertEqual(
            r.parse_version(
                b"ERROR: The system was unable to find the specified registry key or value.", 1),
            "ABSENT")
        self.assertEqual(r.parse_version(b"Version REG_SZ 4.8\nVersion REG_SZ 4.8", 0),
                         "MALFORMED")
        self.assertEqual(r.parse_version(b"Version REG_SZ private", 0), "MALFORMED")

    def test_private_text_and_ambiguous_failures_never_escape(self):
        self.assertEqual(r.parse(b"ERROR: The system was unable to find the specified registry key or value.\n", 1), "ABSENT")
        self.assertEqual(r.parse(b"process failed C:\\Users\\hidden", 1), "UNAVAILABLE")
        self.assertEqual(r.parse(b"Release REG_SZ private", 0), "MALFORMED")
        self.assertEqual(r.parse(b"Release REG_DWORD 0x80ea8\nRelease REG_DWORD 0x80ea8", 0), "MALFORMED")
        self.assertEqual(r.parse(b"\x00" + b"a" * 40, 0), "MALFORMED")
        self.assertEqual(r.parse(b"Release REG_DWORD 0x80ea8\n" + b"x" * 4097, 0), "MALFORMED")
        self.assertEqual(r.parse(b"\xff", 0), "UNAVAILABLE")
        self.assertFalse(r.valid({**r.blank(), "path": "private"}))
        self.assertFalse(r.valid({**r.blank(), "native64": "C:\\Users\\private"}))

    def test_two_views_read_only_and_no_wine_override(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            wine = root / "wine"
            wine.write_text("fixture")
            wine.chmod(0o700)
            prefix = root / "prefix"
            prefix.mkdir()
            called = []

            def fake_subprocess(argv, **kwargs):
                self.assertEqual(argv[:3], [str(wine), "reg.exe", "query"])
                self.assertEqual(argv[4], "/v")
                self.assertIn(argv[5], {"Release", "Version"})
                self.assertIs(kwargs["stderr"], kwargs["stdout"])
                self.assertEqual(kwargs["cwd"], prefix)
                self.assertEqual(kwargs["timeout"], 20)
                self.assertNotIn("WINEDLLOVERRIDES", kwargs["env"])
                self.assertEqual(kwargs["env"]["WINEPREFIX"], str(prefix))
                self.assertEqual(kwargs["stdin"], subprocess.DEVNULL)
                called.append(argv[3])
                if argv[5] == "Version":
                    kwargs["stdout"].write(
                        b" Version REG_SZ 4.0.30319\n" if len(called) == 3
                        else b" Version REG_SZ 4.7\n")
                    return mock.Mock(returncode=0)
                if len(called) == 1:
                    kwargs["stdout"].write(b"  Release  REG_DWORD  0x60267\n")
                    return mock.Mock(returncode=0)
                kwargs["stdout"].write(b"  Release  REG_DWORD  0x82348\n")
                return mock.Mock(returncode=0)

            with mock.patch.object(r, "validate_prefix"), \
                 mock.patch.object(r.subprocess, "run", side_effect=fake_subprocess), \
                 mock.patch.dict(r.os.environ, {"WINEDLLOVERRIDES": "mscoree=b"}):
                result = r.inspect(wine, prefix)
            self.assertEqual(called, list(r.FIELDS.values()))
            self.assertEqual(result, {
                "native64": "OLDER_RELEASE", "wow32": "AT_LEAST_481",
                "native64_version": "V4_0", "wow32_version": "V4_7_PLUS"})
            self.assertTrue(r.valid(result))
            self.assertNotIn(str(root), str(result))

    def test_missing_value_written_to_stderr_is_not_unknown(self):
        # Windows reg.exe often prints missing-value errors to stderr.
        # The diagnostic must capture that stream privately and classify it.
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            wine = root / "wine"
            wine.write_text("fixture")
            wine.chmod(0o700)
            prefix = root / "prefix"
            prefix.mkdir()

            def fake_subprocess(argv, **kwargs):
                self.assertIs(kwargs["stderr"], kwargs["stdout"])
                self.assertEqual(argv[2], "query")
                self.assertEqual(argv[4], "/v")
                self.assertIn(argv[5], {"Release", "Version"})
                kwargs["stderr"].write(
                    b"ERROR: The system was unable to find the specified "
                    b"registry key or value.\n")
                return mock.Mock(returncode=1)

            with mock.patch.object(r, "validate_prefix"), \
                 mock.patch.object(r.subprocess, "run", side_effect=fake_subprocess):
                result = r.inspect(wine, prefix)
            self.assertEqual(result, {key: "ABSENT" for key in r.FIELDS})
            self.assertTrue(r.valid(result))

    def test_failure_is_not_absence_and_no_mutations(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            wine = root / "wine"
            wine.write_text("fixture")
            wine.chmod(0o700)
            prefix = root / "prefix"
            prefix.mkdir()
            with mock.patch.object(r, "validate_prefix"), \
                 mock.patch.object(r.subprocess, "run",
                                   side_effect=subprocess.TimeoutExpired("reg.exe", 20)):
                result = r.inspect(wine, prefix)
            self.assertEqual(result, {key: "UNAVAILABLE" for key in r.FIELDS})
            self.assertTrue(r.valid(result))
            self.assertEqual(r.blank(), {key: "NOT_RUN" for key in r.FIELDS})


if __name__ == "__main__":
    unittest.main()
