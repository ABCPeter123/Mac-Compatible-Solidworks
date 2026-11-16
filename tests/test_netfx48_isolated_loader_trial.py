"""Private original .NET 4.8 x64 CLR loader test, synthetic-only fixtures."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock
from scripts import netfx48_isolated_loader_trial as t


def stdout(state: str) -> bytes:
    return (f"SWCOMPAT_NETFX48_ISOLATED_SCHEMA=1\n"
            f"SWCOMPAT_NETFX48_ISOLATED_LOADER={state}\n"
            f"SWCOMPAT_NETFX48_ISOLATED_MANAGED=NOT_TESTED\n").encode("ascii")


class IsolatedLoaderTests(unittest.TestCase):
    def test_exact_valid_error_classes_only(self):
        for state in t.STATES - {"TIMEOUT", "PROBE_ERROR", "NOT_RUN"}:
            with self.subTest(state=state):
                self.assertEqual(t.parse_loader(stdout(state), 0), state)
        for raw, rc in (
            (stdout("LOADED"), 1),
            (stdout("LOADED") + stdout("LOADED"), 0),
            (stdout("LOADED") + b"SWCOMPAT_NETFX48_ISOLATED_SNEAK=SECRET\n", 0),
            (stdout("LOADED") + b"\x00", 0),
            (stdout("MADEUP"), 0),
            (stdout("LOADED") + b"x" * 1500, 0),
        ):
            self.assertEqual(t.parse_loader(raw, rc), "PROBE_ERROR")

    def test_outcomes_never_invent_managed_48(self):
        self.assertTrue(t.valid(t.blank()))
        for forbidden in (
            dict(t.blank(), runtime_installed=True),
            dict(t.blank(), managed_executed=True),
            dict(t.blank(), original_payload_artifact=True),
            dict(t.blank(), original_file="private-original"),
        ):
            self.assertFalse(t.valid(forbidden))
        d = t.blank()
        d.update(status="MEASURED",
                 installer_authenticode_preverified=True,
                 installer_sha256_verified=True,
                 extraction="PE_AMD64",
                 selftest="LOADED", selftest_process="EXIT_ZERO",
                 wine_system_process="EXIT_ZERO",
                 original_process="EXIT_ZERO",
                 loader="MISSING_DEPENDENCY")
        self.assertTrue(t.valid(d))
        d["extraction"] = "NO_MZZ"
        self.assertFalse(t.valid(d))

    def test_digest_verification_uses_full_original_file_and_expected_name(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            original = root / "NDP48-x86-x64-AllOS-ENU.exe"
            original.write_bytes(b"synthetic")
            with self.assertRaises(ValueError):
                t.verify_original(original, "a" * 64)
            with mock.patch.object(t, "MAX_INSTALLER", 300):
                with mock.patch.object(t, "hashlib") as hashing:
                    # No test relaxes the real 15MiB media minimum.
                    with self.assertRaises(ValueError):
                        t.verify_original(original, "a" * 64)
            with self.assertRaises(ValueError):
                t.verify_original(original, "malformed")
            other = root / "private-vendor.exe"
            other.write_bytes(b"binary")
            with self.assertRaises(ValueError):
                t.verify_original(other, hashlib.sha256(b"binary").hexdigest())

    def test_probe_only_in_disposable_prefix(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            prefix = root / "prefix"
            (prefix / "drive_c").mkdir(parents=True)
            (prefix / "system.reg").write_text("synthetic")
            wine = root / "wine"
            wine.write_text("self authored")
            reader = root / "7zz"
            reader.write_text("self authored")
            fixture = root / "netfx48_isolated_loader.exe"
            fixture.write_bytes(b"self authored")
            original = root / "NDP48-x86-x64-AllOS-ENU.exe"
            original.write_bytes(b"synthetic")
            with mock.patch.object(t, "extract_clr") as extract:
                with self.assertRaises(ValueError):
                    t.trial(original, "a" * 64, wine, prefix, reader, fixture)
                extract.assert_not_called()

    def test_wine_selftest_differentiates_process_and_output_failure(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            fixture = base / "netfx48_isolated_loader.exe"
            fixture.write_bytes(b"independent")
            def fake_code(code: int):
                def cb(argv, **kwargs):
                    if code == 0:
                        kwargs["stdout"].write(stdout("LOADED"))
                    return mock.Mock(returncode=code)
                return cb
            for code, status, process in (
                    (0, "LOADED", "EXIT_ZERO"),
                    (1, "PROBE_ERROR", "EXIT_1"),
                    (-11, "PROBE_ERROR", "SIGNALLED")):
                with self.subTest(code=code), mock.patch.object(
                        t.subprocess, "run", side_effect=fake_code(code)):
                    self.assertEqual(
                        t._invoke(base / "wine", base / "prefix", fixture,
                                  "--selftest-windows", original=False),
                        (status, process))
            with mock.patch.object(t.subprocess, "run", return_value=mock.Mock(returncode=0)):
                self.assertEqual(
                    t._invoke(base / "wine", base / "prefix", fixture,
                              "--selftest-windows", original=False),
                    ("PROBE_ERROR", "EXIT_ZERO"))

    def test_wine_cmd_control_and_finite_exit_buckets(self):
        self.assertEqual(t.exit_class(0), "EXIT_ZERO")
        self.assertEqual(t.exit_class(126), "EXIT_126")
        self.assertEqual(t.exit_class(127), "EXIT_127")
        self.assertEqual(t.exit_class(193), "EXIT_193")
        self.assertEqual(t.exit_class(999999), "EXIT_NONZERO_OTHER")
        self.assertEqual(t.exit_class(-11), "SIGNALLED")
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            with mock.patch.object(t.subprocess, "run", return_value=mock.Mock(returncode=0)) as f:
                self.assertEqual(t._wine_system_control(root / "wine", root), "EXIT_ZERO")
                self.assertEqual(f.call_args.args[0][1:], ["cmd.exe", "/c", "ver"])
            with mock.patch.object(t.subprocess, "run", return_value=mock.Mock(returncode=127)):
                self.assertEqual(t._wine_system_control(root / "wine", root), "EXIT_127")

    def test_no_raw_filenames_returned_on_missing_mzz(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            installer = root / "NDP48-x86-x64-AllOS-ENU.exe"
            installer.write_bytes(b"fixture")
            seven = root / "7zz"
            seven.write_bytes(b"fixture")
            with mock.patch.object(t, "_run_private", return_value=0):
                with tempfile.TemporaryDirectory() as destination:
                    result, f = t.extract_clr(installer, seven, Path(destination))
            self.assertEqual(result, "NO_MZZ")
            self.assertIsNone(f)
            self.assertNotIn(str(root), json.dumps(t.blank()))


if __name__ == "__main__":
    unittest.main()
