"""Synthetic-only tests for private Wine CLR startup trace classification."""
from pathlib import Path
import json
import tempfile
import unittest
from unittest import mock

from scripts import netfx48_start_trace as t


class Original48StartTraceTests(unittest.TestCase):
    def test_sanitizes_vendor_paths_and_only_returns_fixed_categories(self):
        raw = (
            b'0044:trace:loaddll:build_module Loaded L"C:\\windows\\Microsoft.NET\\'
            b'Framework64\\v4.0.30319\\clr.dll" at 0000000000123000: native\n'
            b'0044:trace:loaddll:build_module Loaded L"C:\\windows\\system32\\'
            b'mscoree.dll" at 0000000000123000: native\n'
            b'0044:trace:loaddll:build_module Loaded L"C:\\windows\\Microsoft.NET\\'
            b'Framework64\\v4.0.30319\\mscoreei.dll" at 0000000000123000: native\n'
            b'0044:err:module:import_dll Library C:\\secret\\missing.dll not found\n'
            b'0044:err:module:import_dll unresolved import in C:\\secret\\host.dll\n'
            b'0044:err:seh:raise_exception Unhandled exception\n'
            b'0044:err:kernelbase:stub unimplemented function\n'
        )
        report = t.classify_trace(raw)
        self.assertTrue(report["native_clr_seen"])
        self.assertTrue(report["native_mscoree_seen"])
        self.assertTrue(report["native_mscoreei_seen"])
        self.assertTrue(report["module_missing"])
        self.assertTrue(report["export_missing"])
        self.assertTrue(report["seh_exception"])
        self.assertTrue(report["unimplemented_api"])
        report.update(host="HOST_START_E_FAIL", process="EXIT_ZERO")
        self.assertTrue(t.valid(report))
        text = json.dumps(report)
        self.assertNotIn("secret", text)
        self.assertNotIn("clr.dll", text)
        self.assertNotIn("C:", text)
        self.assertNotIn("0x", text)

    def test_rejects_arbitrary_schema_and_truncated_logs(self):
        self.assertTrue(t.valid(t.blank()))
        self.assertFalse(t.valid(dict(t.blank(), private_path="Z:\\vendor")))
        self.assertFalse(t.valid(dict(t.blank(), framework48_installed=True)))
        self.assertFalse(t.valid(dict(t.blank(), host="E_FAIL 0x80004005")))
        truncated = t.classify_trace(b"vendor private content", truncated=True)
        self.assertEqual(truncated["status"], "PARTIAL")
        self.assertEqual(truncated["trace"], "TOO_LARGE")
        self.assertFalse(truncated["module_missing"])
        bad = t.classify_trace(b"\xff\xfe")
        self.assertEqual(bad["trace"], "INVALID_ENCODING")
        self.assertFalse(bad["native_clr_seen"])

    def test_wine_invocation_has_native_only_host_and_never_emits_raw_trace(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            wine = root / "wine"
            wine.write_text("self authored")
            wine.chmod(0o755)
            prefix = root / "prefix"
            prefix.mkdir()
            fixture = root / "netfx48_host_activation.exe"
            fixture.write_text("self authored")
            managed = root / "netfx48_managed_host_check.dll"
            managed.write_text("self authored")
            def fake(argv, **kwargs):
                env = kwargs["env"]
                self.assertEqual(env["WINEDLLOVERRIDES"], "mscoree=n;clr=n")
                self.assertIn("+loaddll", env["WINEDEBUG"])
                self.assertIn("+seh", env["WINEDEBUG"])
                self.assertEqual(kwargs["cwd"], fixture.parent)
                self.assertEqual(Path(argv[1]), fixture)
                kwargs["stdout"].write(
                    b"SWCOMPAT_NETFX48_HOST_SCHEMA=1\n"
                    b"SWCOMPAT_NETFX48_HOST_STATUS=HOST_START_E_FAIL\n")
                kwargs["stderr"].write(
                    b"0044:err:module:import_dll Library Z:\\private\\secret.dll not found\n")
                return mock.Mock(returncode=0)
            with mock.patch.object(t.subprocess, "run", side_effect=fake):
                report = t.probe(wine, prefix, fixture, managed)
            self.assertTrue(t.valid(report))
            self.assertEqual(report["host"], "HOST_START_E_FAIL")
            self.assertTrue(report["module_missing"])
            self.assertNotIn("secret", json.dumps(report))


if __name__ == "__main__":
    unittest.main()
