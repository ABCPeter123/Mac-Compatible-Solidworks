"""Vendor-free controls for installed original .NET 4.0 public CLR host A/B."""
from pathlib import Path
import json
import tempfile
import unittest
from unittest import mock
from scripts import netfx40_host_api_diagnostic as t


def output(status: str) -> bytes:
    return ("SWCOMPAT_NETFX48_HOST_SCHEMA=1\n"
            "SWCOMPAT_NETFX48_HOST_STATUS=" + status + "\n").encode()


class NativeHostAPITests(unittest.TestCase):
    def test_exact_host_status_and_reject_malformed(self):
        self.assertEqual(t.classify(output("MANAGED_ORIGINAL_PASS"), 0),
                         "MANAGED_ORIGINAL_PASS")
        self.assertEqual(t.classify(output("OTHER_RUNTIME_SELECTED"), 0),
                         "OTHER_RUNTIME_SELECTED")
        self.assertEqual(t.classify(output("HOST_START_CLR_FACILITY"), 0),
                         "HOST_START_CLR_FACILITY")
        self.assertEqual(t.classify(output("HOST_START_WIN32_NOT_IMPLEMENTED"), 0),
                         "HOST_START_WIN32_NOT_IMPLEMENTED")
        for raw, code in [
            (output("MANAGED_ORIGINAL_PASS"), 1),
            (output("UNKNOWN_STATUS"), 0),
            (output("MANAGED_ORIGINAL_PASS") * 2, 0),
            (output("MANAGED_ORIGINAL_PASS") + bytes([0]), 0),
            (output("MANAGED_ORIGINAL_PASS") + b"SWCOMPAT_NETFX48_HOST_STATUS=OTHER_RUNTIME_SELECTED\n", 0),
            (b"SWCOMPAT_NETFX48_HOST_SCHEMA=0\nSWCOMPAT_NETFX48_HOST_STATUS=MANAGED_ORIGINAL_PASS\n", 0),
            (b"untrusted", 0),
            (b"A" * (t.MAX_BYTES + 1), 0),
        ]:
            with self.subTest(code=code, raw=raw[:40]):
                self.assertEqual(t.classify(raw, code), "INVALID_OUTPUT")

    def test_reports_are_bounded_and_never_claim_48(self):
        self.assertTrue(t.valid(t.blank()))
        self.assertFalse(t.valid(dict(t.blank(), framework48_installed=True)))
        self.assertFalse(t.valid(dict(t.blank(), private_path="Z:\\private")))
        good = {"status": "MEASURED", "native": "MANAGED_ORIGINAL_PASS",
                "builtin": "OTHER_RUNTIME_SELECTED",
                "native_managed_pass": True, "framework48_installed": False}
        self.assertTrue(t.valid(good))
        self.assertFalse(t.valid(dict(good, native_managed_pass=False)))
        self.assertFalse(t.valid(dict(good, framework48_installed=True)))
        self.assertNotIn("Z:", json.dumps(good))

    def test_execution_uses_only_original_CLR_and_explicit_host_modes(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            wine = root / "wine"
            wine.write_text("self authored")
            wine.chmod(0o755)
            prefix = root / "prefix"
            (prefix / "drive_c").mkdir(parents=True)
            (prefix / "system.reg").write_text("")
            (prefix / ".swcompat-netfx481-disposable").write_text("")
            fixture = root / "netfx48_host_activation.exe"
            fixture.write_text("self authored")
            managed = root / "netfx48_managed_host_check.dll"
            managed.write_text("self authored")
            report = {"persistent_native_managed": True,
                      "native_only_managed": "PASS"}
            calls = []
            def fake(argv, **kwargs):
                env = kwargs["env"]
                calls.append(env["WINEDLLOVERRIDES"])
                self.assertEqual(env["SWCOMPAT_CLR_PATH"], t.CLR_PATH)
                self.assertTrue(env["SWCOMPAT_MANAGED_DLL"].startswith("Z:"))
                self.assertNotIn("SWCOMPAT_ORIGINAL_SHIM_PATH", env)
                self.assertEqual(env["WINEDEBUG"], "-all")
                status = ("MANAGED_ORIGINAL_PASS" if
                          env["WINEDLLOVERRIDES"] == "mscoree=n;clr=n"
                          else "OTHER_RUNTIME_SELECTED")
                kwargs["stdout"].write(output(status))
                return mock.Mock(returncode=0)
            with mock.patch.object(t, "validate_restart", return_value=True), \
                 mock.patch.object(t.subprocess, "run", side_effect=fake):
                result = t.audit(wine, prefix, fixture, managed, report)
            self.assertTrue(t.valid(result))
            self.assertTrue(result["native_managed_pass"])
            self.assertEqual(calls, ["mscoree=n;clr=n", "mscoree=b;clr=n"])
            self.assertEqual(result["builtin"], "OTHER_RUNTIME_SELECTED")
            with mock.patch.object(t, "validate_restart", return_value=True):
                self.assertEqual(t.audit(wine, prefix, fixture, managed,
                                         {"persistent_native_managed": False,
                                          "native_only_managed": "FAIL"}),
                                 t.blank())
            with self.assertRaises(ValueError):
                t.execute(wine, prefix, fixture, managed, "n,b")


if __name__ == "__main__":
    unittest.main()
