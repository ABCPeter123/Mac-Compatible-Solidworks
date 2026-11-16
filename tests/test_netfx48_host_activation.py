"""Synthetic-only coverage for the original CLR 4.8 hosting boundary."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock
from scripts import netfx48_isolated_loader_trial as t


def host_output(status):
    return (f"SWCOMPAT_NETFX48_HOST_SCHEMA=1\n"
            f"SWCOMPAT_NETFX48_HOST_STATUS={status}\n").encode("ascii")


class HostBoundaryTests(unittest.TestCase):
    def test_fixed_categories(self):
        for status in t.HOST_STATES - {"NOT_RUN", "TIMEOUT", "PROBE_ERROR"}:
            with self.subTest(status=status):
                self.assertEqual(t.parse_host(host_output(status), 0), status)
        for data, code in (
            (host_output("MANAGED_ORIGINAL_PASS"), 1),
            (host_output("MANAGED_ORIGINAL_PASS") * 2, 0),
            (host_output("UNSAFE_VENDOR_OUTPUT"), 0),
            (host_output("MANAGED_ORIGINAL_PASS") + b"\x00", 0),
            (host_output("MANAGED_ORIGINAL_PASS") + b"x"*1400, 0),
            (host_output("MANAGED_ORIGINAL_PASS") +
             b"SWCOMPAT_NETFX48_HOST_SECRET=filename.dll\n", 0),
        ):
            self.assertEqual(t.parse_host(data, code), "PROBE_ERROR")

    def test_only_original_runtime_execution_can_mark_managed(self):
        r = t.blank()
        self.assertTrue(t.valid(r))
        self.assertFalse(t.valid(dict(r, managed_executed=True)))
        self.assertFalse(t.valid(dict(r, host_stage="MANAGED_ORIGINAL_PASS")))
        self.assertFalse(t.valid(dict(r, host_stage="MANAGED_ORIGINAL_PASS",
                                      host_process="EXIT_ZERO",
                                      managed_executed=True)))
        good = t.blank()
        good.update(
            status="MEASURED",
            installer_authenticode_preverified=True,
            installer_sha256_verified=True,
            wine_system_process="EXIT_ZERO",
            selftest="LOADED", selftest_process="EXIT_ZERO",
            extraction="PE_AMD64",
            loader="MISSING_DEPENDENCY", original_process="EXIT_ZERO",
            signed_mzz_staging=dict(
                good["signed_mzz_staging"], status="STAGED",
                missing_requested=1, located=1, staged=1,
                families={
                    **good["signed_mzz_staging"]["families"],
                    "VCRUNTIME": {"located": 1, "staged": 1}}),
            loader_after_mzz="LOADED", mzz_process="EXIT_ZERO",
            host_stage="MANAGED_ORIGINAL_PASS", host_process="EXIT_ZERO",
            managed_executed=True,
        )
        self.assertTrue(t.valid(good))
        good["host_stage"] = "OTHER_RUNTIME_SELECTED"
        self.assertFalse(t.valid(good))
        self.assertFalse(t.valid(dict(good, private_original_dll="vendor")))
        self.assertNotIn("original_file_path", json.dumps(good))

    def test_private_host_invocation_is_bounded_and_classified(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            prefix = root / "prefix"
            (prefix / "dosdevices").mkdir(parents=True)
            (prefix / "dosdevices" / "z:").symlink_to("/")
            dll = root / "clr.dll"
            dll.write_bytes(b"synthetic")
            managed = root / "netfx48_managed_host_check.dll"
            managed.write_bytes(b"synthetic")
            fixture = root / "netfx48_host_activation.exe"
            fixture.write_bytes(b"synthetic")
            def success(argv, **kwargs):
                self.assertEqual(argv[1], str(fixture))
                self.assertEqual(kwargs["env"]["WINEDLLOVERRIDES"], "clr=n")
                self.assertIn("clr.dll", kwargs["env"]["SWCOMPAT_CLR_PATH"])
                kwargs["stdout"].write(host_output("RUNTIME_DISCOVERY_FAILED"))
                return mock.Mock(returncode=0)
            with mock.patch.object(t.subprocess, "run", side_effect=success):
                self.assertEqual(t.host_check(root/"wine", prefix, fixture, managed, dll),
                                 ("RUNTIME_DISCOVERY_FAILED", "EXIT_ZERO"))
            with mock.patch.object(t.subprocess, "run",
                                   side_effect=__import__("subprocess").TimeoutExpired("wine", 1)):
                self.assertEqual(t.host_check(root/"wine", prefix, fixture, managed, dll),
                                 ("TIMEOUT", "TIMEOUT"))


if __name__ == "__main__":
    unittest.main()
