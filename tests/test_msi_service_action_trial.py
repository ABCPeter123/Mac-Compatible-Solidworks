"""Safety and real-service-action readiness regressions for original MSI differential."""
from pathlib import Path
from tempfile import TemporaryDirectory
import hashlib
import os
import unittest
from unittest import mock

from scripts import msi_service_action_trial as service


class MSIServiceActionTests(unittest.TestCase):
    def test_original_win32_service_protocol(self):
        absent = (
            b"SWCOMPAT_SERVICE_PHASE=absent\n"
            b"SWCOMPAT_SERVICE_ERROR=1060\n"
            b"SWCOMPAT_SERVICE_STATE=0\n"
            b"SWCOMPAT_SERVICE_CHECK=PASS\n"
        )
        running = (
            b"SWCOMPAT_SERVICE_PHASE=status\n"
            b"SWCOMPAT_SERVICE_ERROR=0\n"
            b"SWCOMPAT_SERVICE_STATE=4\n"
            b"SWCOMPAT_SERVICE_PID=640\n"
            b"SWCOMPAT_SERVICE_CHECK=PASS\n"
        )
        self.assertEqual(service.service_result(absent, 0, "absent"), "ABSENT")
        self.assertEqual(service.service_result(running, 0, "status"), "RUNNING")
        self.assertEqual(service.service_result(running, 0, "absent"), "UNKNOWN")
        self.assertEqual(service.service_result(running + b"SWCOMPAT_SERVICE_STATE=4\n", 0, "status"),
                         "UNKNOWN")
        self.assertEqual(service.service_result(running, 1, "status"), "OTHER")
        failure = running.replace(b"SWCOMPAT_SERVICE_ERROR=0",
                                  b"SWCOMPAT_SERVICE_ERROR=1060").replace(
                b"SWCOMPAT_SERVICE_CHECK=PASS", b"SWCOMPAT_SERVICE_CHECK=FAIL")
        self.assertEqual(service.service_result(failure, 1, "status"), "ABSENT")
        self.assertEqual(service.service_result(b"PRIVATE=secret", 0, "status"), "UNKNOWN")

    def test_candidate_must_have_real_file_and_running_service(self):
        r = {
            "schema": 1, "scope": service.SCOPE, "status": "MEASURED",
            "winver": "APPLIED", "service_before": "ABSENT",
            "binary_before": "ABSENT", "msi_process": "ZERO",
            "unix_exit": 0, "binary_after": "PRESENT_MATCH",
            "service_after": "RUNNING", "msi_service_start_candidate": True,
            "dotnet_compatibility": False,
            "solidworks_compatibility": "NOT_DEMONSTRATED",
        }
        self.assertTrue(service.validate(r))
        for key, value in (
            ("service_after", "ABSENT"),
            ("binary_after", "CHANGED"),
            ("msi_process", "NONZERO"),
            ("service_before", "RUNNING"),
            ("dotnet_compatibility", True),
            ("solidworks_compatibility", "READY"),
            ("msi_service_start_candidate", 1),
            ("unix_exit", 3010),
        ):
            with self.subTest(key=key):
                self.assertFalse(service.validate(dict(r, **{key: value})))
        self.assertFalse(service.validate(dict(r, raw_log="private")))

    @unittest.skipIf(os.name == "nt", "Only isolated POSIX Wine prefix test")
    def test_genuine_msi_action_attempt_cannot_be_faked_by_process_zero(self):
        with TemporaryDirectory() as td:
            root = Path(td)
            prefix = root / "prefix"
            (prefix / "drive_c").mkdir(parents=True)
            (prefix / "system.reg").touch()
            (prefix / ".swcompat-netfx481-disposable").touch()
            wine = root / "wine"; wine.write_bytes(b"mock wine"); wine.chmod(0o700)
            exe = root / service.EXE_NAME; exe.write_bytes(b"s" * 4096)
            msi = root / service.MSI_NAME; msi.write_bytes(b"m" * 4096)
            sha = root / "msi.sha256"; sha.write_text(hashlib.sha256(msi.read_bytes()).hexdigest())
            with (
                mock.patch.object(service, "query_service",
                                  side_effect=["ABSENT", "ABSENT"]),
                mock.patch.object(service, "set_legacy_winver",
                                  return_value="APPLIED"),
                mock.patch.object(service, "launch_msi",
                                  return_value=("ZERO", 0)) as launch,
                mock.patch.object(service, "binary_state",
                                  side_effect=["ABSENT", "PRESENT_MATCH"]),
            ):
                r = service.inspect(wine, prefix, msi, sha, exe)
            self.assertEqual(launch.call_count, 1)
            self.assertTrue(service.validate(r))
            self.assertEqual(r["msi_process"], "ZERO")
            self.assertEqual(r["service_after"], "ABSENT")
            self.assertFalse(r["msi_service_start_candidate"])
            self.assertNotIn(str(root), str(r))

    @unittest.skipIf(os.name == "nt", "Only isolated POSIX Wine prefix test")
    def test_refuse_unmarked_or_preexisting_prefix(self):
        with TemporaryDirectory() as td:
            root = Path(td); prefix = root / "prefix"
            (prefix / "drive_c").mkdir(parents=True)
            (prefix / "system.reg").touch()
            wine = root / "wine"; wine.write_bytes(b"x"); wine.chmod(0o700)
            exe = root / service.EXE_NAME; exe.write_bytes(b"x" * 4096)
            msi = root / service.MSI_NAME; msi.write_bytes(b"x" * 4096)
            sha = root / "msi.sha256"; sha.write_text(hashlib.sha256(msi.read_bytes()).hexdigest())
            with self.assertRaises(ValueError):
                service.inspect(wine, prefix, msi, sha, exe)
            (prefix / ".swcompat-netfx481-disposable").touch()
            with (
                mock.patch.object(service, "query_service", return_value="RUNNING"),
                mock.patch.object(service, "binary_state", return_value="ABSENT"),
                mock.patch.object(service, "launch_msi") as launch,
            ):
                r = service.inspect(wine, prefix, msi, sha, exe)
                launch.assert_not_called()
                self.assertEqual(r["status"], "ALREADY_PRESENT")
                self.assertFalse(r["msi_service_start_candidate"])


if __name__ == "__main__":
    unittest.main()
