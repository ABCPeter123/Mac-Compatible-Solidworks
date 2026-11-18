"""Finite x86 native/managed Wine WoW64 fault classification, no raw log release."""
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase, mock
import subprocess

from scripts import netfx40_wow64_fault_triage as d


class Wow64FaultTriageTests(TestCase):
    def test_upstream_wow64cpu_mode_mismatch_only_a_candidate(self):
        trace = (b"trace:seh:dispatch_exception code=c0000005 "
                 b"flags=0 addr=7BF21135 cs=0107 "
                 b"info[1]=00002EC5\n")
        self.assertEqual(d.classify_seh(trace, False), "WOW64CPU_MODE_CANDIDATE")
        self.assertEqual(d.classify_seh(
            b"trace:seh:dispatch_exception code=c0000005 addr=12345", False),
            "ACCESS_VIOLATION")
        self.assertEqual(d.classify_seh(
            b"trace:seh:dispatch_exception code=80000003", False),
            "OTHER_EXCEPTION")
        self.assertEqual(d.classify_seh(b"", False), "NO_EXCEPTION")
        self.assertEqual(d.classify_seh(trace, True), "TOO_LARGE")

    def test_controlled_x86_native_then_managed_evidence_stays_private(self):
        with TemporaryDirectory() as td:
            root = Path(td)
            wine = root / "wine"
            wine.write_bytes(b"x")
            prefix = root / "prefix"
            prefix.mkdir()
            native = root / d.NATIVE_NAME
            managed = root / d.MANAGED_NAME
            native.write_bytes(b"MZ")
            managed.write_bytes(b"MZ")
            native_data = b"\n".join(d.NATIVE_MARKERS) + b"\nPRIVATE HOME PATH\n"
            managed_data = (b"SWCOMPAT_NETFX481_SCHEMA=1\n"
                            b"SWCOMPAT_NETFX481_REGISTRY=BELOW_481\n"
                            b"SWCOMPAT_NETFX481_CLR_FAMILY=MICROSOFT_CLR_CANDIDATE\n"
                            b"SWCOMPAT_NETFX481_MANAGED=PASS\n"
                            b"z:\\private\\somefile.dll")
            with (mock.patch.object(d, "validate_prefix"),
                  mock.patch.object(d, "_capture", side_effect=[
                      ("EXIT_ZERO", "NO_EXCEPTION", native_data),
                      ("EXIT_ZERO", "WOW64CPU_MODE_CANDIDATE", managed_data),
                  ]) as captured):
                report = d.inspect(wine, prefix, native, managed)
            self.assertTrue(d.valid(report))
            self.assertTrue(report["native_control"])
            self.assertEqual(report["managed_family"], "MICROSOFT_CLR_CANDIDATE")
            self.assertEqual(report["managed_execution"], "PASS")
            self.assertEqual(report["managed_seh"], "WOW64CPU_MODE_CANDIDATE")
            self.assertNotIn("private", str(report))
            self.assertEqual(captured.call_count, 2)
            self.assertEqual(captured.call_args_list[0].kwargs["managed"], False)
            self.assertEqual(captured.call_args_list[1].kwargs["managed"], True)

    def test_denied_cleanup_must_abort_before_managed_code(self):
        with TemporaryDirectory() as td:
            root = Path(td)
            prefix = root / "prefix"
            prefix.mkdir()
            wine = root / "wine"
            wine.write_bytes(b"x")
            native = root / d.NATIVE_NAME
            native.write_bytes(b"MZ")
            managed = root / d.MANAGED_NAME
            managed.write_bytes(b"MZ")
            with (mock.patch.object(d, "validate_prefix"),
                  mock.patch.object(d, "_capture", return_value=(
                      "TIMED_OUT_CLEANUP_DENIED", "ACCESS_VIOLATION", b""))
                  as captured):
                result = d.inspect(wine, prefix, native, managed)
            self.assertEqual(captured.call_count, 1)
            self.assertEqual(result["managed_run"], "NOT_RUN")
            self.assertTrue(d.valid(result))

    def test_captured_child_timeout_is_killed_as_process_group(self):
        with TemporaryDirectory() as td:
            child = mock.Mock()
            child.wait.side_effect = subprocess.TimeoutExpired("wine", 25)
            with (mock.patch.object(d.subprocess, "Popen", return_value=child),
                  mock.patch.object(d.time, "monotonic", side_effect=[0, 26]),
                  mock.patch.object(d, "_terminate_group") as terminate):
                run, status, raw = d._capture(Path("wine"), Path(td), Path("x86.exe"),
                                              25, managed=True)
            self.assertEqual((run, status, raw), ("TIMED_OUT", "NO_EXCEPTION", b""))
            terminate.assert_called_once_with(child)

    def test_strict_report_rejects_untrusted_and_ambiguous_fields(self):
        b = d.blank()
        self.assertTrue(d.valid(b))
        self.assertFalse(d.valid({**b, "native_run": "EXIT_ZERO",
                                  "native_control": True}))
        self.assertFalse(d.valid({**b, "managed_run": "EXIT_ZERO",
                                  "managed_execution": "PASS"}))
        self.assertFalse(d.valid({**b, "private_trace": "password"}))
        self.assertFalse(d.valid({**b, "native_seh": []}))
        self.assertFalse(d.valid({**b, "native_control": 1}))
