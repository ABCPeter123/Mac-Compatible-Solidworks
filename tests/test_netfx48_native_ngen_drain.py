"""Strict original Microsoft NGen x64/x86 preflight controls.

No genuine vendor files or Wine processes are needed for these unit tests.
"""
from __future__ import annotations

import os
from pathlib import Path
import struct
import subprocess
from tempfile import TemporaryDirectory
import unittest
from unittest import mock

from scripts import netfx48_native_ngen_drain as ngen


def _pe(machine: int, magic: int) -> bytes:
    buf = bytearray(8192)
    buf[:2] = b"MZ"
    struct.pack_into("<I", buf, 0x3C, 0x80)
    buf[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<H", buf, 0x84, machine)
    struct.pack_into("<H", buf, 0x80 + 20, 0xE0)
    struct.pack_into("<H", buf, 0x80 + 24, magic)
    return bytes(buf)


class OriginalNGenPreflightTests(unittest.TestCase):
    def fixture(self, root: Path):
        wine = root / "wine"
        wine.write_bytes(b"synthetic self-authored launcher")
        wine.chmod(0o755)
        prefix = root / "netfx40-msxml3-prefix"
        (prefix / "drive_c").mkdir(parents=True)
        (prefix / "system.reg").write_bytes(b"Wine generated registry fixture")
        (prefix / ".swcompat-netfx481-disposable").touch()
        native40 = {
            "persistent_native_managed": True,
            "runtime_family": "MICROSOFT_CLR_CANDIDATE",
            "native_only_managed": "PASS",
        }
        return wine, prefix, native40

    def make_ngen(self, prefix: Path, arch: str, *, wrong_machine=False):
        frame = "Framework64" if arch == "x64" else "Framework"
        machine, magic = ((0x8664, 0x20B) if arch == "x64"
                          else (0x14C, 0x10B))
        if wrong_machine:
            machine, magic = 0x14C, 0x10B
        path = prefix / "drive_c/windows/Microsoft.NET" / frame / "v4.0.30319/ngen.exe"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(_pe(machine, magic))
        return path

    def test_strict_schema_disallows_success_without_both_architectures(self):
        self.assertTrue(ngen.valid(ngen.blank()))
        self.assertTrue(ngen.valid({
            "status": "READY", "x64": "SUCCESS", "x86": "SUCCESS",
            "ready": True, "wine_trace": {"x64": ngen.trace_blank(), "x86": ngen.trace_blank()},
            "ngen_progress": ngen.progress_blank(),
        }))
        self.assertFalse(ngen.valid({
            "status": "READY", "x64": "SUCCESS", "x86": "NOT_RUN",
            "ready": True, "wine_trace": {"x64": ngen.trace_blank(), "x86": ngen.trace_blank()},
            "ngen_progress": ngen.progress_blank(),
        }))
        self.assertFalse(ngen.valid(dict(ngen.blank(), vendor_log="private")))
        self.assertFalse(ngen.valid(dict(ngen.blank(), ready=1)))
        self.assertFalse(ngen.valid(dict(ngen.blank(), x64="C:/secret")))

    def test_missing_or_wrong_architecture_never_starts_ngen(self):
        with TemporaryDirectory() as td:
            root = Path(td)
            wine, prefix, native40 = self.fixture(root)
            with (mock.patch.dict(os.environ, {"RUNNER_TEMP": td}),
                  mock.patch.object(ngen, "valid_restart", return_value=True),
                  mock.patch.object(ngen.subprocess, "Popen") as start):
                missing = ngen.inspect(wine, prefix, native40)
                self.assertEqual(missing["x64"], "FILE_MISSING")
                self.assertEqual(missing["x86"], "NOT_RUN")
                self.assertFalse(missing["ready"])
                start.assert_not_called()
                self.make_ngen(prefix, "x64", wrong_machine=True)
                invalid = ngen.inspect(wine, prefix, native40)
                self.assertEqual(invalid["x64"], "INVALID_PE")
                start.assert_not_called()

    def test_both_original_architectures_run_sequentially(self):
        with TemporaryDirectory() as td:
            root = Path(td)
            wine, prefix, native40 = self.fixture(root)
            exe64 = self.make_ngen(prefix, "x64")
            exe86 = self.make_ngen(prefix, "x86")
            calls = []
            def launch(command, **kwargs):
                calls.append(command)
                self.assertEqual(command[-1], "executeQueuedItems")
                self.assertIn(command[1], (str(exe64), str(exe86)))
                self.assertEqual(kwargs["env"]["WINEPREFIX"], str(prefix))
                self.assertEqual(kwargs["env"]["WINEDLLOVERRIDES"], "mscoree=n;clr=n")
                self.assertEqual(kwargs["cwd"], prefix)
                self.assertTrue(kwargs["start_new_session"])
                self.assertIs(kwargs["stdout"], subprocess.DEVNULL)
                return mock.Mock(wait=mock.Mock(return_value=0))
            with (mock.patch.dict(os.environ, {"RUNNER_TEMP": td}),
                  mock.patch.object(ngen, "valid_restart", return_value=True),
                  mock.patch.object(ngen.subprocess, "Popen", side_effect=launch)):
                report = ngen.inspect(wine, prefix, native40)
            self.assertEqual([cmd[1] for cmd in calls], [str(exe64), str(exe86)])
            self.assertEqual(report["status"], "READY")
            self.assertTrue(report["ready"])
            self.assertTrue(ngen.valid(report))

    def test_nonzero_ngen_prevents_x86_and_msi_progression(self):
        with TemporaryDirectory() as td:
            root = Path(td)
            wine, prefix, native40 = self.fixture(root)
            self.make_ngen(prefix, "x64")
            self.make_ngen(prefix, "x86")
            with (mock.patch.dict(os.environ, {"RUNNER_TEMP": td}),
                  mock.patch.object(ngen, "valid_restart", return_value=True),
                  mock.patch.object(ngen.subprocess, "Popen",
                                    return_value=mock.Mock(wait=mock.Mock(return_value=99))) as start):
                report = ngen.inspect(wine, prefix, native40)
            self.assertEqual(report["status"], "BLOCKED")
            self.assertEqual(report["x64"], "EXIT_NONZERO")
            self.assertEqual(report["x86"], "NOT_RUN")
            self.assertEqual(start.call_count, 1)
            self.assertTrue(ngen.valid(report))

    def test_timeout_terminates_entire_original_ngen_process_group(self):
        with TemporaryDirectory() as td:
            root = Path(td)
            wine, prefix, native40 = self.fixture(root)
            self.make_ngen(prefix, "x64")
            child = mock.Mock(wait=mock.Mock(side_effect=subprocess.TimeoutExpired("ngen", 180)))
            with (mock.patch.dict(os.environ, {"RUNNER_TEMP": td}),
                  mock.patch.object(ngen, "valid_restart", return_value=True),
                  mock.patch.object(ngen.subprocess, "Popen", return_value=child),
                  mock.patch.object(ngen, "_terminate_group") as terminate):
                report = ngen.inspect(wine, prefix, native40)
                terminate.assert_called_once_with(child)
            self.assertEqual(report["x64"], "TIMED_OUT")
            self.assertEqual(report["x86"], "NOT_RUN")
            self.assertFalse(report["ready"])

    def test_real_ngen_queue_log_progress_is_metadata_only(self):
        with TemporaryDirectory() as td:
            root = Path(td)
            wine, prefix, native40 = self.fixture(root)
            self.make_ngen(prefix, "x64")
            self.make_ngen(prefix, "x86")
            log_dir = prefix / "drive_c/windows/Microsoft.NET/Framework64/v4.0.30319"
            calls = []
            def launch(cmd, **kwargs):
                calls.append(cmd)
                def wait(*, timeout):
                    if len(calls) == 1:
                        (log_dir / "ngen.log").write_bytes(b"SECRET managed assembly name")
                    return 0
                return mock.Mock(wait=mock.Mock(side_effect=wait))
            with (mock.patch.dict(os.environ, {"RUNNER_TEMP": td}),
                  mock.patch.object(ngen, "valid_restart", return_value=True),
                  mock.patch.object(ngen.subprocess, "Popen", side_effect=launch)):
                report = ngen.inspect(wine, prefix, native40)
            self.assertEqual(report["status"], "READY")
            self.assertEqual(len(calls), 2)
            self.assertEqual(report["ngen_progress"]["status"], "OBSERVED")
            self.assertGreaterEqual(report["ngen_progress"]["x64_growth_windows"], 1)
            self.assertTrue(ngen.valid_progress(report["ngen_progress"]))
            self.assertNotIn("SECRET", str(report))

    def test_timeout_budget_remains_fixed_with_sampling(self):
        with TemporaryDirectory() as td:
            root = Path(td)
            wine, prefix, native40 = self.fixture(root)
            self.make_ngen(prefix, "x64")
            calls = []
            def launch(cmd, **kwargs):
                def wait(*, timeout):
                    calls.append(timeout)
                    raise subprocess.TimeoutExpired("ngen", timeout)
                return mock.Mock(wait=mock.Mock(side_effect=wait))
            with (mock.patch.dict(os.environ, {"RUNNER_TEMP": td}),
                  mock.patch.object(ngen, "valid_restart", return_value=True),
                  mock.patch.object(ngen.subprocess, "Popen", side_effect=launch),
                  mock.patch.object(ngen, "_terminate_group")):
                report = ngen.inspect(wine, prefix, native40)
            self.assertEqual(calls, [60, 60, 60])
            self.assertEqual(report["x64"], "TIMED_OUT")
            self.assertEqual(report["ngen_progress"]["status"], "OBSERVED")
            self.assertEqual(report["ngen_progress"]["samples"], 4)
            self.assertTrue(ngen.valid(report))
            self.assertFalse(report["ready"])

    def test_private_wine_seh_trace_on_timed_out_x64_is_safe_enum_only(self):
        with TemporaryDirectory() as td:
            root = Path(td)
            wine, prefix, native40 = self.fixture(root)
            self.make_ngen(prefix, "x64")
            def launch(command, **kwargs):
                self.assertEqual(kwargs["env"]["WINEDEBUG"],
                                 "-all,err+seh,err+ntdll,err+ole,err+rpc")
                self.assertNotEqual(kwargs["stderr"], subprocess.DEVNULL)
                kwargs["stderr"].write(
                    b"01af:err:seh:setup_exception_record stack overflow 756 bytes "
                    b"eip 0xPRIVATE\\n"
                    b"01af:err:ntdll:RtlpWaitForCriticalSection wait timed out\\n")
                return mock.Mock(wait=mock.Mock(
                    side_effect=subprocess.TimeoutExpired("ngen", 180)))
            with (mock.patch.dict(os.environ, {"RUNNER_TEMP": td}),
                  mock.patch.object(ngen, "valid_restart", return_value=True),
                  mock.patch.object(ngen.subprocess, "Popen", side_effect=launch),
                  mock.patch.object(ngen, "_terminate_group")):
                report = ngen.inspect(wine, prefix, native40,
                                      observe_wine_failures=True)
            self.assertEqual(report["x64"], "TIMED_OUT")
            self.assertEqual(report["x86"], "NOT_RUN")
            self.assertEqual(report["wine_trace"]["x64"], {
                "status": "CLASSIFIED",
                "signals": ["CRITICAL_SECTION_WAIT", "STACK_OVERFLOW"]})
            self.assertEqual(report["wine_trace"]["x86"], ngen.trace_blank())
            self.assertTrue(ngen.valid(report))
            self.assertNotIn("PRIVATE", str(report))
            self.assertNotIn("0xPRIVATE", str(report))

    def test_stack_diagnostic_cannot_run_without_real_wiage_msi_guard(self):
        workflow = (Path(__file__).resolve().parents[1] /
                    ".github/workflows/netfx40-legacy-ci.yml").read_text()
        self.assertIn("if: inputs.ngen_host_stack64 && (!inputs.drain_native40_ngen", workflow)
        self.assertIn("inputs.wine_baseline != 'wiage-11.13'", workflow)
        self.assertIn("ulimit -s 65520", workflow)
        self.assertIn('[[ "$(ulimit -s)" == "65520" ]]', workflow)
        self.assertIn('trace_flags+=(--observe-wine-failures)', workflow)

    def test_refuse_unverified_clr4_and_unmarked_or_wrong_root(self):
        with TemporaryDirectory() as td:
            root = Path(td)
            wine, prefix, native40 = self.fixture(root)
            with mock.patch.dict(os.environ, {"RUNNER_TEMP": td}):
                with self.assertRaises(ValueError):
                    ngen.inspect(wine, prefix, dict(native40, persistent_native_managed=False))
                (prefix / ".swcompat-netfx481-disposable").unlink()
                with self.assertRaises(ValueError):
                    ngen.inspect(wine, prefix, native40)
                (prefix / ".swcompat-netfx481-disposable").touch()
                (prefix / "drive_c" / "windows").mkdir()
                (prefix / "drive_c" / "windows" / "Microsoft.NET").symlink_to(root)
                _, state = ngen._ngen(prefix, "x64")
                self.assertEqual(state, "UNSAFE_FILE")

    def test_ci_gates_msis_on_opt_in_and_captures_only_fixed_statuses(self):
        workflow = (Path(__file__).resolve().parents[1] /
                    ".github/workflows/netfx40-legacy-ci.yml").read_text()
        marker = "      - name: Drain genuine original Microsoft CLR4 NGen x64 and x86 queues before signed 4.8 MSI"
        next_marker = "      - name: Extract authenticated original .NET 4.8 x64 MSI and MSP after genuine CLR4.0"
        self.assertLess(workflow.index(marker), workflow.index(next_marker))
        block = workflow.split(marker, 1)[1].split(next_marker, 1)[0]
        self.assertIn("inputs.drain_native40_ngen", block)
        self.assertIn("env.SWCOMPAT_NATIVE40_READY == 'yes'", block)
        self.assertIn("--native40-report build/netfx40-msxml3-restart.json", block)
        self.assertIn("--agree-disposable-prefix", block)
        self.assertIn("build/netfx40-native-ngen-drain.json", workflow)
        self.assertNotIn("continue-on-error: true", block)


if __name__ == "__main__":
    unittest.main()
