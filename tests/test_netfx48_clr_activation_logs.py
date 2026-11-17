"""Synthetic privacy and lifetime tests for native CLR activation logging."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from scripts import netfx48_clr_activation_logs as logs
from scripts import netfx40_host_api_diagnostic as host


def prefix_fixture(root: Path):
    prefix = root / "prefix"
    (prefix / "drive_c").mkdir(parents=True)
    (prefix / "system.reg").write_text("")
    (prefix / ".swcompat-netfx481-disposable").write_text("")
    wine = root / "wine"
    wine.write_text("synthetic")
    fixture = root / "netfx48_host_activation.exe"
    fixture.write_text("synthetic")
    managed = root / "netfx48_managed_host_check.dll"
    managed.write_text("synthetic")
    return prefix, wine, fixture, managed


class ActivationLogTests(unittest.TestCase):
    def test_original_clr_log_tokens_are_boolean_not_content(self):
        private = (
            b"CLR Loading log for C:\\Users\\private\\secret.exe\n"
            b"Installed Runtime: v4.0.30319 VERSION_ARCHITECTURE: 0\n"
            b"Decided on runtime: v4.0.30319\n"
            b"FunctionCall: LoadRuntime 0x80131702\n"
            b"Error: CLR_E_SHIM_INSTALLROOT, user=private@example.org\n"
        )
        flags = logs.classify_text(private)
        self.assertIsNotNone(flags)
        self.assertTrue(all(flags.values()))
        self.assertEqual(set(flags), set(logs.FLAGS))
        self.assertNotIn("private", json.dumps(flags))
        self.assertNotIn("80131702", json.dumps(flags))
        self.assertNotIn("secret.exe", json.dumps(flags))
        self.assertEqual(logs.classify_text(b"\xff" * 4), None)
        self.assertIsNone(logs.classify_text(b"x" * (logs.MAX_BYTES + 1)))

    def test_unicode_and_non_error_log_are_supported(self):
        raw = b"\xff\xfe" + (
            "CLR Loading log for C:\\private\\name.exe\n"
            "Installed Runtime: v4.0.30319\n").encode("utf-16-le")
        flags = logs.classify_text(raw)
        self.assertTrue(flags["activation_header"])
        self.assertTrue(flags["installed_runtime"])
        self.assertFalse(flags["shim_failure"])
        self.assertFalse(flags["reported_error"])

    def test_no_logs_does_not_mean_success(self):
        with tempfile.TemporaryDirectory() as td:
            folder = Path(td)
            report = logs.inspect(folder, "HOST_START_E_FAIL")
            self.assertEqual(report["status"], "NO_LOG")
            self.assertEqual(report["host"], "HOST_START_E_FAIL")
            self.assertFalse(report["framework48_installed"])
            self.assertTrue(logs.valid(report))
            self.assertFalse(logs.valid(dict(report, leaked_path="Z:\\secret")))

    def test_reject_bounded_file_and_symlink_evidence(self):
        with tempfile.TemporaryDirectory() as td:
            folder = Path(td) / "private"
            folder.mkdir()
            (folder / "large.txt").write_bytes(b"a" * (logs.MAX_BYTES + 1))
            report = logs.inspect(folder, "HOST_START_E_FAIL")
            self.assertEqual(report["status"], "PARTIAL")
            self.assertTrue(logs.valid(report))
            (folder / "large.txt").unlink()
            for i in range(logs.MAX_FILES + 1):
                (folder / ("diag" + str(i))).write_text("private")
            self.assertEqual(logs.inspect(folder, "HOST_START_E_FAIL")["status"],
                             "PARTIAL")
            for item in folder.iterdir():
                item.unlink()
            external = Path(td) / "outside"
            external.write_text("private")
            (folder / "link").symlink_to(external)
            self.assertEqual(logs.inspect(folder, "HOST_START_E_FAIL")["status"],
                             "PARTIAL")

    def test_process_scoped_env_and_private_cleanup(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            prefix, wine, fixture, managed = prefix_fixture(root)
            observed = []
            def fake_execute(w, p, f, m, mode, *, clrload_log_dir=None):
                self.assertEqual(mode, "n")
                self.assertTrue(clrload_log_dir.startswith("C:\\swcompat-clrload-"))
                folder = prefix / "drive_c" / clrload_log_dir[3:]
                self.assertTrue(folder.is_dir())
                (folder / "clrload.log").write_text(
                    "CLR Loading log for C:\\Private\\original.exe\n"
                    "Installed Runtime: v4.0.30319\n"
                    "Error: CLR_E_SHIM_INSTALLROOT\n")
                observed.append(folder)
                return "HOST_START_E_FAIL"
            with mock.patch.object(logs, "host_execute", side_effect=fake_execute):
                report = logs.probe(wine, prefix, fixture, managed, phase="staged")
            self.assertTrue(logs.valid(report))
            self.assertEqual(report["status"], "CAPTURED")
            self.assertEqual(report["file_count"], 1)
            self.assertTrue(report["flags"]["install_root_failure"])
            self.assertEqual(report["host"], "HOST_START_E_FAIL")
            self.assertFalse(report["framework48_installed"])
            self.assertNotIn("Private", json.dumps(report))
            self.assertTrue(all(not p.exists() for p in observed))
            self.assertEqual(list((prefix / "drive_c").glob("swcompat-clrload-*")), [])

    def test_invalid_stage_and_unmarked_prefix_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            prefix, wine, fixture, managed = prefix_fixture(Path(td))
            with self.assertRaises(ValueError):
                logs.probe(wine, prefix, fixture, managed, phase="invalid")
            (prefix / ".swcompat-netfx481-disposable").unlink()
            with self.assertRaises(ValueError):
                logs.probe(wine, prefix, fixture, managed, phase="before")

    def test_host_env_cannot_inherit_injected_log_location(self):
        with tempfile.TemporaryDirectory() as td:
            prefix, wine, fixture, managed = prefix_fixture(Path(td))
            response = (
                b"SWCOMPAT_NETFX48_HOST_SCHEMA=1\n"
                b"SWCOMPAT_NETFX48_HOST_STATUS=MANAGED_ORIGINAL_PASS\n"
            )
            observed = []
            def run(argv, **kwargs):
                observed.append(kwargs["env"].get("COMPLUS_CLRLoadLogDir"))
                kwargs["stdout"].write(response)
                return mock.Mock(returncode=0)
            with mock.patch.object(host.subprocess, "run", side_effect=run), \
                 mock.patch.dict(host.os.environ, {
                     "COMPLUS_CLRLoadLogDir": "Z:\\private\\injected"
                 }):
                self.assertEqual(host.execute(wine, prefix, fixture, managed, "n"),
                                 "MANAGED_ORIGINAL_PASS")
                self.assertEqual(host.execute(
                    wine, prefix, fixture, managed, "n",
                    clrload_log_dir="C:\\swcompat-clrload-abc123"),
                    "MANAGED_ORIGINAL_PASS")
                with self.assertRaises(ValueError):
                    host.execute(
                        wine, prefix, fixture, managed, "n",
                        clrload_log_dir="C:\\Users\\private\\logs")
            self.assertEqual(observed, [None, "C:\\swcompat-clrload-abc123"])


if __name__ == "__main__":
    unittest.main()
