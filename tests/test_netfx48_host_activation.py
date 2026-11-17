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

    def test_read_only_clr_loadability_precheck_is_bounded(self):
        source = (Path(__file__).resolve().parents[1] /
                  "probes/netfx48_host_activation.c").read_text(encoding="utf-8")
        statuses = (
            "PRECHECK_LOADABLE_FAILED", "PRECHECK_STARTED_FAILED",
            "PRECHECK_LOADABLE_ALREADY_STARTED",
            "PRECHECK_LOADABLE_NOT_STARTED",
            "PRECHECK_UNLOADABLE_ALREADY_STARTED",
            "PRECHECK_UNLOADABLE_NOT_STARTED",
        )
        for status in statuses:
            with self.subTest(status=status):
                self.assertIn('RESULT("' + status + '")', source)
                self.assertIn(status, t.HOST_STATES)
                self.assertEqual(t.parse_host(host_output(status), 0), status)
        self.assertIn("ICLRRuntimeInfo_IsLoadable(info, &loadable)", source)
        self.assertIn("ICLRRuntimeInfo_IsStarted(info, &started, &flags)", source)
        self.assertLess(source.index("ICLRRuntimeInfo_IsLoadable"),
                        source.index("ICLRRuntimeInfo_GetInterface"))
        self.assertEqual(t.parse_host(host_output("PRECHECK_LOADABLE_0x80004005"), 0),
                         "PROBE_ERROR")

    def test_start_hresult_categories_are_bounded_and_never_raw(self):
        source = (Path(__file__).resolve().parents[1] /
                  "probes/netfx48_host_activation.c").read_text(encoding="utf-8")
        statuses = (
            "HOST_START_E_FAIL", "HOST_START_NOT_IMPLEMENTED",
            "HOST_START_UNEXPECTED", "HOST_START_ACCESS_DENIED",
            "HOST_START_OUT_OF_MEMORY", "HOST_START_INVALID_ARGUMENT",
            "HOST_START_MISSING_MODULE", "HOST_START_MISSING_EXPORT",
            "HOST_START_BAD_IMAGE", "HOST_START_WIN32_NOT_IMPLEMENTED",
            "HOST_START_WIN32_NOT_SUPPORTED", "HOST_START_CLR_FACILITY",
            "HOST_START_WIN32_FACILITY", "HOST_START_OTHER",
        )
        for status in statuses:
            with self.subTest(status=status):
                self.assertIn('RESULT("' + status + '")', source)
                self.assertIn(status, t.HOST_STATES)
                self.assertEqual(t.parse_host(host_output(status), 0), status)
        self.assertIn("HRESULT_FROM_WIN32(ERROR_MOD_NOT_FOUND)", source)
        self.assertIn("HRESULT_FROM_WIN32(ERROR_CALL_NOT_IMPLEMENTED)", source)
        self.assertEqual(t.parse_host(host_output("HOST_START_80004005"), 0),
                         "PROBE_ERROR")
        self.assertNotIn("WriteFile(out, &hr", source)
        self.assertNotIn("printf(", source)

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

    def test_original_shim_schema_rejects_unrelated_or_unstaged_success(self):
        blank = t.blank()
        self.assertTrue(t.valid(blank))
        self.assertFalse(t.valid(dict(blank, original_shim_host="MANAGED_ORIGINAL_PASS")))
        self.assertFalse(t.valid(dict(blank, original_shim_process="EXIT_ZERO")))
        self.assertFalse(t.valid(dict(blank, original_shim_staging=dict(
            blank["original_shim_staging"], original_vendor_path="private"))))
        self.assertIn("ORIGINAL_SHIM_LOAD_FAILED", t.HOST_STATES)
        self.assertIn("ORIGINAL_SHIM_NO_HOST_EXPORT", t.HOST_STATES)
        self.assertIn("ORIGINAL_SHIM_MISSING", t.HOST_STATES)
        self.assertEqual(t.parse_host(host_output("ORIGINAL_SHIM_NO_HOST_EXPORT"), 0),
                         "ORIGINAL_SHIM_NO_HOST_EXPORT")

    def test_missing_original_shim_dependencies_are_never_synthetic_success(self):
        blank = t.blank()
        self.assertTrue(t.valid(blank))
        for status in (
                "ORIGINAL_SHIM_MISSING_DEPENDENCY",
                "ORIGINAL_SHIM_MISSING_EXPORT",
                "ORIGINAL_SHIM_BAD_IMAGE",
                "ORIGINAL_SHIM_INIT_FAILED",
                "ORIGINAL_SHIM_ACCESS_DENIED"):
            with self.subTest(status=status):
                self.assertEqual(t.parse_host(host_output(status), 0), status)
        self.assertFalse(t.valid(dict(blank, original_shim_reused=1)))
        self.assertFalse(t.valid(dict(blank, original_shim_retry="MANAGED_ORIGINAL_PASS",
                                      original_shim_retry_process="EXIT_ZERO",
                                      managed_executed=True)))
        self.assertFalse(t.valid(dict(blank, original_shim_direct_imports=dict(
            blank["original_shim_direct_imports"], original_filename="private.dll"))))
        self.assertFalse(t.valid(dict(blank, original_shim_dependency_stage=dict(
            blank["original_shim_dependency_stage"], original_path="private"))))
        self.assertFalse(t.valid(dict(blank, original_shim_retry="ORIGINAL_SHIM_MISSING_EXPORT",
                                      original_shim_retry_process="EXIT_ZERO")))
        self.assertEqual(blank["original_shim_dependency_stage"]["status"], "NOT_RUN")
        self.assertEqual(blank["original_shim_direct_imports"]["status"], "NOT_RUN")

    def test_native_runtime_identity_guard_uses_equal_counted_directories(self):
        source = (Path(__file__).resolve().parents[1]
                  / "probes/netfx48_host_activation.c").read_text(encoding="utf-8")
        # Comparing a whole zero-terminated path to the prefix of a longer
        # filename is not a valid CLR provenance test. The known-good native
        # Windows runtime must pass; unrelated CLR directories must not.
        self.assertIn("i != slash", source)
        self.assertIn("CompareStringOrdinal(runtime_dir, (int)i, mapped_path, (int)slash, TRUE)",
                      source)
        self.assertNotIn("CompareStringOrdinal(runtime_dir, -1,", source)
        self.assertLess(source.index("CompareStringOrdinal(runtime_dir"),
                        source.index("hr = ICLRRuntimeInfo_GetInterface(info"))
        self.assertIn('RESULT("OTHER_RUNTIME_SELECTED")', source)

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
                self.assertEqual(Path(argv[1]).resolve(), fixture.resolve())
                self.assertEqual(kwargs["env"]["WINEDLLOVERRIDES"], "clr=n")
                self.assertIn("clr.dll", kwargs["env"]["SWCOMPAT_CLR_PATH"])
                kwargs["stdout"].write(host_output("RUNTIME_DISCOVERY_FAILED"))
                return mock.Mock(returncode=0)
            shim = root / "mscoreei.dll"
            shim.write_bytes(b"synthetic")
            def original_shim_case(argv, **kwargs):
                self.assertEqual(kwargs["env"]["WINEDLLOVERRIDES"], "clr=n")
                self.assertIn("mscoreei.dll", kwargs["env"]["SWCOMPAT_ORIGINAL_SHIM_PATH"])
                kwargs["stdout"].write(host_output("ORIGINAL_SHIM_NO_HOST_EXPORT"))
                return mock.Mock(returncode=0)
            def shim_only_case(argv, **kwargs):
                self.assertEqual(kwargs["env"]["SWCOMPAT_SHIM_ONLY"], "1")
                self.assertIn("mscoreei.dll", kwargs["env"]["SWCOMPAT_ORIGINAL_SHIM_PATH"])
                kwargs["stdout"].write(host_output("ORIGINAL_SHIM_INIT_FAILED"))
                return mock.Mock(returncode=0)
            with mock.patch.object(t.subprocess, "run", side_effect=shim_only_case):
                self.assertEqual(t.host_check(root/"wine", prefix, fixture, managed, dll,
                                              original_shim=shim, shim_only=True),
                                 ("ORIGINAL_SHIM_INIT_FAILED", "EXIT_ZERO"))
            with self.assertRaises(ValueError):
                t.host_check(root/"wine", prefix, fixture, managed, dll, shim_only=True)
            with mock.patch.object(t.subprocess, "run", side_effect=original_shim_case):
                self.assertEqual(t.host_check(root/"wine", prefix, fixture, managed, dll,
                                              original_shim=shim),
                                 ("ORIGINAL_SHIM_NO_HOST_EXPORT", "EXIT_ZERO"))
            with mock.patch.object(t.subprocess, "run", side_effect=success):
                self.assertEqual(t.host_check(root/"wine", prefix, fixture, managed, dll),
                                 ("RUNTIME_DISCOVERY_FAILED", "EXIT_ZERO"))
            with mock.patch.object(t.subprocess, "run",
                                   side_effect=__import__("subprocess").TimeoutExpired("wine", 1)):
                self.assertEqual(t.host_check(root/"wine", prefix, fixture, managed, dll),
                                 ("TIMEOUT", "TIMEOUT"))


if __name__ == "__main__":
    unittest.main()
