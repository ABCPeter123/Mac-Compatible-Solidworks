"""No Microsoft media or installation in these direct .NET 4.8 safety tests."""
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest import mock

from scripts import netfx40_to_48_direct as p
from scripts import netfx481_win32_exit as win32
from scripts import netfx481_setup_evidence as evidence
from scripts.netfx481_prereq_diagnostic import empty as empty_prerequisite


class DirectNative48Tests(unittest.TestCase):
    @staticmethod
    def setup(exit_hex="00000000", category="SUCCESS", lifecycle="ALL_EXITED"):
        return {
            "status": "EXIT_CAPTURED", "exit_hex": exit_hex,
            "category": category, "child_seen": "OBSERVED",
            "child_lifecycle": lifecycle,
            "child_exit": "ALL_ZERO" if lifecycle == "ALL_EXITED" else "NOT_VERIFIED",
        }

    @staticmethod
    def secondary():
        return {
            "status": "NOT_FOUND", "files_scanned": 0,
            "prerequisite_files": 0, "stage_files": 0,
            "stage_scope": "CAPTURED",
            "sources": {name: 0 for name in evidence.SECONDARY_SOURCE_NAMES},
            "phase": "UNKNOWN", "codes": [],
            "prerequisite": empty_prerequisite("NOT_FOUND"),
            "stage_prerequisite": empty_prerequisite("NOT_FOUND"),
        }

    @staticmethod
    def fixture(root):
        prefix = root / "prefix"
        prefix.mkdir()
        names = ("wine", "NDP48-x86-x64-AllOS-ENU.exe", "netfx48.sha256",
                 "netfx48_win32_launch.exe", "netfx481_clr_load.exe",
                 "netfx481_runtime_probe.exe")
        paths = [root / n for n in names]
        for path in paths:
            path.write_text("synthetic")
        return (paths[0], prefix, *paths[1:])

    def run_case(self, root, *, setup=None, changed=True, registry="NETFX48_RANGE"):
        args = self.fixture(root)
        fake_setup = setup or self.setup()
        diff = {"changes": {"CLR64": "CHANGED" if changed else "UNCHANGED"}}
        with (
            mock.patch.object(p, "validate_prefix"),
            mock.patch.object(p, "verify_original_media"),
            mock.patch.object(p, "validate_native40", return_value=True),
            mock.patch.object(p, "inspect_registrations", return_value={
                "native64": "OLDER_RELEASE", "wow32": "AT_LEAST_481",
                "native64_version": "V4_0", "wow32_version": "V4_7_PLUS"}),
            mock.patch.object(p, "inventory_services", return_value={
                "TrustedInstaller": "ABSENT", "msiserver": "PRESENT",
                "wuauserv": "PRESENT", "BITS": "UNKNOWN"}),
            mock.patch.object(p, "snapshot", return_value={"CLR64": ("PE_AMD64", "fake")}),
            mock.patch.object(p, "compare", return_value=diff),
            mock.patch.object(p, "load_clr", return_value="LOADED"),
            mock.patch.object(p, "probe", return_value={
                "clr_family": "MICROSOFT_CLR_CANDIDATE", "managed": "PASS"}),
            mock.patch.object(p, "_set_winver", return_value="APPLIED"),
            mock.patch.object(p, "_release", return_value=registry),
            mock.patch.object(p, "private_setup_log", return_value=root / "private"),
            mock.patch.object(p, "classify_log", return_value={
                "status": "CLASSIFIED", "phase": "UNKNOWN", "codes": []}),
            mock.patch.object(p, "discard_log"),
            mock.patch.object(p, "classify_primary_prerequisite", return_value={
                "status": "CLASSIFIED", "os_versions": ["BELOW_WINDOWS_10"],
                "blockers": ["MISSING_UPDATE_BLOCK"],
                "5100_in_log": True}) as primary_scan,
            mock.patch.object(p, "snapshot_secondary_logs", return_value={}),
            mock.patch.object(p, "scan_secondary_logs", return_value=self.secondary()) as secondary_scan,
            mock.patch.object(p, "wineboot_restart", return_value="COMPLETED"),
            mock.patch.object(p, "launch", return_value=fake_setup) as started,
        ):
            result = p.inspect(*args, {"persistent_native_managed": True})
        self.assertTrue(p.validate(result))
        self.assertEqual(started.call_args.kwargs["setup_family"], "NETFX48")
        self.assertEqual(secondary_scan.call_args.kwargs["family"], "NETFX48")
        self.assertEqual(primary_scan.call_count, 1)
        self.assertEqual(primary_scan.call_args.kwargs["family"], "NETFX48")
        self.assertEqual(result["primary_prerequisite"]["blockers"], ["MISSING_UPDATE_BLOCK"])
        self.assertTrue(result["primary_prerequisite"]["5100_in_log"])
        self.assertTrue(evidence.validate_secondary_report(result["secondary_evidence"]))
        self.assertEqual(result["service_prerequisites"]["TrustedInstaller"], "ABSENT")
        self.assertEqual(result["registry_preflight"]["native64"], "OLDER_RELEASE")
        self.assertEqual(result["registry_preflight"]["wow32"], "AT_LEAST_481")
        self.assertTrue(p.valid_services(result["service_prerequisites"]))
        self.assertTrue(started.call_args.kwargs["fusion_builtin"])
        self.assertNotIn(str(root), str(result))
        return result

    @unittest.skipIf(os.name == "nt", "POSIX Wine experiment")
    def test_real_exit_native_clr_and_48_release_all_required(self):
        with TemporaryDirectory() as td:
            result = self.run_case(Path(td))
            self.assertTrue(result["native48_candidate"])
            self.assertFalse(result["framework481_confirmed"])
            self.assertFalse(p.validate(dict(result, framework481_confirmed=True)))
            self.assertFalse(p.validate(dict(result, private_text="PRIVATE")))

    @unittest.skipIf(os.name == "nt", "POSIX Wine experiment")
    def test_failure_timeout_registry_and_unchanged_clr_not_ready(self):
        with TemporaryDirectory() as td:
            for index, attrs in enumerate((
                {"changed": False},
                {"registry": "NOT_FOUND"},
                {"registry": "AT_LEAST_481"},
                {"setup": self.setup("000013EC", "PREREQUISITE_BLOCK_5100")},
                {"setup": win32.blank("TIMEOUT")},
            )):
                root = Path(td) / str(index)
                root.mkdir()
                with self.subTest(attrs=attrs):
                    self.assertFalse(self.run_case(root, **attrs)["native48_candidate"])

    @unittest.skipIf(os.name == "nt", "POSIX Wine experiment")
    def test_prior_native_40_gate_prevents_installation(self):
        with TemporaryDirectory() as td:
            args = self.fixture(Path(td))
            with (
                mock.patch.object(p, "validate_prefix"),
                mock.patch.object(p, "verify_original_media"),
                mock.patch.object(p, "validate_native40", return_value=True),
                mock.patch.object(p, "launch") as launch,
            ):
                result = p.inspect(*args, {"persistent_native_managed": False})
            self.assertEqual(result, p.blank())
            launch.assert_not_called()

    @unittest.skipIf(os.name == "nt", "POSIX Wine experiment")
    def test_48_secondary_report_must_be_finite_and_current(self):
        with TemporaryDirectory() as td:
            result = self.run_case(Path(td))
            corrupt = dict(result)
            corrupt["secondary_evidence"] = dict(
                result["secondary_evidence"], private_log="C:\\Users\\sensitive")
            self.assertFalse(p.validate(corrupt))
            corrupt["secondary_evidence"] = None
            self.assertFalse(p.validate(corrupt))
            corrupt = dict(result)
            corrupt["primary_prerequisite"] = dict(
                result["primary_prerequisite"], private_path="SECRET")
            self.assertFalse(p.validate(corrupt))
            corrupt["primary_prerequisite"] = dict(
                result["primary_prerequisite"], blockers=["COPY_OF_RAW_LINE"])
            self.assertFalse(p.validate(corrupt))

    def test_sc_query_bounded_read_only_service_inventory(self):
        with TemporaryDirectory() as td:
            root = Path(td)
            prefix = root / "prefix"
            prefix.mkdir()
            wine = root / "wine"
            wine.write_bytes(b"synthetic")
            called = []

            def fake_run(argv, **kwargs):
                name = argv[-1]
                called.append(name)
                self.assertEqual(argv, [str(wine), "sc", "query", name])
                self.assertEqual(kwargs["env"]["WINEPREFIX"], str(prefix))
                self.assertEqual(kwargs["env"]["WINEDEBUG"], "-all")
                self.assertNotIn("WINEDLLOVERRIDES", kwargs["env"])
                self.assertEqual(kwargs["timeout"], 15)
                if name == "TrustedInstaller":
                    kwargs["stdout"].write(
                        b"[SC] OpenService FAILED 1060: "
                        b"The specified service does not exist\n"
                        b"Private path: C:\\Users\\secret\\installer.exe\n")
                    return mock.Mock(returncode=1)
                if name == "msiserver":
                    kwargs["stdout"].write(b"SERVICE_NAME: msiserver\n")
                    return mock.Mock(returncode=0)
                if name == "wuauserv":
                    kwargs["stdout"].write(b"SERVICE_NAME: wuauserv\n")
                    return mock.Mock(returncode=0)
                kwargs["stdout"].write(b"Failed without a known error\n")
                return mock.Mock(returncode=1)

            with mock.patch.object(p, "validate_prefix"), \
                 mock.patch.object(p.subprocess, "run", side_effect=fake_run), \
                 mock.patch.dict(p.os.environ, {
                     "WINEDLLOVERRIDES": "mscoree=b",
                 }):
                result = p.inventory_services(wine, prefix)
            self.assertEqual(called, list(p.SERVICE_NAMES))
            self.assertEqual(result, {
                "TrustedInstaller": "ABSENT", "msiserver": "PRESENT",
                "wuauserv": "PRESENT", "BITS": "UNKNOWN",
            })
            self.assertTrue(p.valid_services(result))
            self.assertNotIn("secret", str(result))
            self.assertFalse(p.valid_services(
                dict(result, private_path="C:\\Users\\secret")))
            self.assertFalse(p.valid_services(
                dict(result, TrustedInstaller="error 1060 C:\\secret")))

    def test_sc_query_timeout_does_not_invent_service_absence(self):
        with TemporaryDirectory() as td:
            root = Path(td)
            wine = root / "wine"
            wine.write_bytes(b"fixture")
            prefix = root / "prefix"
            prefix.mkdir()
            with mock.patch.object(p, "validate_prefix"), \
                 mock.patch.object(p.subprocess, "run",
                                   side_effect=p.subprocess.TimeoutExpired("sc", 15)):
                result = p.inventory_services(wine, prefix)
            self.assertTrue(all(value == "UNKNOWN" for value in result.values()))
            self.assertTrue(p.valid_services(result))

    def test_requires_exact_sha_and_original_media_name(self):
        with TemporaryDirectory() as td:
            root = Path(td)
            installer = root / "NDP48-x86-x64-AllOS-ENU.exe"
            installer.write_bytes(b"test")
            digest = root / "netfx48.sha256"
            digest.write_text("not-a-valid-sha")
            with self.assertRaises(ValueError):
                p.verify_original_media(installer, digest)
            with self.assertRaises(ValueError):
                p.verify_original_media(root / "user-installer.exe", digest)

    def test_only_finite_original_setup_evidence_survives(self):
        outcome = p.blank()
        outcome["setup_evidence"] = {
            "status": "CLASSIFIED", "phase": "UNKNOWN", "codes": ["PRIVATE_DATA"]}
        self.assertFalse(p.validate(outcome))
        outcome = p.blank()
        self.assertTrue(p.validate(outcome))
        self.assertFalse(p.validate(dict(outcome, custom="private path")))

    def test_4_8_family_must_match_compiled_monitor_and_installer(self):
        with TemporaryDirectory() as td:
            root = Path(td)
            prefix = root / "prefix"
            (prefix / "drive_c").mkdir(parents=True)
            (prefix / "system.reg").write_text("")
            (prefix / ".swcompat-netfx481-disposable").write_text("")
            wine = root / "wine"
            wine.write_text("test")
            native48 = root / "NDP48-x86-x64-AllOS-ENU.exe"
            native48.write_text("test")
            monitor = root / "netfx48_win32_launch.exe"
            monitor.write_text("test")
            with mock.patch.object(win32.subprocess, "run") as child:
                with self.assertRaises(ValueError):
                    win32.launch(wine, prefix, native48, monitor)
                with self.assertRaises(ValueError):
                    win32.launch(wine, prefix, native48, monitor,
                                 setup_family="ARBITRARY")
                child.assert_not_called()


if __name__ == "__main__":
    unittest.main()
