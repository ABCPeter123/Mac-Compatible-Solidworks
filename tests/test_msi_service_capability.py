"""Strict no-leak protocol tests for read-only Windows Installer service probe."""
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase, mock
import os

from scripts import msi_service_capability as msi


def fixture(registry="PRESENT", service="PRESENT", state="STOPPED",
            dll="BOTH_PRESENT", exe="PRESENT") -> bytes:
    return ("\n".join((
        "SWCOMPAT_MSI_SCHEMA=1",
        "SWCOMPAT_MSI_REGISTRY=" + registry,
        "SWCOMPAT_MSI_SERVICE=" + service,
        "SWCOMPAT_MSI_SERVICE_STATE=" + state,
        "SWCOMPAT_MSI_DLL_API=" + dll,
        "SWCOMPAT_MSI_EXEC=" + exe,
    )) + "\n").encode("ascii")


class MSICapabilityTests(TestCase):
    def test_windows_and_wine_fixed_statuses(self):
        self.assertEqual(msi.parse(fixture(), 0), {
            "registry": "PRESENT", "service": "PRESENT",
            "service_state": "STOPPED", "dll_api": "BOTH_PRESENT",
            "exec": "PRESENT"})
        self.assertEqual(msi.parse(fixture(
            registry="ABSENT", service="ABSENT", state="NOT_VERIFIED",
            dll="LOAD_FAILED", exe="ABSENT"), 0)["service"], "ABSENT")
        self.assertTrue(msi.validate(msi.parse(fixture(), 0)))

    def test_bad_reports_fail_closed_and_cannot_leak(self):
        for data, code in (
            (fixture() + b"SWCOMPAT_MSI_REGISTRY=PRESENT\n", 0),
            (fixture() + b"SWCOMPAT_MSI_PRIVATE_PATH=C:\\Users\\Bob\n", 0),
            (fixture().replace(b"STOPPED", b"STARTED_BY_US"), 0),
            (fixture().replace(b"SWCOMPAT_MSI_SCHEMA=1\n", b""), 0),
            (fixture(), 53),
            (fixture() + b"\x00", 0),
            (fixture() + b"x" * 2048, 0),
            (b"\xff" + fixture(), 0),
            (fixture(service="ABSENT", state="RUNNING"), 0),
        ):
            with self.subTest(code=code, sample=data[:16]):
                self.assertEqual(msi.parse(data, code), msi.NO_REPORT)
        self.assertTrue(msi.validate(msi.NO_REPORT))
        leaked = dict(msi.NO_REPORT)
        leaked["exec"] = "C:\\Windows\\System32\\private.exe"
        self.assertFalse(msi.validate(leaked))
        half = dict(msi.NO_REPORT)
        half["registry"] = "PRESENT"
        self.assertFalse(msi.validate(half))

    def test_only_self_authored_fixture_runs_in_disposable_wine(self):
        with TemporaryDirectory(dir=Path.cwd()) as td:
            root = Path(td)
            prefix = root / "prefix"
            (prefix / "drive_c").mkdir(parents=True)
            (prefix / "system.reg").touch()
            (prefix / ".swcompat-netfx481-disposable").touch()
            wine = root / "wine"
            wine.write_bytes(b"mock")
            exe = root / "msi_service_capability.exe"
            exe.write_bytes(b"mock")
            with mock.patch.object(msi.subprocess, "run") as proc:
                def execute(command, **kwargs):
                    self.assertEqual(command[1], str(exe.resolve()))
                    self.assertEqual(kwargs["cwd"], exe.parent)
                    self.assertNotIn("WINEDLLOVERRIDES", kwargs["env"])
                    kwargs["stdout"].write(fixture())
                    return mock.Mock(returncode=0)
                proc.side_effect = execute
                report = msi.run(
                    wine, prefix,
                    Path(os.path.relpath(exe, Path.cwd())))
            self.assertEqual(report["service"], "PRESENT")
            (prefix / ".swcompat-netfx481-disposable").unlink()
            with mock.patch.object(msi.subprocess, "run") as proc:
                with self.assertRaises(ValueError):
                    msi.run(wine, prefix, exe)
                proc.assert_not_called()
            with self.assertRaises(ValueError):
                msi.run(wine, prefix, root / "random.exe")
