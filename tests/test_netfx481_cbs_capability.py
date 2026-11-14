"""Synthetic Windows servicing API evidence, no Microsoft binaries."""
import tempfile
from pathlib import Path
import unittest
from unittest import mock

from scripts import netfx481_cbs_capability as cbs
from scripts.netfx481_trial import SENTINEL


def valid(registry="PRESENT", packages="PRESENT", service="PRESENT", dism="EXPORT_PRESENT"):
    return ("\n".join([
        "SWCOMPAT_CBS_SCHEMA=1",
        "SWCOMPAT_CBS_REGISTRY=" + registry,
        "SWCOMPAT_CBS_PACKAGES=" + packages,
        "SWCOMPAT_CBS_TRUSTEDINSTALLER=" + service,
        "SWCOMPAT_CBS_DISMAPI=" + dism,
    ]) + "\n").encode("ascii")


class CBSProbeTests(unittest.TestCase):
    def test_complete_reference_and_wine_absence(self):
        expected = cbs.parse(valid(), 0)
        self.assertEqual(expected, {
            "registry": "PRESENT", "packages": "PRESENT",
            "trustedinstaller": "PRESENT", "dismapi": "EXPORT_PRESENT",
        })
        observed = cbs.parse(valid(registry="ABSENT", packages="ABSENT",
                                   service="ABSENT", dism="ABSENT"), 0)
        self.assertTrue(cbs.validate(observed))
        self.assertEqual(observed["registry"], "ABSENT")

    def test_unknown_partial_and_extra_fields_fail_closed(self):
        for text in [
            valid() + valid(),
            valid().replace(b"SWCOMPAT_CBS_SCHEMA=1\n", b""),
            valid().replace(b"SWCOMPAT_CBS_DISMAPI=EXPORT_PRESENT",
                            b"SWCOMPAT_CBS_DISMAPI=SUPER_NATIVE"),
            valid() + b"SWCOMPAT_CBS_PATH=C:\\Users\\private\n",
            valid() + b"\x00",
            b"\xff" + valid(),
            valid() * 100,
        ]:
            with self.subTest(text=text[:20]):
                self.assertEqual(cbs.parse(text, 0), cbs.blank())
        self.assertEqual(cbs.parse(valid(), 1), cbs.blank())
        self.assertTrue(cbs.validate(cbs.blank()))

    def test_only_disposable_prefix_can_run_external_windows_fixture(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            prefix = root / "prefix"
            (prefix / "drive_c").mkdir(parents=True)
            (prefix / "system.reg").write_text("")
            exe = root / "netfx481_cbs_capability.exe"
            exe.write_bytes(b"synthetic")
            wine = root / "wine"
            wine.write_bytes(b"synthetic")
            with mock.patch.object(cbs.subprocess, "run") as process:
                with self.assertRaises(ValueError):
                    cbs.run(wine, prefix, exe)
                process.assert_not_called()
            (prefix / SENTINEL).write_text("")
            with mock.patch.object(cbs.subprocess, "run") as process:
                def execute(command, **kwargs):
                    # Windows Path.resolve() expands 8.3 path aliases, so
                    # compare with the canonical executable, not the temp alias.
                    self.assertEqual(command, [str(wine), str(exe.resolve())])
                    self.assertEqual(kwargs["env"]["WINEPREFIX"], str(prefix))
                    self.assertNotIn("WINEDLLOVERRIDES", kwargs["env"])
                    kwargs["stdout"].write(valid(registry="ABSENT"))
                    return mock.Mock(returncode=0)
                process.side_effect = execute
                result = cbs.run(wine, prefix, exe)
            self.assertEqual(result["registry"], "ABSENT")

    def test_fixed_report_does_not_expose_strings(self):
        result = cbs.parse(valid(registry="UNAVAILABLE", dism="LOAD_FAILED"), 0)
        import json
        output = json.dumps(result)
        self.assertNotIn("C:\\", output)
        self.assertNotIn("TrustedInstaller.exe", output)
        self.assertNotIn("HKEY", output)
        unsafe = dict(result)
        unsafe["dismapi"] = "C:\\Windows\\sensitive"
        self.assertFalse(cbs.validate(unsafe))


    def test_cbs_probe_resolves_relative_build_exe_before_changing_cwd(self):
        # In prior CI, run(build/fixture.exe) with cwd=build/ attempted
        # build/build/fixture.exe and produced Unix 53 with no protocol.
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            root = Path(temp)
            prefix = root / "prefix"
            (prefix / "drive_c").mkdir(parents=True)
            (prefix / "system.reg").write_text("")
            (prefix / SENTINEL).write_text("")
            exe = root / "netfx481_cbs_capability.exe"
            exe.write_bytes(b"synthetic")
            relative = exe.relative_to(Path.cwd())
            wine = root / "wine"
            wine.write_bytes(b"synthetic")
            with mock.patch.object(cbs.subprocess, "run") as process:
                def execute(command, **kwargs):
                    self.assertEqual(command[1], str(exe))
                    self.assertEqual(kwargs["cwd"], exe.parent)
                    kwargs["stdout"].write(valid(registry="ABSENT"))
                    return mock.Mock(returncode=0)
                process.side_effect = execute
                result = cbs.run(wine, prefix, relative)
            self.assertEqual(result["registry"], "ABSENT")
            process.assert_called_once()


if __name__ == "__main__":
    unittest.main()
