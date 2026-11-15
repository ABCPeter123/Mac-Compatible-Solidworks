"""Safety and negative-control semantics for native Wine DISM servicing."""
import os
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase, main, mock
import subprocess

from scripts import netfx481_dism_contract as dism


class DismContractTests(TestCase):
    def test_real_dism_zero_on_missing_package_is_false_success_not_install(self):
        with TemporaryDirectory() as td:
            p = Path(td)
            wine = p / "wine"
            wine.write_text("self-authored fixture")
            wine.chmod(0o700)
            prefix = p / "prefix"
            (prefix / "drive_c").mkdir(parents=True)
            with (mock.patch.object(dism, "validate_prefix"),
                  mock.patch.object(dism.os, "name", "posix"),
                  mock.patch.object(dism.subprocess, "run",
                                    return_value=subprocess.CompletedProcess([], 0)) as invoke):
                r = dism.run(wine, prefix)
            self.assertEqual(r["status"], "DISM_FALSE_SUCCESS")
            self.assertFalse(r["genuine481_servicing_proven"])
            self.assertTrue(dism.validate(r))
            cmd = invoke.call_args.args[0]
            self.assertIn("/Add-Package", cmd)
            self.assertIn("/PackagePath:" + dism.CAB, cmd)
            self.assertEqual(invoke.call_args.kwargs["stdout"], subprocess.DEVNULL)
            self.assertEqual(invoke.call_args.kwargs["stderr"], subprocess.DEVNULL)

    def test_real_dism_failure_on_missing_package_is_correct(self):
        with TemporaryDirectory() as td:
            p = Path(td)
            wine = p / "wine"
            wine.write_bytes(b"fixture")
            wine.chmod(0o700)
            prefix = p / "prefix"
            (prefix / "drive_c").mkdir(parents=True)
            with (mock.patch.object(dism, "validate_prefix"),
                  mock.patch.object(dism.os, "name", "posix"),
                  mock.patch.object(dism.subprocess, "run",
                                    return_value=subprocess.CompletedProcess([], 87))):
                r = dism.run(wine, prefix)
            self.assertEqual(r["status"], "DISM_REJECTED_MISSING_CAB")
            self.assertFalse(r["genuine481_servicing_proven"])

    def test_refuses_nonempty_target_and_fake_positive_results(self):
        with TemporaryDirectory() as td:
            p = Path(td)
            wine = p / "wine"
            wine.write_bytes(b"fixture")
            wine.chmod(0o700)
            prefix = p / "prefix"
            (prefix / "drive_c" / "swcompat_probe_missing").mkdir(parents=True)
            with (mock.patch.object(dism, "validate_prefix"),
                  mock.patch.object(dism.os, "name", "posix"),
                  mock.patch.object(dism.subprocess, "run") as run):
                r = dism.run(wine, prefix)
            self.assertEqual(r["status"], "REFUSED_NONEMPTY_TARGET")
            run.assert_not_called()
        self.assertFalse(dism.validate(dict(dism.blank(), genuine481_servicing_proven=True)))
        self.assertFalse(dism.validate(dict(dism.blank(), vendor_path="PRIVATE")))

if __name__ == "__main__":
    main()
