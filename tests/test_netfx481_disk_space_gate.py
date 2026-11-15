"""Finite, privacy-safe Windows disk-capacity probe regression tests."""
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import subprocess
from unittest import mock
import unittest

from scripts import netfx481_disk_space_gate as d


def fixture(c="ABOVE_5GB", t="ABOVE_5GB", legacy="ABOVE_5GB", same="YES"):
    return (f"SWCOMPAT_DISK_SCHEMA=1\n"
            f"SWCOMPAT_DISK_C={c}\n"
            f"SWCOMPAT_DISK_TEMP={t}\n"
            f"SWCOMPAT_DISK_LEGACY={legacy}\n"
            f"SWCOMPAT_DISK_TEMP_SAME_VOLUME={same}\n").encode("ascii")


class DiskSpaceTests(unittest.TestCase):
    def test_four_distinct_api_checks(self):
        for value in d.CAPACITIES:
            report = d.parse(fixture(c=value, t=value, legacy=value), 0)
            self.assertTrue(d.valid(report))
            self.assertEqual(report["c_drive"], value)
            self.assertEqual(report["temp"], value)
            self.assertEqual(report["legacy_c"], value)
        self.assertEqual(d.parse(fixture(t="TEMP_PATH_FAILED", same="UNKNOWN"), 0)["status"],
                         "MEASURED")

    def test_never_publish_actual_bytes_or_extra_output(self):
        for raw, code in (
            (fixture() + b"C:\\Users\\private\\secret.txt\n", 0),
            (fixture() + b"SWCOMPAT_DISK_C=BELOW_4P5GB\n", 0),
            (fixture().replace(b"ABOVE_5GB", b"5324294300"), 0),
            (fixture().replace(b"SCHEMA=1", b"SCHEMA=2"), 0),
            (fixture().replace(b"YES", b"PRIVATE"), 0),
            (fixture(), 1),
            (fixture() * 20, 0),
            (b"\x00" + fixture(), 0),
        ):
            self.assertEqual(d.parse(raw, code), d.empty())

    def test_strict_status_and_no_false_success(self):
        self.assertTrue(d.valid(d.empty()))
        self.assertFalse(d.valid(dict(d.empty(), status="MEASURED")))
        self.assertFalse(d.valid(dict(d.empty(), measured_bytes=123)))
        self.assertFalse(d.valid(dict(d.empty(), c_drive="NOT_ENOUGH")))
        self.assertFalse(d.valid(dict(d.empty(), temp_same_volume="C:\\Users\\secret")))

    @unittest.skipIf(os.name == "nt", "Wine wrapper runs only on POSIX")
    def test_disposable_prefix_wrapper(self):
        with TemporaryDirectory() as td:
            p = Path(td)
            wine = p / "wine"
            wine.write_bytes(b"fixture")
            wine.chmod(0o755)
            exe = p / "netfx481_disk_space_gate.exe"
            exe.write_bytes(b"fixture")
            prefix = p / "prefix"
            prefix.mkdir()
            with mock.patch.object(d, "validate_prefix"), mock.patch.object(
                d.subprocess, "run", return_value=subprocess.CompletedProcess(
                    ["fixture"], 0, stdout=fixture(c="BELOW_4P5GB"))
            ) as call:
                result = d.run(wine, prefix, exe)
            self.assertEqual(result["c_drive"], "BELOW_4P5GB")
            self.assertTrue(d.valid(result))
            self.assertEqual(call.call_args.kwargs["stderr"], subprocess.DEVNULL)
            self.assertNotIn("WINEDLLOVERRIDES", call.call_args.kwargs["env"])
            with self.assertRaises(ValueError):
                d.run(wine, prefix, exe, timeout=100)


if __name__ == "__main__":
    unittest.main()
