"""Never leak original custom-action DLL bytes or identifiers in test reports."""
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest import mock
from scripts import msi_original_binary_imports as p


def markers(machine="AMD64", status="PARSED", imports=None):
    counts = {name: 0 for name in p.FAMILIES}
    counts.update(imports or {})
    lines = {"STATUS": status, "MACHINE": machine, **counts}
    return "".join(f"SWCOMPAT_BINARY_{k}={v}\r\n" for k, v in lines.items()).encode()


class OriginalBinaryImportTests(unittest.TestCase):
    def test_strict_positive_import_categories(self):
        report = p.parse(markers(imports={"ADVAPI32": 1, "KERNEL32": 1,
                                          "MSCOREE": 1, "OTHER": 2}), 0)
        self.assertEqual(report["status"], "PARSED")
        self.assertEqual(report["machine"], "AMD64")
        self.assertEqual(report["imports"]["MSCOREE"], 1)
        self.assertFalse(report["native_microsoft_clr"])
        self.assertTrue(p.validate(report))

    def test_reject_bad_protocol_and_unbounded_counts(self):
        raw = markers()
        for candidate in (raw + b"SECRET=HIDDEN\n", raw + raw,
                          raw.replace(b"AMD64", b"USER_PRIVATE"),
                          raw.replace(b"ADVAPI32=0", b"ADVAPI32=999999"),
                          raw[:-20], b""):
            self.assertEqual(p.parse(candidate, 0)["status"], "MALFORMED")
        self.assertEqual(p.parse(raw, 1)["status"], "PROCESS_FAILED")
        self.assertEqual(p.parse(raw * 200, 0)["status"], "MALFORMED")

    def test_nonparsed_never_reports_partial_imports(self):
        r = p.parse(markers(machine="AMD64", status="STREAM_FAILED",
                            imports={"ADVAPI32": 1}), 0)
        self.assertEqual(r, p.empty("STREAM_FAILED"))
        self.assertFalse(p.validate(dict(r, native_microsoft_clr=True)))
        self.assertFalse(p.validate(dict(r, original_dll_bytes="PRIVATE")))

    @unittest.skipIf(os.name == "nt", "POSIX Wine wrapper")
    def test_private_identifier_always_deleted(self):
        with TemporaryDirectory() as td:
            root = Path(td)
            prefix = root / "prefix"
            win_temp = prefix / "drive_c" / "windows" / "temp"
            win_temp.mkdir(parents=True)
            wine = root / "wine"
            wine.write_text("fixture")
            wine.chmod(0o755)
            helper = root / "msi_original_binary_imports.exe"
            helper.write_bytes(b"self-authored test helper")
            msi = root / "test.msi"
            msi.write_bytes(b"self-authored original MSI simulation")
            def subprocess_result(*args, **kwargs):
                self.assertEqual((win_temp / "swcompat_ca_action_private.input").read_bytes(),
                                 b"PrivateOriginal_1")
                (win_temp / "swcompat_ca_binary_probe.status").write_bytes(
                    markers(imports={"KERNEL32": 1}))
                return mock.Mock(returncode=0)
            with mock.patch.object(p, "validate_prefix"), \
                 mock.patch.object(p, "windows_media_path", return_value="Z:\\test.msi"), \
                 mock.patch.object(p.subprocess, "run", side_effect=subprocess_result):
                r = p.inspect(wine, prefix, helper, msi, "PrivateOriginal_1")
            self.assertEqual(r["status"], "PARSED")
            self.assertFalse((win_temp / "swcompat_ca_action_private.input").exists())
            self.assertFalse((win_temp / "swcompat_ca_binary_probe.status").exists())
            self.assertNotIn("PrivateOriginal", str(r))
            with self.assertRaises(ValueError):
                p.inspect(wine, prefix, helper, msi, "../secret")


if __name__ == "__main__":
    unittest.main()
