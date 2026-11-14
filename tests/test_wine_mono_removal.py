"""MSI-targeted Wine Mono removal, no proprietary binaries or user prefix."""
import os
from pathlib import Path
import tempfile
from unittest import mock
import unittest

from scripts import wine_mono_removal as removal

GUID1 = "{12345678-1234-1234-1234-123456789ABC}"
GUID2 = "{AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA}"


class WineMonoRemovalTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.prefix = self.root / "prefix"
        (self.prefix / "drive_c").mkdir(parents=True)
        (self.prefix / "system.reg").write_text("")
        (self.prefix / ".swcompat-netfx481-disposable").write_text("")
        self.wine = self.root / "wine"
        self.wine.write_text("synthetic")
        self.wine.chmod(0o755)

    def test_only_recognized_mono_products_are_candidates(self):
        data = (GUID1 + "|||Wine Mono Windows Support\n" +
                GUID2 + "|||Wine Mono Runtime\n" +
                "{BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBBBBBB}|||SOLIDWORKS\n").encode()
        self.assertEqual(removal.parse_uninstaller_list(data), tuple(sorted([GUID1, GUID2])))

    def test_wine_native_uninstaller_uses_triple_pipe_not_single(self):
        value = (GUID1 + "|||Wine Mono Windows Support\n").encode()
        self.assertEqual(removal.parse_uninstaller_list(value), (GUID1,))
        with self.assertRaises(ValueError):
            removal.parse_uninstaller_list((GUID1 + "|Wine Mono Windows Support\n").encode())

    def test_reject_malformed_records_unsafe_product_name_and_raw_output(self):
        bad = [
            b"{invalid}|Wine Mono Windows Support\n",
            b"WINE MONO NOT LISTED Wine Mono\n",
            (GUID1 + "|Wine Mono Windows Support of other vendor\n").encode(),
            b"\x00", b"x" * (removal.MAX_LIST_BYTES + 1),
        ]
        for raw in bad:
            with self.subTest(raw=raw[:20]):
                with self.assertRaises(ValueError):
                    removal.parse_uninstaller_list(raw)

    def test_can_uninstall_only_confirmed_mono_msi_and_verify_absence(self):
        before = {"clr_family": "MONO"}
        operations = []
        def run(command, **kwargs):
            operations.append((command, kwargs))
            if command[2] == "--list":
                payload = ((GUID1 + "|||Wine Mono Windows Support\n") if len(operations) == 1
                           else "").encode()
                kwargs["stdout"].write(payload)
            return mock.Mock(returncode=0)
        with mock.patch.object(removal.subprocess, "run", side_effect=run):
            report = removal.remove_mono(self.wine, self.prefix, before)
        self.assertEqual(report, {"before": 1, "after": 0, "action": "REMOVED"})
        self.assertEqual([entry[0][1:] for entry in operations], [
            ["uninstaller", "--list"],
            ["uninstaller", "--remove", GUID1],
            ["uninstaller", "--list"],
        ])
        for _, kwargs in operations:
            self.assertEqual(kwargs["env"]["WINEPREFIX"], str(self.prefix))
            self.assertNotIn("shell", kwargs)

    def test_mono_absent_from_msi_does_not_fake_native_clr(self):
        with mock.patch.object(removal, "inventory", return_value=()):
            self.assertEqual(
                removal.remove_mono(self.wine, self.prefix, {"clr_family": "MONO"})["action"],
                "MONO_NOT_REGISTERED",
            )

    def test_uninstall_failure_is_not_counted_as_ready(self):
        with mock.patch.object(removal, "inventory", return_value=(GUID1,)), \
             mock.patch.object(removal.subprocess, "run", return_value=mock.Mock(returncode=1603)):
            result = removal.remove_mono(self.wine, self.prefix, {"clr_family": "MONO"})
        self.assertEqual(result["action"], "REMOVE_FAILED")

    def test_unmarked_prefix_and_native_clr_do_not_remove_anything(self):
        (self.prefix / ".swcompat-netfx481-disposable").unlink()
        with mock.patch.object(removal.subprocess, "run") as proc:
            with self.assertRaises(ValueError):
                removal.remove_mono(self.wine, self.prefix, {"clr_family": "MONO"})
            proc.assert_not_called()
        (self.prefix / ".swcompat-netfx481-disposable").write_text("")
        with mock.patch.object(removal.subprocess, "run") as proc:
            result = removal.remove_mono(
                self.wine, self.prefix, {"clr_family": "MICROSOFT_CLR_CANDIDATE"}
            )
            self.assertEqual(result["action"], "NOT_APPLICABLE")
            proc.assert_not_called()


if __name__ == "__main__":
    unittest.main()
