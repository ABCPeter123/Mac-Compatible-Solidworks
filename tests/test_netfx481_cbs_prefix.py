"""Test fixed, read-only Wine CBS registry and servicing disk inventory."""
import json
from pathlib import Path
import tempfile
from unittest import TestCase, mock

from scripts import netfx481_cbs_prefix as cbs
from scripts.netfx481_trial import SENTINEL


class PrefixCBSInventoryTests(TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.prefix = self.root / "prefix"
        (self.prefix / "drive_c" / "windows" / "system32").mkdir(parents=True)
        (self.prefix / "system.reg").write_text("")
        self.wine = self.root / "wine"
        self.wine.write_text("synthetic")

    def test_requires_marked_prefix(self):
        with mock.patch.object(cbs, "_reg") as reg:
            with self.assertRaises(ValueError):
                cbs.inspect(self.wine, self.prefix)
            reg.assert_not_called()

    def test_enumerates_only_fixed_keys_and_no_raw_registry_data(self):
        (self.prefix / SENTINEL).write_text("")
        with mock.patch.object(cbs, "_reg", return_value="ABSENT") as queried:
            result = cbs.inspect(self.wine, self.prefix)
        self.assertEqual(result["cbs_registry"], "ABSENT")
        self.assertEqual(result["packages_directory"], "ABSENT")
        self.assertEqual(result["trustedinstaller_service_registration"], "ABSENT")
        self.assertEqual(result["dismapi_disk_file"], "ABSENT")
        self.assertTrue(cbs.validate(result))
        self.assertEqual(queried.call_count, 2)
        self.assertEqual([call.args[2] for call in queried.call_args_list],
                         [cbs.CBS_KEY, cbs.SERVICE_KEY])
        payload = json.dumps(result)
        self.assertNotIn(self.temp.name, payload)
        self.assertNotIn("TrustedInstaller", payload)
        self.assertNotIn("HKLM", payload)

    def test_disk_presence_and_symlink_rejection(self):
        (self.prefix / SENTINEL).write_text("")
        packages = self.prefix / "drive_c" / "windows" / "servicing" / "Packages"
        packages.mkdir(parents=True)
        dism = self.prefix / "drive_c" / "windows" / "system32" / "dismapi.dll"
        dism.write_bytes(b"not an original PE")
        with mock.patch.object(cbs, "_reg", return_value="PRESENT"):
            state = cbs.inspect(self.wine, self.prefix)
        self.assertEqual(state["packages_directory"], "PRESENT")
        self.assertEqual(state["dismapi_disk_file"], "NON_PE_FILE")
        dism.unlink()
        try:
            dism.symlink_to(self.prefix / "system.reg")
        except (OSError, NotImplementedError):
            return
        with mock.patch.object(cbs, "_reg", return_value="PRESENT"):
            self.assertEqual(cbs.inspect(self.wine, self.prefix)["dismapi_disk_file"],
                             "LINKED")

    def test_unexpected_keys_and_result_injection_fails(self):
        with self.assertRaises(ValueError):
            cbs._reg(self.wine, self.prefix, "HKLM\\SECRET")
        report = {"scope": "MARKED_DISPOSABLE_WINE_PREFIX",
                  "cbs_registry": "PRESENT",
                  "packages_directory": "ABSENT",
                  "trustedinstaller_service_registration": "UNAVAILABLE",
                  "dismapi_disk_file": "LINKED"}
        self.assertTrue(cbs.validate(report))
        report["dismapi_disk_file"] = "/Users/private/path.dll"
        self.assertFalse(cbs.validate(report))
