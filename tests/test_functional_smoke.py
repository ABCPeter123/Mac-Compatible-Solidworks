import unittest
from pathlib import Path
from scripts.functional_smoke import validate_marker, wine_path, run_managed
from unittest.mock import patch


class FunctionalSmokeTests(unittest.TestCase):
    def test_wine_path_translates_unix_absolute(self):
        self.assertEqual(wine_path(Path("/tmp/myfile.msi")), r"Z:\tmp\myfile.msi")

    def test_marker_requires_clean_exit(self):
        self.assertTrue(validate_marker({"exit_code": 0, "output": "SWCOMPAT_DOTNET=PASS\n"}, "SWCOMPAT_DOTNET=PASS"))
        self.assertFalse(validate_marker({"exit_code": 1, "output": "SWCOMPAT_DOTNET=PASS\n"}, "SWCOMPAT_DOTNET=PASS"))
        self.assertFalse(validate_marker({"exit_code": 0, "output": "noiseSWCOMPAT_DOTNET=PASS\n"}, "SWCOMPAT_DOTNET=PASS"))

    def test_missing_runtime_is_not_false_positive(self):
        with patch("scripts.functional_smoke.execute", return_value={"exit_code": 1, "output": "CLR not found"}):
            from tempfile import TemporaryDirectory
            with TemporaryDirectory() as root:
                exe = Path(root) / "smoke.exe"
                exe.write_bytes(b"MZ")
                result = run_managed("native", None, Path(root), exe)
                self.assertFalse(result["passed"])

    def test_msi_product_guid_stable(self):
        from scripts.functional_smoke import PRODUCT_CODE
        self.assertRegex(PRODUCT_CODE, r"^\{[A-F0-9-]{36}\}$")


if __name__ == "__main__":
    unittest.main()
