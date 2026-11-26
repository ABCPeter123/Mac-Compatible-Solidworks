"""Tests for the dry-run-only WUSA integration."""
from pathlib import Path
import unittest
from scripts.patch_wusa_ipd_dryrun import patch_main, OLD_IPD, OLD_INSTALL, git_blob
from scripts.netfx481_ipd_wusa_dryrun import parse_packet, CATEGORIES


class WusaDryRunTests(unittest.TestCase):
    def test_patch_removes_apply_and_preserves_dryrun(self):
        fixture = "\n".join(["WINE_DEFAULT_DEBUG_CHANNEL(wusa);", OLD_IPD,
                             "    HKEY root, subkey;", "    install_updates(state, TRUE);",
                             OLD_INSTALL, "static void restart_as_x86_64(void)",
                             "int __cdecl wmain(int argc, WCHAR *argv[])"])
        modified = patch_main(fixture)
        self.assertIn("temp_path = swcompat_stage;", modified)
        self.assertIn("install_updates(state, TRUE)", modified)
        self.assertNotIn("install_updates(state, FALSE)", modified)
        self.assertNotIn("restart_as_x86_64", modified)
        with self.assertRaises(ValueError):
            patch_main(modified)

    def test_git_blob_identity(self):
        self.assertEqual(git_blob(b""), "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391")

    def packet(self, result="PASS", count=1):
        return "\n".join(["SWCOMPAT_IPD_DRYRUN_SCHEMA=1",
                          "SWCOMPAT_IPD_DRYRUN_RESULT=" + result,
                          "SWCOMPAT_IPD_DRYRUN_IPD=" + str(count)] +
                         [f"SWCOMPAT_IPD_DRYRUN_C{i}=0" for i in range(len(CATEGORIES))]).encode()

    def test_allowlisted_result(self):
        report = parse_packet(self.packet(), 0)
        self.assertEqual(report["dryrun"], "PASS")
        self.assertFalse(report["servicing_performed"])
        self.assertEqual(parse_packet(self.packet("FAIL", 0), 1)["dryrun"], "FAIL")
        for data, code in [(self.packet(), 1), (self.packet(count=0), 0),
                           (self.packet() + b"\nprivate path", 0),
                           (self.packet() + b"\nSWCOMPAT_IPD_DRYRUN_C0=4", 0)]:
            with self.assertRaises(ValueError):
                parse_packet(data, code)


if __name__ == "__main__":
    unittest.main()
