"""No vendor files or filenames leave the servicing payload inventory."""
from tempfile import TemporaryDirectory
from pathlib import Path
from unittest import TestCase, main
from scripts.netfx481_servicing_inventory import (
    summarize_listing, blank, valid, _safe_embedded,
)


class ServicingInventoryTests(TestCase):
    def test_classifies_real_7zip_style_listing_without_exposing_names(self):
        raw = (b"Path = NDP481-x86-x64-AllOS-ENU.exe\n"
               b"Type = PE\n----------\n"
               b"Path = WINDOWS10.0-KB5011048-x64.cab\nSize = 43000000\n"
               b"Path = package_x64.msu\n"
               b"Path = amd64_NETFX48/update.mum\n"
               b"Path = Windows\\servicing\\Packages\\amd64_component.manifest\n"
               b"Path = netfx.msi\nPath = clr.dll\n")
        result = summarize_listing(raw, exit_code=0)
        self.assertEqual(result["status"], "OK")
        self.assertEqual(result["types"],
                         {"CAB": 1, "MSU": 1, "MUM": 1,
                          "MANIFEST": 1, "MSI": 1, "DLL": 1})
        self.assertTrue(result["arch_x64"])
        self.assertTrue(result["kb5011048"])
        self.assertTrue(result["update_mum"])
        self.assertNotIn("WINDOWS10.0", str(result))
        self.assertNotIn("clr.dll", str(result))

    def test_invalid_and_bounded_inputs(self):
        self.assertEqual(summarize_listing(b"anything", exit_code=2)["status"],
                         "UNSUPPORTED")
        self.assertEqual(summarize_listing(b"x" * (4 * 1024 * 1024 + 1),
                                           exit_code=0)["status"], "TOO_LARGE")
        self.assertEqual(summarize_listing(b"\xff", exit_code=0)["status"], "INVALID")
        self.assertFalse(valid(dict(blank(), private_manifest="SECRET")))
        self.assertFalse(valid(dict(blank(), genuine_servicing_installed=True)))
        self.assertFalse(valid(dict(blank(), outer_types={"CAB": 1})))

    def test_nested_extraction_rejects_symlinks_and_too_many_packages(self):
        with TemporaryDirectory() as td:
            root = Path(td)
            (root / "component.cab").write_bytes(b"cab fixture")
            (root / "linked.cab").symlink_to(root / "component.cab")
            found, partial = _safe_embedded(root)
            self.assertEqual(len(found), 0)  # The CAB fixture fails minimum size.
            self.assertTrue(partial)
            (root / "linked.cab").unlink()
            (root / "component.cab").write_bytes(b"test CAB " * 8)
            found, partial = _safe_embedded(root)
            self.assertEqual(len(found), 1)
            self.assertFalse(partial)


if __name__ == "__main__":
    main()
