import unittest
from scripts.netfx481_catalog_cab_inventory import classify_listing


class CatalogCabInventoryTests(unittest.TestCase):
    def test_exact_delta_marker_and_normal_full_payload(self):
        result = classify_listing(b"Path = outer.cab\n----------\nPath = PRIVATE\\_manifest_.cix.xml\nPath = PRIVATE\\CLR.DLL\nPath = private.mum\nPath = private.manifest\n")
        self.assertTrue(result["complete"])
        self.assertTrue(result["cix"])
        self.assertTrue(result["clr_file"])
        self.assertTrue(result["mum"])
        self.assertTrue(result["manifest"])
        self.assertFalse(result["psf"])
        self.assertNotIn("PRIVATE", str(result))
        self.assertEqual(result["entries"], 4)

    def test_archive_header_and_false_marker_are_not_members(self):
        result = classify_listing(b"Path = _manifest_.cix.xml\n----------\nPath = fake_manifest_.cix.xml.bak\nPath = payload.psf\n")
        self.assertTrue(result["complete"])
        self.assertFalse(result["cix"])
        self.assertTrue(result["psf"])

    def test_unparseable_listing_not_evidence_of_no_delta(self):
        for raw in (b"", b"Path = _manifest_.cix.xml\n", b"\xff"):
            self.assertFalse(classify_listing(raw)["complete"])
