"""Synthetic Windows Installer registration packet checks. No vendor data."""
from unittest import TestCase
from scripts import netfx48_msi_registration as r


class SignedMSIRegistrationTests(TestCase):
    @staticmethod
    def packet(status="OBSERVED", product="INSTALLED", cache="PRESENT"):
        return (
            "SWCOMPAT_MSI_REG_SCHEMA=1\n"
            f"SWCOMPAT_MSI_REG_STATUS={status}\n"
            f"SWCOMPAT_MSI_REG_PRODUCT={product}\n"
            f"SWCOMPAT_MSI_REG_CACHE={cache}\n"
        ).encode("ascii")

    def test_original_signed_msi_product_registration_is_not_patch_success(self):
        for product, cache in (("INSTALLED", "PRESENT"),
                               ("ABSENT", "UNKNOWN"),
                               ("INSTALLED", "MISSING"),
                               ("ADVERTISED", "PRESENT"),
                               ("OTHER", "UNKNOWN")):
            with self.subTest(product=product, cache=cache):
                result = r.parse(self.packet(product=product, cache=cache),
                                 "SUCCESS")
                self.assertTrue(r.valid(result))
                self.assertEqual(result["status"], "OBSERVED")
                self.assertEqual(result["product"], product)
                self.assertEqual(result["cache"], cache)

    def test_fixture_selftest_requires_exact_fixed_packet(self):
        self.assertEqual(
            r.parse(self.packet(status="SELFTEST"), "SUCCESS", selftest=True),
            {"status": "SELFTEST", "product": "INSTALLED", "cache": "PRESENT"})
        self.assertEqual(r.parse(self.packet(status="SELFTEST"), "SUCCESS"),
                         r.blank("BAD_PACKET"))
        self.assertEqual(r.parse(self.packet(), "SUCCESS", selftest=True),
                         r.blank("BAD_PACKET"))

    def test_native_probe_never_leaks_vendor_data_or_accepts_extra_lines(self):
        valid = self.packet()
        for input_data in (
                valid + b"ORIGINAL_PRODUCT_CODE={SECRET}\n",
                b"0124:fixme:msi:private path\n" + valid,
                valid.replace(b"SCHEMA=1", b"SCHEMA=2"),
                valid.replace(b"PRESENT", b"ORIGINAL_CACHE_PATH"),
                valid[:-1] + b"\nSECRET\n",
                b"\xff" + valid,
                b"A" * (r.MAX_BYTES + 1),
                None, [], {}, 4):
            with self.subTest(length=len(str(input_data))):
                result = r.parse(input_data, "SUCCESS")
                self.assertEqual(result, r.blank("BAD_PACKET"))
                self.assertNotIn("SECRET", str(result))
                self.assertTrue(r.valid(result))

    def test_failed_native_process_does_not_claim_product_registration(self):
        self.assertEqual(r.parse(self.packet(), "EXIT_NONZERO"),
                         r.blank("HOST_ERROR"))
        self.assertEqual(r.parse(self.packet(), "TIMED_OUT_PREFIX_REAPED"),
                         r.blank("HOST_ERROR"))
        self.assertFalse(r.valid({"status": "OBSERVED", "product": "{GUID}",
                                  "cache": "PRESENT"}))
        self.assertFalse(r.valid({**r.blank(), "cache": "PRESENT"}))
        self.assertTrue(r.valid(r.blank()))
