"""Privacy and semantic checks for native, read-only patch applicability."""
from unittest import TestCase

from scripts import netfx48_msp_patch_sequence as p


class OriginalSignedMSPSequenceTests(TestCase):
    @staticmethod
    def packet(status="OBSERVED", user="APPLICABLE", machine="PRODUCT_UNKNOWN"):
        return (b"SWCOMPAT_MSI_SEQ_SCHEMA=1\n"
                + f"SWCOMPAT_MSI_SEQ_STATUS={status}\n".encode("ascii")
                + f"SWCOMPAT_MSI_SEQ_USER={user}\n".encode("ascii")
                + f"SWCOMPAT_MSI_SEQ_MACHINE={machine}\n".encode("ascii"))

    def test_read_only_win32_contexts_are_never_conflated(self):
        for user, machine in (
            ("APPLICABLE", "PRODUCT_UNKNOWN"),
            ("PRODUCT_UNKNOWN", "APPLICABLE"),
            ("TARGET_MISMATCH", "TARGET_MISMATCH"),
            ("UNSUPPORTED", "UNSUPPORTED"),
            ("NO_SEQUENCE", "PRODUCT_UNKNOWN"),
            ("EXCLUDED", "PRODUCT_UNKNOWN"),
            ("PATCH_UNOPENABLE", "OTHER_ERROR"),
        ):
            with self.subTest(user=user, machine=machine):
                r = p.parse(self.packet(user=user, machine=machine))
                self.assertEqual(r, {"status": "OBSERVED",
                                     "user": user, "machine": machine})
                self.assertTrue(p.valid(r))
        self.assertEqual(p.parse(self.packet(
            status="NOT_RUN", user="UNKNOWN", machine="UNKNOWN")), p.blank())
        self.assertFalse(p.valid({"status": "OBSERVED",
                                  "user": "UNKNOWN", "machine": "UNKNOWN"}))

    def test_fixture_packet_is_distinct_from_real_signed_msp(self):
        self.assertEqual(p.parse(self.packet(status="SELFTEST"),
                                 selftest=True),
                         {"status": "SELFTEST", "user": "APPLICABLE",
                          "machine": "PRODUCT_UNKNOWN"})
        self.assertEqual(p.parse(self.packet(status="SELFTEST")),
                         p.blank("BAD_PACKET"))
        self.assertEqual(p.parse(self.packet(), selftest=True),
                         p.blank("BAD_PACKET"))

    def test_raw_vendor_or_secrets_never_leave_packet_classifier(self):
        clean = self.packet()
        bad = (
            clean + b"MSI_PATCH_GUID={PRIVATE}\n",
            b"003a:trace:msi:source_path PRIVATE\n" + clean,
            clean.replace(b"SCHEMA=1", b"SCHEMA=4"),
            clean.replace(b"APPLICABLE", b"C:\\PRIVATE\\PATCH.msp"),
            clean.replace(b"PRODUCT_UNKNOWN", b"PRIVATE"),
            clean + b"\x00",
            clean + clean,
            b"X" * (p.MAX_BYTES + 1),
            b"\xff" + clean,
            None, 12, ["PRIVATE"],
        )
        for item in bad:
            with self.subTest(sample_type=type(item).__name__):
                r = p.parse(item)
                self.assertEqual(r, p.blank("BAD_PACKET"))
                self.assertTrue(p.valid(r))
                self.assertNotIn("PRIVATE", str(r))
        self.assertFalse(p.valid({"status": "OBSERVED", "user": "APPLICABLE",
                                  "machine": "{PRIVATE_PRODUCTCODE}"}))
        self.assertFalse(p.valid({**p.blank(), "secret": "PRIVATE"}))
