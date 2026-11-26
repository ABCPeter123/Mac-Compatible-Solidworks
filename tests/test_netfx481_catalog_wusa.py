import hashlib
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch
from scripts import netfx481_catalog_wusa as p


class CatalogWusaTests(unittest.TestCase):
    def test_authentic_digest_and_size_fail_closed(self):
        with TemporaryDirectory() as td:
            root = Path(td)
            data = b"synthetic test only"
            msu = root / p.PACKAGE
            msu.write_bytes(data)
            manifest = root / "sha256"
            manifest.write_text(hashlib.sha256(data).hexdigest())
            with patch.object(p, "SHA1", hashlib.sha1(data).hexdigest()), patch.object(p, "SIZE", len(data)):
                p.verify_package(msu, manifest)
                manifest.write_text("0" * 64)
                with self.assertRaises(ValueError):
                    p.verify_package(msu, manifest)

    def test_full_dword_packet(self):
        def packet(status, code):
            return (f"SWCOMPAT_WUSA_SCHEMA=1\nSWCOMPAT_WUSA_STATUS={status}\n"
                    f"SWCOMPAT_WUSA_EXIT={code}\n").encode()
        self.assertEqual(p.parse_packet(packet("EXIT", "800F081E")), "800F081E")
        self.assertEqual(p.parse_packet(packet("SELFTEST", "00000BC2"), True), "00000BC2")
        self.assertIsNone(p.parse_packet(packet("SELFTEST", "00000BC2")))
        self.assertIsNone(p.parse_packet(packet("EXIT", "00000000") + b"unexpected\n"))
        self.assertIsNone(p.parse_packet(packet("EXIT", "0")))

    def test_green_wrapper_cannot_claim_runtime(self):
        r = p.blank()
        self.assertTrue(p.valid(r))
        r.update(original_package_verified=True, native40_persistent=True,
                 wusa="EXIT_CAPTURED", exit_hex="00000000", restart="COMPLETED")
        self.assertTrue(p.valid(r))
        self.assertFalse(p.valid(dict(r, framework481_confirmed=True)))
        payload = p.blank_payload()
        payload["status"] = "MEASURED"
        payload["before"]["CLR64"] = "PE_AMD64"
        payload["after"]["CLR64"] = payload["after"]["MSCORLIB64"] = "PE_AMD64"
        payload["changes"]["CLR64"] = "CHANGED"
        r.update(payload=payload, loader="LOADED", registry="AT_LEAST_481",
                 runtime_family="MICROSOFT_CLR_CANDIDATE", native_only_managed="PASS",
                 framework481_confirmed=True)
        self.assertTrue(p.valid(r))
        for key, value in (("exit_hex", "800F081E"), ("restart", "NOT_RUN"),
                           ("registry", "BELOW_481"), ("native_only_managed", "FAIL"),
                           ("runtime_family", "MONO"), ("loader", "NOT_VERIFIED")):
            with self.subTest(key=key):
                self.assertFalse(p.valid(dict(r, **{key: value})))
        payload["changes"]["CLR64"] = "UNCHANGED"
        self.assertFalse(p.valid(r))

    def test_workflow_is_independent_and_artifacts_do_not_export_msu(self):
        root = Path(__file__).resolve().parents[1]
        caller = (root / ".github/workflows/netfx481-catalog-wusa-ci.yml").read_text()
        reusable = (root / ".github/workflows/netfx40-legacy-ci.yml").read_text()
        self.assertIn("try_481_catalog_wusa: true", caller)
        self.assertIn("try_48_msi: false", caller)
        self.assertIn("workflow_dispatch:", caller)
        self.assertNotIn("pull_request:", caller)
        for marker in ("build/netfx481-catalog.sha256", "build/netfx481_catalog_wusa.exe",
                       "build/netfx481-catalog-wusa.json", "and not catalog_requested"):
            self.assertIn(marker, reusable)
        for chunk in reusable.split("uses: actions/upload-artifact@v4")[1:]:
            upload = chunk.split("\n      - ", 1)[0].split("\n  ", 1)[0]
            self.assertNotIn("KB5011048.msu", upload)
