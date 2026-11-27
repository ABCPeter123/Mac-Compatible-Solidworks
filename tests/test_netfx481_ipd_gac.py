"""Synthetic controls: no Wine, vendor files or real GAC writes."""
from pathlib import Path
import tempfile
import unittest
from scripts.netfx481_ipd_gac import registration_sources, cached_sources, GacRejected, registration_complete


class GacTests(unittest.TestCase):
    def test_completion_accepts_only_exact_accounting(self):
        for before in (0, 1, 137, 274):
            with self.subTest(before=before):
                report = dict(transport="COMPLETED", directives=274, unique_payloads=274,
                              cached_before=before, cached_after=274,
                              attempted=274-before, successful_hresult=274-before,
                              failed_hresult={})
                self.assertTrue(registration_complete(report))
                for key, bad in (("cached_before", -1), ("cached_after", 273),
                                 ("attempted", 275), ("successful_hresult", True),
                                 ("unique_payloads", 273), ("transport", "REJECTED"),
                                 ("failed_hresult", {"80004005": 1})):
                    self.assertFalse(registration_complete(dict(report, **{key: bad})))
                missing = dict(report)
                del missing["cached_before"]
                self.assertFalse(registration_complete(missing))

    def test_exact_source_and_native_cache_bytes(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            manifest = root / "one.manifest"
            manifest.write_text('<assembly xmlns="urn:schemas-microsoft-com:asm.v3">'
                                '<file sourceName="one.dll"><gac clrarch="msil" '
                                'clrversion="v4.0.30319" managedversion="4.0.0.0" '
                                'fileCopy="false"/></file></assembly>')
            source = root / "one.dll"
            source.write_bytes(b"verified original")
            members = {"one.manifest": manifest, "one/one.dll": source}
            self.assertEqual(registration_sources(members, expected_count=1), [source])
            original = manifest.read_text()
            for version in ("4.0", "4.0.30319", "4.0.0.0"):
                manifest.write_text(original.replace("v4.0.30319", version))
                self.assertEqual(registration_sources(members, expected_count=1), [source])
            manifest.write_text(original.replace('clrarch="msil"', 'clrarch="unknown"'))
            with self.assertRaisesRegex(GacRejected, "^GAC_ARCHITECTURE$"):
                registration_sources(members, expected_count=1)
            manifest.write_text(original.replace("v4.0.30319", "v2.0.50727"))
            with self.assertRaisesRegex(GacRejected, "^GAC_CLR_VERSION$"):
                registration_sources(members, expected_count=1)
            manifest.write_text(original)
            with self.assertRaises(ValueError):
                registration_sources(members, expected_count=2)
            with self.assertRaises(ValueError):
                registration_sources({"one.manifest": manifest}, expected_count=1)
            cache = root / "prefix/drive_c/windows/Microsoft.NET/assembly/GAC_MSIL/one/version"
            cache.mkdir(parents=True)
            target = cache / "one.dll"
            target.write_bytes(b"older version")
            self.assertEqual(len(cached_sources(root / "prefix", [source])), 0)
            target.write_bytes(source.read_bytes())
            self.assertEqual(len(cached_sources(root / "prefix", [source])), 1)
            manifest.write_text('<!DOCTYPE a [<!ENTITY x "test">]><a/>')
            with self.assertRaises(ValueError):
                registration_sources(members, expected_count=1)
