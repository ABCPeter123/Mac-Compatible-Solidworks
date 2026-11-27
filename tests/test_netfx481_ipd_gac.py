"""Synthetic controls: no Wine, vendor files or real GAC writes."""
from pathlib import Path
import tempfile
import unittest
from scripts.netfx481_ipd_gac import registration_sources, cached_sources


class GacTests(unittest.TestCase):
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
