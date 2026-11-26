"""Regression for authenticated Wine release differential on original .NET 4.8."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
LEGACY = ROOT / ".github/workflows/netfx40-legacy-ci.yml"
SHA_1110 = "940bdd1a177872020be01c5c33917cb8eecc1cc3193ad554914fb6efd90d7889"
SHA_1121 = "d7bcd5abf4df27aae397a7898aef074fea4a2e0b51e0a55aa9659517bbf9d452"


class Wine1110Comparison(unittest.TestCase):
    def test_only_official_sha256_pinned_releases_allowed(self):
        source = LEGACY.read_text(encoding="utf-8")
        self.assertEqual(source.count("      wine_baseline:"), 2)
        self.assertIn("options: ['11.21', '11.10']", source)
        self.assertIn(SHA_1110, source)
        self.assertIn(SHA_1121, source)
        self.assertIn('case "$SWCOMPAT_WINE_BASELINE" in', source)
        self.assertIn('Unsupported Wine baseline', source)
        self.assertIn('shasum -a 256 -c -', source)
        self.assertIn('Gcenx/macOS_Wine_builds/releases/download/', source)
        self.assertIn('default: \'11.21\'', source)


if __name__ == "__main__":
    unittest.main()
