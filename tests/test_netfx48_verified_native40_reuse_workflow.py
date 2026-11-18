"""Only opt-in to skipping duplicate Winetricks 4.0 after real Microsoft CLR evidence."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
LEGACY = ROOT / ".github/workflows/netfx40-legacy-ci.yml"
ONCE = ROOT / ".github/workflows/netfx48-skip-verified-dotnet40-once-ci.yml"


class VerifiedNative40ReuseWorkflow(unittest.TestCase):
    def test_reuse_disabled_by_default_and_separately_allowlisted(self):
        text = LEGACY.read_text(encoding="utf-8")
        self.assertEqual(text.count("      reuse_verified_native40:"), 2)
        self.assertIn("          SWCOMPAT_REUSE_NATIVE40: ${{ inputs.reuse_verified_native40 }}", text)
        self.assertIn('if [ "$SWCOMPAT_REUSE_NATIVE40" = "true" ]; then', text)
        self.assertIn('extra+=(--reuse-verified-native40)', text)
        self.assertIn('            --timeout 840 "${extra[@]}" --agree-disposable-prefix', text)
        self.assertIn("if: env.SWCOMPAT_NATIVE40_READY == 'yes'", text)

    def test_explicit_one_shot_native40_provenance_is_not_global(self):
        text = ONCE.read_text(encoding="utf-8")
        self.assertIn("branches: [main]", text)
        self.assertIn("      - '.github/workflows/netfx48-skip-verified-dotnet40-once-ci.yml'", text)
        self.assertIn("reuse_verified_native40: true", text)
        self.assertIn("try_48_intermediate: true", text)
        self.assertIn("try_48_direct: false", text)
        self.assertIn("host_provenance_only: false", text)
        self.assertIn("wine_baseline: '11.21'", text)
        self.assertIn("uses: ./.github/workflows/netfx40-legacy-ci.yml", text)
        self.assertNotIn("actions/upload-artifact", text)


if __name__ == "__main__":
    unittest.main()
