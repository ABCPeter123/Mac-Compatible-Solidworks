"""Only opt-in to skipping duplicate Winetricks 4.0 after real Microsoft CLR evidence."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
LEGACY = ROOT / ".github/workflows/netfx40-legacy-ci.yml"


class VerifiedNative40ReuseWorkflow(unittest.TestCase):
    def test_reuse_disabled_by_default_and_separately_allowlisted(self):
        text = LEGACY.read_text(encoding="utf-8")
        self.assertEqual(text.count("      reuse_verified_native40:"), 2)
        self.assertIn("          SWCOMPAT_REUSE_NATIVE40: ${{ inputs.reuse_verified_native40 }}", text)
        self.assertIn('if [ "$SWCOMPAT_REUSE_NATIVE40" = "true" ]; then', text)
        self.assertIn('extra+=(--reuse-verified-native40)', text)
        self.assertIn('            --timeout 840 "${extra[@]}" --agree-disposable-prefix', text)
        self.assertIn("if: env.SWCOMPAT_NATIVE40_READY == 'yes'", text)


if __name__ == "__main__":
    unittest.main()
