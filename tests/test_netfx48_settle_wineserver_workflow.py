"""Guard opt-in, disposable-only Wine server shutdown before real 4.8 testing."""
from pathlib import Path
from unittest import TestCase

ROOT = Path(__file__).resolve().parents[1]
LEGACY = ROOT / ".github/workflows/netfx40-legacy-ci.yml"
ONCE = ROOT / ".github/workflows/netfx48-settle-wineserver-once-ci.yml"


class SettledWinetricksContract(TestCase):
    def test_original_workflow_does_not_reset_wineserver_by_default(self):
        source = LEGACY.read_text(encoding="utf-8")
        self.assertEqual(source.count("      settle_wineserver:"), 2)
        self.assertIn("          SWCOMPAT_SETTLE_WINESERVER:", source)
        self.assertIn('if [ "$SWCOMPAT_SETTLE_WINESERVER" = "true" ]; then', source)
        self.assertIn('extra+=(--settle-disposable-wineserver)', source)
        self.assertIn('"wineserver_settle"', source)

    def test_exact_one_shot_does_not_request_other_installer_methods(self):
        source = ONCE.read_text(encoding="utf-8")
        self.assertIn("branches: [main]", source)
        self.assertIn("      - '.github/workflows/netfx48-settle-wineserver-once-ci.yml'", source)
        self.assertIn("uses: ./.github/workflows/netfx40-legacy-ci.yml", source)
        for expected in (
            "      settle_wineserver: true", "      reuse_verified_native40: true",
            "      try_48_intermediate: true", "      try_48_msi: false",
            "      try_48_direct: false", "      host_provenance_only: false",
            "      use_macos26_runner: true", "      wine_baseline: '11.21'",
        ):
            self.assertIn(expected, source)
        self.assertNotIn("actions/upload-artifact", source)
