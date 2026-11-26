"""Guard opt-in, disposable-only Wine server shutdown before real 4.8 testing."""
from pathlib import Path
from unittest import TestCase

ROOT = Path(__file__).resolve().parents[1]
LEGACY = ROOT / ".github/workflows/netfx40-legacy-ci.yml"


class SettledWinetricksContract(TestCase):
    def test_original_workflow_does_not_reset_wineserver_by_default(self):
        source = LEGACY.read_text(encoding="utf-8")
        self.assertEqual(source.count("      settle_wineserver:"), 2)
        self.assertIn("          SWCOMPAT_SETTLE_WINESERVER:", source)
        self.assertIn('if [ "$SWCOMPAT_SETTLE_WINESERVER" = "true" ]; then', source)
        self.assertIn('extra+=(--settle-disposable-wineserver)', source)
        self.assertIn('"wineserver_settle"', source)

