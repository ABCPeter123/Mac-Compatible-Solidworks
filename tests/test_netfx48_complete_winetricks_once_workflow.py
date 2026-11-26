"""Ensure full Winetricks is a single disposable, authenticated experiment."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
LEGACY = ".github/workflows/netfx40-legacy-ci.yml"


class FullWinetricksOnceTests(unittest.TestCase):

    def test_existing_genuine_runtime_gate_cannot_claim_success_on_winetricks_exit(self):
        text = (ROOT / LEGACY).read_text(encoding="utf-8")
        self.assertIn("python3 -m scripts.netfx40_to_48_intermediate", text)
        self.assertIn("--agree-disposable-prefix", text)
        self.assertIn('intermediate["native48_candidate"]', text)
        self.assertIn("assert valid_intermediate(intermediate)", text)
        self.assertIn("Select either Winetricks 4.8 OR original signed 4.8", text)


if __name__ == "__main__":
    unittest.main()
