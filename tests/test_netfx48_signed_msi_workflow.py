"""CI must keep original signed MSI trial isolated from Winetricks and 4.8.1."""
from pathlib import Path
from unittest import TestCase

ROOT = Path(__file__).resolve().parents[1]
LEGACY = ROOT / ".github/workflows/netfx40-legacy-ci.yml"
ONCE = ROOT / ".github/workflows/netfx48-signed-msi-once-ci.yml"


class SignedMSIGates(TestCase):
    def test_only_explicit_one_shot_msi_and_no_other_original_upgrade_path(self):
        source = ONCE.read_text(encoding="utf-8")
        self.assertIn("branches: [main]", source)
        self.assertIn("      - '.github/workflows/netfx48-signed-msi-once-ci.yml'", source)
        self.assertIn("      try_48_msi: true", source)
        for line in ("try_48_intermediate: false", "try_48_direct: false",
                     "try_48_payload_host: false", "host_provenance_only: false",
                     "use_macos26_runner: true", "wine_baseline: '11.21'"):
            self.assertIn(line, source)
        self.assertNotIn("actions/upload-artifact", source)

    def test_reusable_only_allows_msi_when_signed_media_authenticated(self):
        workflow = LEGACY.read_text(encoding="utf-8")
        self.assertEqual(workflow.count("      try_48_msi:"), 2)
        self.assertIn("inputs.try_48_direct || inputs.try_48_msi", workflow)
        self.assertIn("SWCOMPAT_TRY_48_MSI:", workflow)
        self.assertIn("SWCOMPAT_DIRECT_48:", workflow)
        self.assertIn("python3 -m scripts.netfx40_to_48_signed_msi", workflow)
        self.assertIn('from scripts.netfx40_to_48_signed_msi import validate as valid_msi', workflow)
        self.assertIn('msi["native48_candidate"]', workflow)
        self.assertIn('not intermediate_required and not direct_required and not msi_required', workflow)
        self.assertIn('sum((direct_required, intermediate_required, msi_required)) <= 1', workflow)
        self.assertIn("build/netfx40-to-48-signed-msi.json", workflow)
        self.assertIn("if: env.SWCOMPAT_NATIVE40_READY == 'yes'", workflow)
