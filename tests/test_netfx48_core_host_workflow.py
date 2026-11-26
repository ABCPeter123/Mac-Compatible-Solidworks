"""Regression checks for original 4.8 payload-only CI on a proven native 4.0 host."""
from pathlib import Path
import unittest

WORKFLOWS = Path(__file__).resolve().parents[1] / ".github" / "workflows"


class Original48CoreWorkflowTests(unittest.TestCase):
    def test_one_shot_main_only_and_never_requests_48_setup(self):
        source = (WORKFLOWS / "netfx48-core-host-once-ci.yml").read_text()
        self.assertIn("  push:\n    branches: [main]\n    paths:\n"
                      "      - '.github/workflows/netfx48-core-host-once-ci.yml'", source)
        self.assertIn("uses: ./.github/workflows/netfx40-legacy-ci.yml", source)
        self.assertIn("      host_provenance_only: true", source)
        self.assertIn("      try_48_payload_host: true", source)
        self.assertIn("      try_48_intermediate: false", source)
        self.assertIn("      try_48_direct: false", source)
        self.assertNotIn("pull_request:", source)
        self.assertNotIn("workflow_dispatch:", source.split("on:", 1)[1].split("jobs:", 1)[0])
        self.assertNotIn("schedule:", source)

    def test_signed_windows_and_private_mac_media_with_host_gate(self):
        source = (WORKFLOWS / "netfx40-legacy-ci.yml").read_text()
        self.assertIn("  workflow_call:", source)
        self.assertIn("  workflow_dispatch:", source)
        self.assertEqual(source.count("      try_48_payload_host:"), 2)
        self.assertIn(
            "if: ((inputs.try_48_direct || inputs.try_48_msi) && !inputs.host_provenance_only) || inputs.try_48_payload_host",
            source)
        self.assertIn('if [ "$SWCOMPAT_DIRECT_48" = "true" ] || [ "$SWCOMPAT_PAYLOAD_48" = "true" ]; then',
                      source)
        self.assertIn("if: env.SWCOMPAT_NATIVE40_READY == 'yes' && inputs.try_48_payload_host",
                      source)
        self.assertIn("python3 -m scripts.netfx48_core_host_trial", source)
        self.assertIn("build/netfx48-core-host-categories.json", source)
        self.assertIn("payload_path.is_file() == payload_requested", source)
        self.assertIn('assert r["framework48_installed"] is False', source)
        self.assertIn('assert r["framework481_installed"] is False', source)
        self.assertIn("if: '!inputs.host_provenance_only && !inputs.try_481_catalog_wusa'", source)
        self.assertIn(
            "if: inputs.try_48_payload_host && (!inputs.host_provenance_only || inputs.try_48_direct || inputs.try_48_intermediate || inputs.try_48_msi)",
            source)
        self.assertIn('not host_only and not catalog_requested and (', source)

    def test_no_vendor_original_payloads_in_artifacts(self):
        source = (WORKFLOWS / "netfx40-legacy-ci.yml").read_text()
        for part in source.split("uses: actions/upload-artifact@v4")[1:]:
            block = part.split("      - name:", 1)[0].split("      - uses:", 1)[0]
            self.assertNotIn("build/NDP48-x86-x64-AllOS-ENU.exe", block)
            self.assertNotIn("build/dotNetFx40_Full_x86_x64.exe", block)
            self.assertNotIn("build/NDP481-x86-x64-AllOS-ENU.exe", block)


if __name__ == "__main__":
    unittest.main()
