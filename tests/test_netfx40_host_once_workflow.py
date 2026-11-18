"""Guard the single main-branch original .NET 4.0 host-only CI trigger.

This intentionally tests the literal workflow wiring without PyYAML, which
would otherwise be an extra dependency in the lightweight foundation CI.
"""
from pathlib import Path
import unittest


WORKFLOWS = Path(__file__).resolve().parents[1] / ".github" / "workflows"


class HostOnceWorkflowTests(unittest.TestCase):
    def test_one_shot_caller_is_main_only_and_host_only(self):
        source = (WORKFLOWS / "netfx40-host-once-ci.yml").read_text(encoding="utf-8")
        self.assertIn("  push:\n    branches: [main]\n    paths:\n"
                      "      - '.github/workflows/netfx40-host-once-ci.yml'", source)
        self.assertIn("uses: ./.github/workflows/netfx40-legacy-ci.yml", source)
        self.assertIn("      host_provenance_only: true", source)
        self.assertIn("      try_48_intermediate: false", source)
        self.assertIn("      try_48_direct: false", source)
        self.assertNotIn("workflow_dispatch:", source.split("on:", 1)[1].split("jobs:", 1)[0])
        self.assertNotIn("pull_request:", source)
        self.assertNotIn("schedule:", source)
        self.assertNotIn("secrets:", source)

    def test_reusable_target_keeps_48_disabled_in_host_only_mode(self):
        source = (WORKFLOWS / "netfx40-legacy-ci.yml").read_text(encoding="utf-8")
        self.assertIn("  workflow_call:", source)
        self.assertIn("  workflow_dispatch:", source)
        self.assertIn("        if: '!inputs.host_provenance_only'", source)
        self.assertIn("if: github.event_name == 'workflow_dispatch' && !inputs.host_provenance_only", source)
        self.assertIn("SWCOMPAT_PROVENANCE_ONLY: ${{ inputs.host_provenance_only }}", source)
        self.assertIn('if [ "$SWCOMPAT_PROVENANCE_ONLY" != "true" ]; then', source)
        self.assertIn("if: inputs.host_provenance_only && (inputs.try_48_intermediate || inputs.try_48_direct || inputs.try_48_msi)", source)
        self.assertIn("if: env.SWCOMPAT_NATIVE40_READY == 'yes'", source)
        self.assertIn("python3 -m scripts.netfx40_host_api_diagnostic", source)
        self.assertIn("AUTHENTIC_NETFX40_HOST_FIXTURE_WINDOWS_CONTROL", source)
        self.assertIn("not host_only and (", source)
        self.assertIn('assert not upgrade_path.is_file(), "Host-only must skip 4.8.1"', source)
        self.assertIn('host_valid(host) and host["status"] == "MEASURED"', source)
        self.assertIn('provenance_valid(provenance) and provenance["status"] == "MEASURED"', source)


if __name__ == "__main__":
    unittest.main()
