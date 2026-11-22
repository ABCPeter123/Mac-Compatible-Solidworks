"""Main-only signed .NET MSI NGen stack A/B does not change vendor packages."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
CALLER = ROOT / ".github/workflows/netfx48-wiage-ngen-stack-seh-once-ci.yml"
REUSE = ROOT / ".github/workflows/netfx40-legacy-ci.yml"


class AuthenticNgenStackTest(unittest.TestCase):
    def test_only_own_main_path_triggers_once(self):
        caller = CALLER.read_text(encoding="utf-8")
        self.assertIn("  push:\n    branches: [main]\n    paths:\n"
                      "      - '.github/workflows/netfx48-wiage-ngen-stack-seh-once-ci.yml'",
                      caller)
        self.assertIn("uses: ./.github/workflows/netfx40-legacy-ci.yml", caller)
        for line in (
            "wine_baseline: 'wiage-11.13'",
            "use_macos26_runner: true",
            "host_provenance_only: false",
            "try_48_direct: false",
            "try_48_intermediate: false",
            "try_48_payload_host: false",
            "try_48_msi: true",
            "drain_native40_ngen: true",
            "ngen_host_stack64: true",
            "signed_msi_timeout_seconds: 420",
            "prepare_48_assembly_cache: true",
            "pause_native_ngen_queue: false",
            "cancel-in-progress: false",
        ):
            with self.subTest(line=line):
                self.assertIn(line, caller)
        for banned in ("actions/upload-artifact", "secrets:", "workflow_dispatch:",
                       "pull_request:", "try_48_msi: false"):
            self.assertNotIn(banned, caller)

    def test_enforced_host_stack_and_private_wine_error_categories(self):
        source = REUSE.read_text(encoding="utf-8")
        anchor = source.index("- name: Reject NGen stack diagnostic outside isolated Wiage signed MSI preflight")
        guard = source[anchor:source.index("- name: Reject incompatible original Microsoft CLR4 NGen", anchor)]
        self.assertIn("inputs.ngen_host_stack64", guard)
        self.assertIn("inputs.wine_baseline != 'wiage-11.13'", guard)
        self.assertIn("inputs.pause_native_ngen_queue", guard)
        self.assertIn("!inputs.use_macos26_runner", guard)
        self.assertIn("echo", guard)
        drain = source.split(
            "- name: Drain genuine original Microsoft CLR4 NGen x64 and x86 queues", 1
        )[1].split("- name: Extract authenticated original .NET 4.8 x64 MSI", 1)[0]
        self.assertIn('SWCOMPAT_NGEN_STACK64: ${{ inputs.ngen_host_stack64 }}', drain)
        self.assertIn("ulimit -s 65520", drain)
        self.assertIn('[[ "$(ulimit -s)" == "65520" ]]', drain)
        self.assertIn("--observe-wine-failures", drain)
        self.assertIn('--native40-report build/netfx40-msxml3-restart.json', drain)
        self.assertIn("--agree-disposable-prefix", drain)
        self.assertNotIn("continue-on-error: true", drain)

    def test_true_microsoft_msi_and_privacy_gates_not_changed(self):
        source = REUSE.read_text(encoding="utf-8")
        self.assertIn("python3 -m scripts.netfx40_to_48_signed_msi", source)
        self.assertIn("--sha256-file build/netfx48.sha256", source)
        self.assertIn("if result[\"native48_candidate\"]:", source)
        self.assertIn("build/netfx40-native-ngen-drain.json", source)
        self.assertNotIn("bypass-NGen", source)
        self.assertNotIn("fake Release", source)


if __name__ == "__main__":
    unittest.main()
