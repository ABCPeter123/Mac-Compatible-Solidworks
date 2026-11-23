"""A single genuine CLR4 provisioning run tests the branch it actually reached.

The opt-in experiment never equates an original MSI 1603, an original Core
MSI candidate, an NGen queue drain or a Wine registry marker with completed
Microsoft .NET Framework 4.0/4.8/4.8.1 installation.
"""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/netfx40-legacy-ci.yml"
CALLER = ROOT / ".github/workflows/netfx40-wiage-core-msi-once-ci.yml"


class AdaptiveOriginalNgenControlTests(unittest.TestCase):
    def test_caller_is_main_only_and_original_microsoft_host_only(self):
        content = CALLER.read_text(encoding="utf-8")
        self.assertIn(
            "  push:\n    branches: [main]\n    paths:\n"
            "      - '.github/workflows/netfx40-wiage-core-msi-once-ci.yml'",
            content,
        )
        self.assertIn("uses: ./.github/workflows/netfx40-legacy-ci.yml", content)
        for expected in (
            "wine_baseline: 'wiage-11.13'",
            "use_macos26_runner: true",
            "host_provenance_only: true",
            "try_40_core_msi_recovery: true",
            "probe_native40_ngen_if_ready: true",
            "try_48_msi: false",
            "try_48_direct: false",
            "try_48_intermediate: false",
            "try_48_payload_host: false",
            "drain_native40_ngen: false",
            "pause_native_ngen_queue: false",
            "cancel-in-progress: false",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, content)
        self.assertNotIn("actions/upload-artifact", content)
        self.assertNotIn("workflow_dispatch:", content)

    def test_only_authentic_disposable_prefix_and_exclusive_microsoft_paths(self):
        content = WORKFLOW.read_text(encoding="utf-8")
        self.assertEqual(content.count("probe_native40_ngen_if_ready:"), 2)
        start = content.index(
            "- name: Reject adaptive native CLR4 NGen outside authenticated Core MSI A/B")
        end = content.index("- name: Reject original CLR4 x64 MSI recovery", start)
        guard = content[start:end]
        for item in (
            "inputs.probe_native40_ngen_if_ready",
            "!inputs.try_40_core_msi_recovery",
            "!inputs.host_provenance_only",
            "inputs.wine_baseline != 'wiage-11.13'",
            "!inputs.use_macos26_runner",
            "inputs.try_48_msi",
            "inputs.try_48_direct",
            "inputs.try_48_intermediate",
            "inputs.try_48_payload_host",
            "inputs.drain_native40_ngen",
            "inputs.pause_native_ngen_queue",
            "inputs.ngen_host_stack64",
        ):
            with self.subTest(item=item):
                self.assertIn(item, guard)
        self.assertIn("exit 1", guard)

    def test_probe_runs_only_when_true_original_native_clr_is_verified(self):
        text = WORKFLOW.read_text(encoding="utf-8")
        marker = (
            "- name: Drain authentic CLR4 NGen when original x64 and x86 "
            "managed code survived restart")
        next_marker = "- name: Reject combining host-provenance-only with any 4.8 installer experiment"
        self.assertLess(text.index("Capture genuine 4.0 Wine mscoree CLR"), text.index(marker))
        self.assertLess(text.index("Test original installed .NET 4.0 public CLRCreateInstance"), text.index(marker))
        self.assertLess(text.index(marker), text.index(next_marker))
        step = text.split(marker, 1)[1].split(next_marker, 1)[0]
        for required in (
            "env.SWCOMPAT_NATIVE40_READY == 'yes'",
            "inputs.try_40_core_msi_recovery",
            "inputs.probe_native40_ngen_if_ready",
            "inputs.host_provenance_only",
            "ulimit -s 65520",
            '[[ "$(ulimit -s)" == "65520" ]]',
            "scripts.netfx48_native_ngen_drain",
            "build/netfx40-core-path-ngen-drain.json",
            "--native40-report build/netfx40-msxml3-restart.json",
            "--observe-wine-failures",
            "--agree-disposable-prefix",
        ):
            with self.subTest(required=required):
                self.assertIn(required, step)
        self.assertNotIn("continue-on-error: true", step)
        self.assertNotIn("msiexec.exe", step)

    def test_no_false_green_and_no_full_install_claims(self):
        text = WORKFLOW.read_text(encoding="utf-8")
        assert_marker = "core_ngen_requested = os.environ.get(\"SWCOMPAT_CORE_NGEN\") == \"true\""
        self.assertIn("SWCOMPAT_CORE_NGEN: ${{ inputs.probe_native40_ngen_if_ready }}", text)
        validator = text.split(
            "- name: Validate that msxml3 cannot fabricate a CLR install", 1)[1]
        self.assertIn(assert_marker, validator)
        self.assertIn(
            'core_ngen_requested and rr["persistent_native_managed"]',
            validator,
        )
        self.assertIn("assert valid_drain(ngen_report)", validator)
        self.assertIn('assert ngen_report["status"] in {"READY", "BLOCKED"}', validator)
        self.assertIn('core["status"] == "SKIPPED_ALREADY_NATIVE"', validator)
        self.assertIn('core["framework40_installed"] is False', validator)
        self.assertIn('core["framework48_installed"] is False', validator)
        self.assertIn("build/netfx40-core-path-ngen-drain.json", text)
        self.assertIn("adaptive_native40_ngen_x64_signals", text.replace("{arch}", "x64"))
        self.assertNotIn("bypass-assembly", text)
        self.assertNotIn("fake Release", text)


if __name__ == "__main__":
    unittest.main()
