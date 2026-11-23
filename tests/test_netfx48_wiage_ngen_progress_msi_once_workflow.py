"""Original signed .NET 4.8 MSI must follow successful genuine x64 and x86 CLR4 NGen.

No original Microsoft media, private logs or Wine subprocesses are used here.
"""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
CALLER = ROOT / ".github/workflows/netfx48-wiage-ngen-progress-msi-once-ci.yml"
REUSE = ROOT / ".github/workflows/netfx40-legacy-ci.yml"


class Signed48AfterProgressNgenTests(unittest.TestCase):
    def test_one_shot_runs_on_main_only_and_never_exports_vendor_media(self):
        caller = CALLER.read_text(encoding="utf-8")
        self.assertIn(
            "  push:\n    branches: [main]\n    paths:\n"
            "      - '.github/workflows/netfx48-wiage-ngen-progress-msi-once-ci.yml'",
            caller)
        self.assertIn("uses: ./.github/workflows/netfx40-legacy-ci.yml", caller)
        for expected in (
            "wine_baseline: 'wiage-11.13'",
            "use_macos26_runner: true",
            "host_provenance_only: false",
            "try_40_core_msi_recovery: false",
            "probe_native40_ngen_if_ready: false",
            "try_48_direct: false",
            "try_48_intermediate: false",
            "try_48_payload_host: false",
            "try_48_msi: true",
            "drain_native40_ngen: true",
            "ngen_host_stack64: true",
            "progress_gated_native40_ngen: true",
            "signed_msi_timeout_seconds: 420",
            "prepare_48_assembly_cache: true",
            "pause_native_ngen_queue: false",
            "cancel-in-progress: false",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, caller)
        for forbidden in (
            "workflow_dispatch:", "pull_request:", "secrets:",
            "actions/upload-artifact", "actions/download-artifact",
        ):
            self.assertNotIn(forbidden, caller)

    def test_grace_requires_authentic_original_stack_and_signed_msi(self):
        reuse = REUSE.read_text(encoding="utf-8")
        self.assertEqual(reuse.count("progress_gated_native40_ngen:"), 2)
        guard = reuse.split(
            "- name: Reject progress-gated NGen outside genuine Wiage signed "
            ".NET 4.8 MSI servicing", 1)[1].split(
            "- name: Fetch selected Microsoft media privately", 1)[0]
        for value in (
            "inputs.progress_gated_native40_ngen",
            "!inputs.drain_native40_ngen",
            "!inputs.ngen_host_stack64",
            "!inputs.try_48_msi",
            "inputs.host_provenance_only",
            "inputs.wine_baseline != 'wiage-11.13'",
            "!inputs.use_macos26_runner",
            "inputs.pause_native_ngen_queue",
            "inputs.try_48_direct",
            "inputs.try_48_intermediate",
            "inputs.try_48_payload_host",
            "inputs.try_40_core_msi_recovery",
            "inputs.probe_native40_ngen_if_ready",
            "inputs.signed_msi_timeout_seconds != 420",
            "exit 1",
        ):
            with self.subTest(value=value):
                self.assertIn(value, guard)

    def test_drain_runs_before_original_msi_and_has_bounded_runtime(self):
        workflow = REUSE.read_text(encoding="utf-8")
        begin = workflow.index(
            "- name: Drain genuine original Microsoft CLR4 NGen x64 and x86 "
            "queues before signed 4.8 MSI")
        signed_msi = workflow.index(
            "- name: Extract authenticated original .NET 4.8 x64 MSI and MSP", begin)
        block = workflow[begin:signed_msi]
        self.assertIn("env.SWCOMPAT_NATIVE40_READY == 'yes'", block)
        self.assertIn("inputs.drain_native40_ngen", block)
        self.assertIn(
            "SWCOMPAT_NGEN_PROGRESS_GRACE: ${{ inputs.progress_gated_native40_ngen }}",
            block)
        self.assertIn("ulimit -s 65520", block)
        self.assertIn("trace_flags+=(--extend-if-progress)", block)
        self.assertIn("--observe-wine-failures", block)
        self.assertIn("--native40-report build/netfx40-msxml3-restart.json", block)
        self.assertIn("--agree-disposable-prefix", block)
        self.assertNotIn("continue-on-error: true", block)
        self.assertNotIn("msiexec.exe", block)
        self.assertIn(
            "inputs.progress_gated_native40_ngen && 55",
            workflow)
        native = (ROOT / "scripts/netfx48_native_ngen_drain.py").read_text(
            encoding="utf-8")
        self.assertIn("PROGRESS_GRACE_SECONDS = 180", native)
        self.assertIn("MAX_PROGRESS_EXTENSIONS = 2", native)
        self.assertIn("grown > previous_growth", native)
        self.assertIn("raise", native)

    def test_msi_and_481_are_blocked_without_genuine_runtime(self):
        workflow = REUSE.read_text(encoding="utf-8")
        self.assertIn("--msi-timeout-seconds \"$SWCOMPAT_SIGNED_MSI_TIMEOUT\"", workflow)
        self.assertIn('assert valid_drain(drain)', workflow)
        self.assertIn('drain_ready = drain["ready"]', workflow)
        self.assertIn(
            'if result["native48_candidate"]:', workflow)
        self.assertIn(
            "SWCOMPAT_NATIVE48_READY=yes", workflow)
        self.assertIn(
            "env.SWCOMPAT_NATIVE48_READY == 'yes'", workflow)
        self.assertIn(
            "build/netfx40-to-48-signed-msi.json", workflow)
        self.assertIn(
            'assert valid_msi(msi)', workflow)


if __name__ == "__main__":
    unittest.main()
