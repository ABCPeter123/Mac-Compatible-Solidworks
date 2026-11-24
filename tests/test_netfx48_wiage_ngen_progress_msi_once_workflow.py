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
            "retry_growing_native40_ngen_nonzero: true",
            "signed_msi_timeout_seconds: 420",
            "prepare_48_assembly_cache: true",
            "pause_native_ngen_queue: false",
            "pause_after_verified_native40_ngen: false",
            "signed_msi_win10_profile: true",
            "signed_msp_win32_exit: true",
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

    def test_genuine_queue_pause_can_only_follow_proven_original_native_clr4_drain(self):
        caller = CALLER.read_text(encoding="utf-8")
        reusable = REUSE.read_text(encoding="utf-8")
        self.assertIn("pause_after_verified_native40_ngen: false", caller)
        self.assertIn("pause_native_ngen_queue: false", caller)
        self.assertEqual(reusable.count("pause_after_verified_native40_ngen:"), 2)
        guard = reusable.split(
            "- name: Reject Microsoft NGen post-preflight queue pause outside "
            "authenticated signed .NET 4.8 servicing", 1)[1].split(
            "- name: Reject progress-gated NGen", 1)[0]
        for precondition in (
            "inputs.pause_after_verified_native40_ngen",
            "!inputs.progress_gated_native40_ngen",
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
            with self.subTest(precondition=precondition):
                self.assertIn(precondition, guard)
        msi = reusable.split(
            "- name: Extract authenticated original .NET 4.8 x64 MSI and MSP "
            "after genuine CLR4.0", 1)[1].split(
            "- name: Gate 4.8.1 on authenticated original MSI", 1)[0]
        self.assertIn(
            "SWCOMPAT_PAUSE_NGEN_QUEUE: ${{ inputs.pause_native_ngen_queue || inputs.pause_after_verified_native40_ngen }}",
            msi)
        self.assertIn('cache_flags+=(--pause-native-ngen-queue)', msi)
        self.assertIn("--native40-report build/netfx40-msxml3-restart.json", msi)
        self.assertIn("--msi-timeout-seconds", msi)
        native = (ROOT / "scripts/netfx40_to_48_signed_msi.py").read_text(
            encoding="utf-8")
        self.assertIn("prepare_queue(wine, prefix, env, private_run)", native)
        self.assertIn("queue_report = resume_queue(", native)
        self.assertIn('result["patch"] == "SUCCESS"', native)
        self.assertIn('result["ngen_queue"]["status"] == "COMPLETE"', native)
        self.assertNotIn("WINEDLLOVERRIDES=ngen.exe=d", native)
        self.assertNotIn("REINSTALLMODE=vomus", native)

    def test_win10_msi_profile_is_pinned_to_real_clr4_preflight_no_pause(self):
        caller = CALLER.read_text(encoding="utf-8")
        reusable = REUSE.read_text(encoding="utf-8")
        self.assertIn("signed_msi_win10_profile: true", caller)
        self.assertIn("pause_after_verified_native40_ngen: false", caller)
        self.assertEqual(reusable.count("signed_msi_win10_profile:"), 2)
        guard = reusable.split(
            "- name: Reject signed .NET 4.8 Win10 profile outside verified "
            "original CLR4 servicing", 1)[1].split(
            "- name: Reject Microsoft NGen post-preflight queue pause", 1)[0]
        for precondition in (
            "inputs.signed_msi_win10_profile",
            "!inputs.progress_gated_native40_ngen",
            "!inputs.drain_native40_ngen",
            "!inputs.ngen_host_stack64",
            "!inputs.try_48_msi",
            "inputs.host_provenance_only",
            "inputs.wine_baseline != 'wiage-11.13'",
            "!inputs.use_macos26_runner",
            "inputs.pause_native_ngen_queue",
            "inputs.pause_after_verified_native40_ngen",
            "inputs.try_48_direct",
            "inputs.try_48_intermediate",
            "inputs.try_48_payload_host",
            "inputs.try_40_core_msi_recovery",
            "inputs.probe_native40_ngen_if_ready",
            "inputs.signed_msi_timeout_seconds != 420",
            "exit 1",
        ):
            with self.subTest(precondition=precondition):
                self.assertIn(precondition, guard)
        msi = reusable.split(
            "- name: Extract authenticated original .NET 4.8 x64 MSI and MSP "
            "after genuine CLR4.0", 1)[1].split(
            "- name: Gate 4.8.1 on authenticated original MSI", 1)[0]
        self.assertIn(
            "SWCOMPAT_MSI_WIN10: ${{ inputs.signed_msi_win10_profile }}", msi)
        self.assertIn("cache_flags+=(--install-profile win10)", msi)
        self.assertIn('"\u0024{cache_flags[@]}"', msi)
        self.assertIn("--native40-report build/netfx40-msxml3-restart.json", msi)
        native = (ROOT / "scripts/netfx40_to_48_signed_msi.py").read_text(
            encoding="utf-8")
        self.assertIn('install_profile: str = "win7"', native)
        self.assertIn('_set_winver(wine, prefix, env, install_profile)', native)
        self.assertIn('install_profile=a.install_profile', native)
        self.assertIn('result["patch"] == "SUCCESS"', native)
        self.assertIn('result["native40_persistent"]', native)
        self.assertIn('result["restart"] == "COMPLETED"', native)

    def test_native_msp_full_win32_exit_only_in_authenticated_signed_msi_arm(self):
        caller = CALLER.read_text(encoding="utf-8")
        reusable = REUSE.read_text(encoding="utf-8")
        self.assertIn("signed_msp_win32_exit: true", caller)
        self.assertEqual(reusable.count("signed_msp_win32_exit:"), 2)
        guard = reusable.split(
            "- name: Reject native full Win32 MSP exit probe outside authentic "
            "original signed Microsoft 4.8", 1)[1].split(
            "- name: Reject signed .NET 4.8 Win10 profile", 1)[0]
        for field in (
            "inputs.signed_msp_win32_exit", "!inputs.signed_msi_win10_profile",
            "!inputs.progress_gated_native40_ngen", "!inputs.drain_native40_ngen",
            "!inputs.ngen_host_stack64", "!inputs.try_48_msi",
            "inputs.host_provenance_only", "inputs.wine_baseline != 'wiage-11.13'",
            "!inputs.use_macos26_runner", "inputs.pause_native_ngen_queue",
            "inputs.pause_after_verified_native40_ngen", "inputs.try_48_direct",
            "inputs.try_48_intermediate", "inputs.try_48_payload_host",
            "inputs.try_40_core_msi_recovery", "inputs.probe_native40_ngen_if_ready",
            "inputs.signed_msi_timeout_seconds != 420", "exit 1",
        ):
            with self.subTest(field=field):
                self.assertIn(field, guard)
        self.assertIn("build/netfx48_msp_win32_status.exe", reusable)
        self.assertIn("netfx48_msp_win32_status.c", reusable)
        self.assertIn("SWCOMPAT_MSP_WIN32_EXIT_HEX=00000643", reusable)
        msi = reusable.split(
            "- name: Extract authenticated original .NET 4.8 x64 MSI and MSP "
            "after genuine CLR4.0", 1)[1].split(
            "- name: Gate 4.8.1 on authenticated original MSI", 1)[0]
        self.assertIn("SWCOMPAT_MSP_WIN32: ${{ inputs.signed_msp_win32_exit }}", msi)
        self.assertIn("cache_flags+=(--patch-fixture build/netfx48_msp_win32_status.exe)", msi)
        self.assertNotIn("REINSTALLMODE=", msi)
        self.assertNotIn("continue-on-error", msi)
        native = (ROOT / "scripts/netfx40_to_48_signed_msi.py").read_text()
        for part in ("parse_win32_patch(", "win32_patch_status(patch_win32)",
                     "patch_win32_mode", "patch_fixture=a.patch_fixture",
                     "TIMED_OUT_CLEANUP_DENIED"):
            with self.subTest(part=part):
                self.assertIn(part, native)

    def test_one_bounded_ngen_retry_only_after_monitored_real_progress(self):
        reusable = REUSE.read_text(encoding="utf-8")
        caller = CALLER.read_text(encoding="utf-8")
        self.assertEqual(reusable.count(
            "retry_growing_native40_ngen_nonzero:"), 2)
        # Previous previous-SHA attempt 2 was cancelled before native NGen.
        # This intentional one-shot must exercise exactly the retry opt-in.
        self.assertEqual(caller.count(
            "retry_growing_native40_ngen_nonzero: true"), 1)
        self.assertIn("drain_native40_ngen: true", caller)
        self.assertIn("progress_gated_native40_ngen: true", caller)
        self.assertIn("ngen_host_stack64: true", caller)
        self.assertIn("signed_msp_win32_exit: true", caller)
        self.assertIn("pause_native_ngen_queue: false", caller)
        self.assertIn("pause_after_verified_native40_ngen: false", caller)
        guard = reusable.split(
            "- name: Reject NGen one-time progress retry outside isolated "
            "original Microsoft CLR4 servicing", 1)[1].split(
            "- name: Reject original CLR4 x64 MSI recovery", 1)[0]
        for item in (
            "inputs.retry_growing_native40_ngen_nonzero",
            "!inputs.progress_gated_native40_ngen",
            "!inputs.drain_native40_ngen",
            "!inputs.ngen_host_stack64",
            "!inputs.try_48_msi",
            "inputs.host_provenance_only",
            "inputs.wine_baseline != 'wiage-11.13'",
            "!inputs.use_macos26_runner",
            "inputs.pause_native_ngen_queue",
            "inputs.pause_after_verified_native40_ngen",
            "inputs.try_48_direct",
            "inputs.try_48_intermediate",
            "inputs.try_48_payload_host",
            "inputs.try_40_core_msi_recovery",
            "inputs.probe_native40_ngen_if_ready",
            "inputs.signed_msi_timeout_seconds != 420",
            "exit 1",
        ):
            with self.subTest(item=item):
                self.assertIn(item, guard)
        block = reusable.split(
            "- name: Drain genuine original Microsoft CLR4 NGen x64 and x86 "
            "queues before signed 4.8 MSI", 1)[1].split(
            "- name: Extract authenticated original .NET 4.8", 1)[0]
        self.assertIn(
            "SWCOMPAT_NGEN_RETRY_ON_PROGRESS: "
            "${{ inputs.retry_growing_native40_ngen_nonzero }}", block)
        self.assertIn("trace_flags+=(--retry-growing-nonzero)", block)
        self.assertIn("trace_flags+=(--observe-wine-failures)", block)
        self.assertIn("trace_flags+=(--extend-if-progress)", block)
        self.assertNotIn("continue-on-error: true", block)
        native = (ROOT / "scripts/netfx48_native_ngen_drain.py").read_text()
        self.assertIn("retry_growing_nonzero: bool = False", native)
        self.assertIn("and progress.report[arch + \"_growth_windows\"] > first_growth", native)
        self.assertIn("result[\"wine_trace\"][arch][\"status\"] == \"NO_SIGNATURE\"", native)
        self.assertIn("extend_if_progress=False", native)
        self.assertIn('"EXIT_SIGNALLED"', native)

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
