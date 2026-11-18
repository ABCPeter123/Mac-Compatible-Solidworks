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

    def test_original_signed_msi_timeout_action_rerun_is_main_only(self):
        source = (ROOT / ".github/workflows/netfx48-signed-msi-timeout-action-once-ci.yml"
                  ).read_text(encoding="utf-8")
        self.assertIn("branches: [main]", source)
        self.assertIn(
            "      - '.github/workflows/netfx48-signed-msi-timeout-action-once-ci.yml'",
            source)
        self.assertIn("      try_48_msi: true", source)
        for key in ("try_48_direct: false", "try_48_intermediate: false",
                    "host_provenance_only: false", "try_48_payload_host: false",
                    "use_macos26_runner: true", "wine_baseline: '11.21'"):
            self.assertIn(key, source)
        self.assertNotIn("actions/upload-artifact", source)

    def test_missing_service_rootcause_caller_is_main_only_and_read_only(self):
        root = ROOT / ".github/workflows/netfx48-msi-service-rootcause-once-ci.yml"
        source = root.read_text(encoding="utf-8")
        self.assertIn("branches: [main]", source)
        self.assertIn(
            "      - '.github/workflows/netfx48-msi-service-rootcause-once-ci.yml'",
            source)
        self.assertIn("      try_48_msi: true", source)
        for expected in (
            "host_provenance_only: false", "try_48_direct: false",
            "try_48_intermediate: false", "try_48_payload_host: false",
            "wine_baseline: '11.21'", "use_macos26_runner: true",
            "uses: ./.github/workflows/netfx40-legacy-ci.yml",
        ):
            self.assertIn(expected, source)
        self.assertNotIn("actions/upload-artifact", source)
        self.assertNotIn("sc.exe create", source)

    def test_native_original_scm_optimization_control_is_read_only(self):
        source = (ROOT / ".github/workflows/netfx48-msi-optimizer-scm-once-ci.yml"
                  ).read_text(encoding="utf-8")
        self.assertIn("branches: [main]", source)
        self.assertIn("      - '.github/workflows/netfx48-msi-optimizer-scm-once-ci.yml'", source)
        self.assertIn("      try_48_msi: true", source)
        self.assertIn("      try_48_direct: false", source)
        self.assertIn("      try_48_intermediate: false", source)
        self.assertIn("uses: ./.github/workflows/netfx40-legacy-ci.yml", source)
        self.assertNotIn("actions/upload-artifact", source)
        legacy = LEGACY.read_text(encoding="utf-8")
        self.assertIn("(inputs.try_48_direct || inputs.try_48_msi)", legacy)
        self.assertIn("--service-fixture build/netfx48_scm_service_probe.exe", legacy)
        self.assertIn("msi['scm_preflight']['services'][service]", legacy)

    def test_ngen_cache_trial_is_only_one_shot_signed_msi_and_opt_in(self):
        source = (ROOT / ".github/workflows/netfx48-msi-ngen-cache-once-ci.yml").read_text(encoding="utf-8")
        self.assertIn("branches: [main]", source)
        self.assertIn("      - '.github/workflows/netfx48-msi-ngen-cache-once-ci.yml'", source)
        for expected in ("try_48_msi: true", "prepare_48_assembly_cache: true",
                         "try_48_direct: false", "try_48_intermediate: false",
                         "host_provenance_only: false", "use_macos26_runner: true",
                         "wine_baseline: '11.21'"):
            self.assertIn(expected, source)
        self.assertNotIn("actions/upload-artifact", source)
        self.assertNotIn("sc.exe create", source)
        reusable = LEGACY.read_text(encoding="utf-8")
        self.assertIn("--prepare-assembly-cache", reusable)
        self.assertIn("SWCOMPAT_PREPARE_ASSEMBLY_CACHE", reusable)
        self.assertIn("signed_msi_48_{key}", reusable)
        self.assertIn('"cache_state"', reusable)
        self.assertIn('"${cache_flags[@]}"', reusable)

    def test_ngen_log_msdtc_caller_is_main_only_and_read_only(self):
        source = (ROOT / ".github/workflows/netfx48-msi-ngen-evidence-once-ci.yml").read_text(encoding="utf-8")
        self.assertIn("branches: [main]", source)
        self.assertIn("      - '.github/workflows/netfx48-msi-ngen-evidence-once-ci.yml'", source)
        for item in ("try_48_msi: true", "try_48_direct: false",
                     "try_48_intermediate: false", "try_48_payload_host: false",
                     "prepare_48_assembly_cache: true", "use_macos26_runner: true",
                     "wine_baseline: '11.21'"):
            self.assertIn(item, source)
        self.assertNotIn("actions/upload-artifact", source)
        self.assertNotIn("sc.exe create", source)
        workflow = LEGACY.read_text(encoding="utf-8")
        self.assertIn('msi["ngen_log"]', workflow)
        self.assertIn('msi[\'ngen_log\'][field]', workflow)
        self.assertIn("signed_msi_48_ngen_{field}", workflow)
        fixture = (ROOT / "probes/netfx48_scm_service_probe.c").read_text(encoding="utf-8")
        self.assertIn('{L"MSDTC", "MSDTC"}', fixture)
        self.assertNotIn("CreateServiceW", fixture)
        self.assertNotIn("StartServiceW", fixture)

    def test_ngen_msdtc_diagnostic_queries_real_service_state_without_mutation(self):
        fixture = (ROOT / "probes/netfx48_scm_service_probe.c").read_text(
            encoding="utf-8")
        self.assertIn("QueryServiceStatusEx(", fixture)
        self.assertIn("SERVICE_QUERY_STATUS", fixture)
        self.assertIn("SWCOMPAT_SCM_STATE_%s", fixture)
        self.assertIn("SWCOMPAT_SCM_API_SCHEMA=2", fixture)
        self.assertNotIn("StartServiceW(", fixture)
        self.assertNotIn("CreateServiceW(", fixture)
        self.assertNotIn("ChangeServiceConfigW(", fixture)
        summary = LEGACY.read_text(encoding="utf-8")
        self.assertIn("signed_msi_48_scm_state_{service}", summary)
        self.assertIn("signed_msi_48_scm_post_state_{service}", summary)
        source = (ROOT / ".github/workflows/netfx48-msi-ngen-evidence-once-ci.yml").read_text(
            encoding="utf-8")
        self.assertIn("branches: [main]", source)
        self.assertIn("try_48_msi: true", source)
        self.assertIn("prepare_48_assembly_cache: true", source)
        self.assertNotIn("actions/upload-artifact", source)

    def test_signed_ngen_summary_uses_actual_line_breaks(self):
        # A double-escaped newline prints literal backslash-n into the CI
        # summary and merges independent NGen fields into one unreadable line.
        source = LEGACY.read_text(encoding="utf-8")
        self.assertIn(r"""f"{msi['ngen_log'][field]}**\n\n")""", source)
        self.assertNotIn(r"""f"{msi['ngen_log'][field]}**\\n\\n")""", source)

    def test_original_extended_ngen_budget_is_only_on_isolated_one_shot(self):
        source = (ROOT / ".github/workflows/netfx48-msi-ngen-long-budget-once-ci.yml").read_text(
            encoding="utf-8")
        self.assertIn("branches: [main]", source)
        self.assertIn("      - '.github/workflows/netfx48-msi-ngen-long-budget-once-ci.yml'", source)
        for expected in ("try_48_msi: true", "signed_msi_timeout_seconds: 1200",
                         "try_48_direct: false", "try_48_intermediate: false",
                         "prepare_48_assembly_cache: true", "use_macos26_runner: true",
                         "wine_baseline: '11.21'"):
            self.assertIn(expected, source)
        self.assertNotIn("actions/upload-artifact", source)
        legacy = LEGACY.read_text(encoding="utf-8")
        self.assertIn("timeout-minutes: ${{ inputs.try_48_msi && inputs.signed_msi_timeout_seconds == 1200 && 55 || 35 }}", legacy)
        self.assertIn('--msi-timeout-seconds "$SWCOMPAT_SIGNED_MSI_TIMEOUT"', legacy)
        self.assertIn("signed_msi_timeout_seconds:", legacy)
        self.assertIn('"msi_timeout_seconds"', legacy)

    def test_signed_msi_can_finish_when_new_commit_queues_another_run(self):
        # Critical: a callee's cancel-in-progress: true overrides the one-shot
        # caller's false value and used to cancel genuine Mac MSI experiments.
        source = LEGACY.read_text(encoding="utf-8")
        self.assertIn("concurrency:", source)
        self.assertIn("inputs.try_48_msi && github.sha || 'shared'", source)
        self.assertIn("cancel-in-progress: ${{ !inputs.try_48_msi }}", source)
        self.assertNotIn("cancel-in-progress: true", source)
        for filename in ("netfx48-msi-ngen-evidence-once-ci.yml",
                         "netfx48-msi-ngen-long-budget-once-ci.yml"):
            caller = (ROOT / ".github/workflows" / filename).read_text(
                encoding="utf-8")
            self.assertIn("try_48_msi: true", caller)
            self.assertIn("cancel-in-progress: false", caller)
            self.assertIn("branches: [main]", caller)

    def test_authenticated_ngen_interval_heartbeat_has_fixed_private_boundaries(self):
        source = (ROOT / "scripts/netfx48_ngen_progress.py").read_text(
            encoding="utf-8")
        self.assertIn("MAX_SAMPLES = 24", source)
        self.assertIn("SAMPLE_INTERVAL = 60", source)
        self.assertIn("def sample(self)", source)
        self.assertNotIn("subprocess.run(", source)
        self.assertNotIn("subprocess.Popen(", source)
        self.assertNotIn("read_bytes(", source)
        workflow = LEGACY.read_text(encoding="utf-8")
        self.assertIn("signed_msi_48_ngen_progress_{field}", workflow)
        self.assertIn('valid_progress(msi["ngen_progress"])', workflow)
        runner = (ROOT / "scripts/netfx40_to_48_signed_msi.py").read_text(
            encoding="utf-8")
        self.assertIn("progress=progress.sample", runner)
        self.assertIn("time.monotonic()", runner)
        self.assertIn("ngen_progress = progress.snapshot()", runner)
        self.assertIn("native48_candidate", runner)

    def test_original_x86_wow64_trial_cannot_run_another_signed_msi(self):
        caller = (ROOT / ".github/workflows/netfx40-wow64-x86-once-ci.yml").read_text(
            encoding="utf-8")
        self.assertIn("branches: [main]", caller)
        self.assertIn("      - '.github/workflows/netfx40-wow64-x86-once-ci.yml'", caller)
        self.assertIn("try_wow64_managed: true", caller)
        self.assertIn("host_provenance_only: true", caller)
        for name in ("try_48_msi: false", "try_48_direct: false",
                     "try_48_intermediate: false", "try_48_payload_host: false",
                     "use_macos26_runner: true", "wine_baseline: '11.21'"):
            self.assertIn(name, caller)
        self.assertNotIn("actions/upload-artifact", caller)
        reusable = LEGACY.read_text(encoding="utf-8")
        self.assertIn("try_wow64_managed:", reusable)
        self.assertIn("/platform:x86", reusable)
        self.assertIn("build/netfx40_wow64_managed_probe.exe", reusable)
        self.assertIn("scripts.netfx40_wow64_managed_probe", reusable)
        self.assertIn("native_microsoft_wow64_x86_{key}", reusable)
        module = (ROOT / "scripts/netfx40_wow64_managed_probe.py").read_text(
            encoding="utf-8")
        self.assertIn('override="native_only"', module)
        self.assertIn("flags & 0x2", module)
        self.assertNotIn("WINEDLLOVERRIDES=mscoree=b", module)

    def test_native_microsoft_ngen_queue_control_one_shot_is_narrow_and_authenticated(self):
        path = ROOT / ".github/workflows/netfx48-ngen-queue-pause-once-ci.yml"
        caller = path.read_text(encoding="utf-8")
        for token in ("branches: [main]", "pause_native_ngen_queue: true",
                      "try_48_msi: true", "prepare_48_assembly_cache: true",
                      "signed_msi_timeout_seconds: 420", "try_48_direct: false",
                      "try_48_intermediate: false", "try_48_payload_host: false",
                      "use_macos26_runner: true", "wine_baseline: '11.21'",
                      "cancel-in-progress: false"):
            self.assertIn(token, caller)
        self.assertNotIn("actions/upload-artifact", caller)
        reusable = LEGACY.read_text(encoding="utf-8")
        self.assertIn("pause_native_ngen_queue:", reusable)
        self.assertIn("SWCOMPAT_PAUSE_NGEN_QUEUE", reusable)
        self.assertIn("--pause-native-ngen-queue", reusable)
        self.assertIn("signed_msi_48_ngen_queue_{field}", reusable)
        module = (ROOT / "scripts/netfx48_ngen_queue_control.py").read_text(
            encoding="utf-8")
        self.assertIn('"mscoree=n;clr=n"', module)
        self.assertIn('"queue", operation', module)
        self.assertNotIn("CreateServiceW", module)
        self.assertNotIn("StartServiceW", module)
        self.assertNotIn("ChangeServiceConfigW", module)

    def test_native_wow64_rossetta_fault_triage_isolated_from_signed_msi(self):
        caller = (ROOT / ".github/workflows/netfx40-wow64-fault-triage-once-ci.yml").read_text(
            encoding="utf-8")
        for token in ("branches: [main]", "try_wow64_faults: true",
                      "try_wow64_managed: true", "host_provenance_only: true",
                      "try_48_msi: false", "try_48_direct: false",
                      "try_48_intermediate: false", "try_48_payload_host: false",
                      "wine_baseline: '11.21'", "cancel-in-progress: false"):
            self.assertIn(token, caller)
        self.assertNotIn("actions/upload-artifact", caller)
        reused = LEGACY.read_text(encoding="utf-8")
        self.assertIn("try_wow64_faults:", reused)
        self.assertIn("netfx40_wow64_native_smoke.c", reused)
        self.assertIn("vcvars32.bat", reused)
        self.assertIn("build/netfx40_wow64_native_smoke.exe", reused)
        self.assertIn("scripts.netfx40_wow64_fault_triage", reused)
        self.assertIn("native_microsoft_wow64_fault_{key}", reused)
        diagnostic = (ROOT / "scripts/netfx40_wow64_fault_triage.py").read_text(
            encoding="utf-8")
        self.assertIn('"WINEDEBUG": "+seh"', diagnostic)
        self.assertIn('"mscoree=n;clr=n"', diagnostic)
        self.assertIn("MAX_CAPTURE = 1024 * 1024", diagnostic)
        self.assertNotIn("print(raw)", diagnostic)

    def test_wow64_host_stack_64mb_requires_real_x86_only_and_no_original_msi(self):
        one_shot = (ROOT / ".github/workflows/netfx40-wow64-hoststack64-once-ci.yml").read_text(
            encoding="utf-8")
        for expected in ("branches: [main]", "wow64_host_stack64: true",
                         "try_wow64_managed: true", "try_wow64_faults: true",
                         "host_provenance_only: true", "use_macos26_runner: true",
                         "wine_baseline: '11.21'", "cancel-in-progress: false",
                         "try_48_msi: false", "try_48_direct: false",
                         "try_48_intermediate: false", "try_48_payload_host: false"):
            self.assertIn(expected, one_shot)
        self.assertNotIn("actions/upload-artifact", one_shot)
        reusable = LEGACY.read_text(encoding="utf-8")
        self.assertEqual(reusable.count("wow64_host_stack64:"), 2)
        self.assertEqual(reusable.count("ulimit -s 65520"), 2)
        self.assertEqual(reusable.count("SWCOMPAT_X86_HOST_STACK64:"), 2)
        self.assertEqual(reusable.count('[[ "$actual_stack" != "65520" ]]'), 2)
        self.assertIn("native_microsoft_wow64_host_stack_kib", reusable)
        self.assertIn("default: false", reusable)
        before = reusable.index("- name: Diagnose new WoW64 x86 process startup")
        after = reusable.index("- name: Capture genuine 4.0 Wine mscoree")
        self.assertGreater(after, before)
        for step in reusable.split("      - name: "):
            if "ulimit -s 65520" in step:
                self.assertTrue(
                    step.startswith("Diagnose new WoW64 x86 process startup")
                    or step.startswith("Verify native Microsoft CLR4 x86 managed"))
                self.assertIn('inputs.wow64_host_stack64', step)
                self.assertIn("python3 - <<'PY'", step)

    def test_original_wow64_macos15_version_ab_keeps_exact_native_clr_only(self):
        original = (ROOT / ".github/workflows/netfx40-wow64-hoststack64-once-ci.yml").read_text(
            encoding="utf-8")
        comparison = (ROOT / ".github/workflows/netfx40-wow64-hoststack64-macos15-once-ci.yml").read_text(
            encoding="utf-8")
        for token in ("branches: [main]", "host_provenance_only: true",
                      "try_wow64_managed: true", "try_wow64_faults: true",
                      "wow64_host_stack64: true", "wine_baseline: '11.21'",
                      "cancel-in-progress: false", "try_48_msi: false",
                      "try_48_direct: false", "try_48_intermediate: false",
                      "try_48_payload_host: false"):
            self.assertIn(token, original)
            self.assertIn(token, comparison)
        self.assertIn("use_macos26_runner: true", original)
        self.assertIn("use_macos26_runner: false", comparison)
        self.assertNotIn("actions/upload-artifact", comparison)
        self.assertNotIn("try_48_msi: true", comparison)
        self.assertNotIn("try_48_direct: true", comparison)
        self.assertNotIn("host_provenance_only: false", comparison)
        self.assertIn(
            "- '.github/workflows/netfx40-wow64-hoststack64-macos15-once-ci.yml'",
            comparison)

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
