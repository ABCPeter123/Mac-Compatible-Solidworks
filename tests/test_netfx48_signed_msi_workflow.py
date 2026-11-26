"""CI must keep original signed MSI trial isolated from Winetricks and 4.8.1."""
from pathlib import Path
from unittest import TestCase

ROOT = Path(__file__).resolve().parents[1]
LEGACY = ROOT / ".github/workflows/netfx40-legacy-ci.yml"
ONCE = ROOT / ".github/workflows/netfx48-wiage-ngen-progress-msi-once-ci.yml"


class SignedMSIGates(TestCase):

    def test_current_authenticated_signed_msi_one_shot_is_only_self_triggered(self):
        caller = ONCE.read_text(encoding="utf-8")
        for item in (
            "branches: [main]",
            "- '.github/workflows/netfx48-wiage-ngen-progress-msi-once-ci.yml'",
            "uses: ./.github/workflows/netfx40-legacy-ci.yml",
            "try_48_msi: true", "try_48_direct: false",
            "try_48_intermediate: false", "try_48_payload_host: false",
            "host_provenance_only: false", "use_macos26_runner: true",
            "wine_baseline: 'wiage-11.13'",
            "drain_native40_ngen: true", "ngen_host_stack64: true",
            "progress_gated_native40_ngen: true",
            "retry_growing_native40_ngen_nonzero: true",
            "signed_msp_win32_exit: true",
            "prepare_48_assembly_cache: true", "signed_msi_timeout_seconds: 1200",
            "signed_msp_reinstall: true",
            "pause_native_ngen_queue: false",
            "pause_after_verified_native40_ngen: false",
            "cancel-in-progress: false",
        ):
            with self.subTest(item=item):
                self.assertIn(item, caller)
        self.assertNotIn("workflow_dispatch:", caller)
        self.assertNotIn("actions/upload-artifact", caller)
        self.assertNotIn("REINSTALLMODE=", caller)

    def test_authentic_installer_diagnostics_still_use_real_scm_and_ngen(self):
        reusable = LEGACY.read_text(encoding="utf-8")
        for item in (
            "--service-fixture build/netfx48_scm_service_probe.exe",
            "msi['scm_preflight']['services'][service]",
            "signed_msi_48_scm_state_{service}",
            "signed_msi_48_scm_post_state_{service}",
            "--prepare-assembly-cache",
            "SWCOMPAT_PREPARE_ASSEMBLY_CACHE",
            "signed_msi_48_{key}",
            '"cache_state"',
            '"${cache_flags[@]}"',
            'msi["ngen_log"]',
            "signed_msi_48_ngen_{field}",
            "signed_msi_48_ngen_queue_{field}",
            "SWCOMPAT_PAUSE_NGEN_QUEUE",
            "--pause-native-ngen-queue",
            "signed_msi_48_patch_win32_",
        ):
            with self.subTest(item=item):
                self.assertIn(item, reusable)
        fixture = (ROOT / "probes/netfx48_scm_service_probe.c").read_text(
            encoding="utf-8")
        for item in (
            'L"MSDTC"', "QueryServiceStatusEx(",
            "SERVICE_QUERY_STATUS", "SWCOMPAT_SCM_API_SCHEMA=2",
        ):
            self.assertIn(item, fixture)
        for forbidden in (
            "StartServiceW(", "CreateServiceW(", "ChangeServiceConfigW(",
        ):
            self.assertNotIn(forbidden, fixture)
        control = (ROOT / "scripts/netfx48_ngen_queue_control.py").read_text(
            encoding="utf-8")
        self.assertIn('"mscoree=n;clr=n"', control)
        self.assertIn('"queue", operation', control)
        self.assertNotIn("CreateServiceW", control)
        self.assertNotIn("StartServiceW", control)

    def test_current_one_shot_keeps_bounded_signed_msi_and_non_cancelled_run(self):
        caller = ONCE.read_text(encoding="utf-8")
        reusable = LEGACY.read_text(encoding="utf-8")
        self.assertIn("cancel-in-progress: false", caller)
        self.assertIn("concurrency:", reusable)
        self.assertIn(
            "(inputs.try_48_msi || inputs.try_48_direct || "
            "inputs.try_48_intermediate) && github.sha || 'shared'", reusable)
        self.assertIn(
            "cancel-in-progress: ${{ !inputs.try_48_msi && "
            "!inputs.try_48_direct && !inputs.try_48_intermediate && "
            "!inputs.try_wow64_managed && !inputs.try_40_core_msi_recovery }}",
            reusable)
        self.assertNotIn("cancel-in-progress: true", reusable)
        self.assertIn(
            "timeout-minutes: ${{ inputs.signed_msp_reinstall && inputs.signed_msi_timeout_seconds "
            "== 1200 && 70 || inputs.progress_gated_native40_ngen && 55 "
            "|| inputs.try_48_msi && inputs.signed_msi_timeout_seconds "
            "== 1200 && 55", reusable)
        self.assertIn('--msi-timeout-seconds "$SWCOMPAT_SIGNED_MSI_TIMEOUT"',
                      reusable)
        self.assertIn("signed_msi_timeout_seconds:", reusable)
        self.assertIn('"msi_timeout_seconds"', reusable)
        self.assertIn('"patch_win32_mode"', reusable)
        self.assertIn('"patch_win32"', (ROOT /
            "scripts/netfx40_to_48_signed_msi.py").read_text())

    def test_signed_ngen_summary_uses_actual_line_breaks(self):
        # A double-escaped newline prints literal backslash-n into the CI
        # summary and merges independent NGen fields into one unreadable line.
        source = LEGACY.read_text(encoding="utf-8")
        self.assertIn(r"""f"{msi['ngen_log'][field]}**\n\n")""", source)
        self.assertNotIn(r"""f"{msi['ngen_log'][field]}**\\n\\n")""", source)

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

    def test_genuine_x86_runtime_controls_cannot_cancel_other_active_experiments(self):
        source = LEGACY.read_text(encoding="utf-8")
        self.assertIn(
            "inputs.try_wow64_managed && format('wow64-{0}-{1}-{2}-{3}', github.sha, inputs.wine_baseline, inputs.use_macos26_runner, inputs.wow64_host_stack64)",
            source)
        self.assertIn(
            "cancel-in-progress: ${{ !inputs.try_48_msi && !inputs.try_48_direct && !inputs.try_48_intermediate && !inputs.try_wow64_managed && !inputs.try_40_core_msi_recovery }}",
            source)
        for filename in (
            "netfx40-wow64-x86-once-ci.yml",
            "netfx40-wiage-rosetta-clr4-once-ci.yml",
        ):
            caller = (ROOT / ".github/workflows" / filename).read_text(
                encoding="utf-8")
            self.assertIn("try_wow64_managed: true", caller)
            self.assertIn("cancel-in-progress: false", caller)
            self.assertIn("host_provenance_only: true", caller)
            self.assertIn("try_48_msi: false", caller)
        self.assertNotIn("cancel-in-progress: true", source)

    def test_native_wow64_rossetta_fault_triage_isolated_from_signed_msi(self):
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
        reusable = LEGACY.read_text(encoding="utf-8")
        self.assertEqual(reusable.count("wow64_host_stack64:"), 2)
        # This assertion must count only the existing two x86 WoW64 steps.
        # The separately guarded original x64 NGen stack A/B does not change
        # the WoW64 experiment or its two inherited stack controls.
        x86_steps = [step for step in reusable.split("      - name: ")
                     if "SWCOMPAT_X86_HOST_STACK64:" in step]
        self.assertEqual(len(x86_steps), 2)
        self.assertTrue(all("ulimit -s 65520" in step for step in x86_steps))
        self.assertEqual(reusable.count("SWCOMPAT_X86_HOST_STACK64:"), 2)
        self.assertEqual(reusable.count('[[ "$actual_stack" != "65520" ]]'), 2)
        self.assertIn("native_microsoft_wow64_host_stack_kib", reusable)
        self.assertIn("default: false", reusable)
        before = reusable.index("- name: Diagnose new WoW64 x86 process startup")
        after = reusable.index("- name: Capture genuine 4.0 Wine mscoree")
        self.assertGreater(after, before)
        for step in x86_steps:
            self.assertTrue(
                step.startswith("Diagnose new WoW64 x86 process startup")
                or step.startswith("Verify native Microsoft CLR4 x86 managed"))
            self.assertIn('inputs.wow64_host_stack64', step)
            self.assertIn("python3 - <<'PY'", step)

    def test_pinned_wiage_engine_exclusively_allows_authenticated_install_routes(self):
        caller = (ROOT / ".github/workflows/netfx40-wiage-rosetta-clr4-once-ci.yml").read_text(
            encoding="utf-8")
        for token in ("branches: [main]", "wine_baseline: 'wiage-11.13'",
                      "use_macos26_runner: true", "host_provenance_only: true",
                      "try_wow64_managed: true", "try_wow64_faults: true",
                      "wow64_host_stack64: false", "cancel-in-progress: false",
                      "try_48_msi: false", "try_48_direct: false",
                      "try_48_intermediate: false", "try_48_payload_host: false"):
            self.assertIn(token, caller)
        self.assertNotIn("actions/upload-artifact", caller)
        reusable = LEGACY.read_text(encoding="utf-8")
        self.assertIn('[[ "$SWCOMPAT_WINE_BASELINE" == "wiage-11.13" ]]', reusable)
        self.assertIn("SWCOMPAT_HOST_ONLY:", reusable)
        self.assertIn("SWCOMPAT_MACOS26:", reusable)
        for env_name in ("SWCOMPAT_WIAGE_TRY_MSI", "SWCOMPAT_WIAGE_TRY_DIRECT",
                         "SWCOMPAT_WIAGE_TRY_INTERMEDIATE", "SWCOMPAT_WIAGE_TRY_PAYLOAD"):
            self.assertIn(env_name + ":", reusable)
        for env_name in ("SWCOMPAT_WIAGE_TRY_INTERMEDIATE", "SWCOMPAT_WIAGE_TRY_PAYLOAD"):
            self.assertIn('"' + "$" + env_name + '" != "false"', reusable)
        self.assertIn("d0cea7ff492dd3801dfa26a2a7d5ed1331e60f65929318d17301a3ce9cbba56c",
                      reusable)
        self.assertIn("github.com/dttdrv/mage/releases/download/preview-2026-08-02",
                      reusable)
        self.assertIn("python3 -m scripts.wine_engine_archive", reusable)
        self.assertIn("wiage/bin/wine", reusable)
        self.assertIn("wiage/bin/wineserver", reusable)
        self.assertIn("SWCOMPAT_WIAGE_TRY_DIRECT:", reusable)
        self.assertIn('"$SWCOMPAT_HOST_ONLY:$SWCOMPAT_WIAGE_TRY_DIRECT:$SWCOMPAT_WIAGE_TRY_MSI:$SWCOMPAT_WIAGE_TRY_CATALOG"', reusable)
        self.assertIn("true:false:false:false|false:true:false:false|false:false:true:false|false:false:false:true)", reusable)
        self.assertIn("Wiage must select exactly one of CLR4 host, signed 4.8 direct, signed 4.8 MSI or catalog WUSA", reusable)
        direct = (ROOT / ".github/workflows/netfx48-wiage-direct-once-ci.yml").read_text(
            encoding="utf-8")
        for value in ("host_provenance_only: false", "try_48_direct: true",
                      "try_48_msi: false", "try_48_intermediate: false",
                      "try_48_payload_host: false", "wine_baseline: 'wiage-11.13'"):
            self.assertIn(value, direct)
        self.assertIn("Unsupported Wine baseline", reusable)
        self.assertIn("d7bcd5abf4df27aae397a7898aef074fea4a2e0b51e0a55aa9659517bbf9d452",
                      reusable)
        self.assertIn("940bdd1a177872020be01c5c33917cb8eecc1cc3193ad554914fb6efd90d7889",
                      reusable)

    def test_unclean_wow64_process_group_prints_only_finite_status_then_stops(self):
        source = LEGACY.read_text(encoding="utf-8")
        step = source.split("      - name: Diagnose new WoW64 x86 process startup", 1)[1].split(
            "      - name: Verify native Microsoft CLR4 x86 managed execution", 1)[0]
        a = step.index("assert valid(outcome)")
        b = step.index('print("Native original CLR4 WoW64 x86 diagnostic", key, value)')
        c = step.index("TIMED_OUT_CLEANUP_DENIED", b)
        d = step.index('raise RuntimeError("Unsafe WoW64 process group cleanup;', c)
        self.assertLess(a, b)
        self.assertLess(b, c)
        self.assertLess(c, d)
        self.assertNotIn("print(raw)", step)
        self.assertNotIn("print(m_raw)", step)
        self.assertNotIn("subprocess.run(", step)
        self.assertNotIn("subprocess.Popen(", step)
        self.assertNotIn("os.system(", step)

    def test_wiage_startup_uses_patched_helper_background_and_msync_only(self):
        workflow = LEGACY.read_text(encoding="utf-8")
        step = workflow.split(
            "      - name: Initialize new marked Wine x64 prefix for msxml3 fix",
            1)[1].split("      - name: Install native msxml3", 1)[0]
        self.assertIn('SWCOMPAT_WINE_BASELINE: ${{ inputs.wine_baseline }}', step)
        self.assertIn('[[ "$SWCOMPAT_WINE_BASELINE" == "wiage-11.13" ]]', step)
        self.assertIn('export MAGE_BACKGROUND_EXE=rundll32.exe:services.exe:', step)
        self.assertIn('export WINEMSYNC=1', step)
        self.assertIn('echo "WINEMSYNC=1" >> "$GITHUB_ENV"', step)
        self.assertIn('BOOT_TIMEOUT=120', step)
        self.assertIn('BOOTSTRAP_OVERRIDE=(--skip-bootstrap-mono-gecko)', step)
        self.assertIn('BOOTSTRAP_OVERRIDE=()', step)
        self.assertIn('"${BOOTSTRAP_OVERRIDE[@]}"', step)
        self.assertIn('BOOT_TIMEOUT=240', step)
        self.assertIn('init --timeout "$BOOT_TIMEOUT"', step)
        self.assertIn('touch "$RUNNER_TEMP/netfx40-msxml3-prefix/.swcompat-netfx481-disposable"',
                      step)
        self.assertNotIn('try_48_msi: true', workflow.split(
            "      - name: Initialize new marked Wine x64 prefix for msxml3 fix",
            1)[1].split("      - name: Install native msxml3", 1)[0])
        self.assertIn('EXPECTED_SHA=d0cea7ff492dd3801dfa26a2a7d5ed1331e60f65929318d17301a3ce9cbba56c', workflow)

    def test_public_wiage_wineboot_control_is_no_original_microsoft_media(self):
        control = (ROOT / ".github/workflows/wiage-wineboot-once-ci.yml").read_text(
            encoding="utf-8")
        for token in ("branches: [main]", "runs-on: macos-26",
                      "cancel-in-progress: false",
                      "d0cea7ff492dd3801dfa26a2a7d5ed1331e60f65929318d17301a3ce9cbba56c",
                      "python3 -m scripts.wine_engine_archive",
                      "COPYFILE_DISABLE=1 tar --exclude='._*'",
                      "WINEMSYNC: '1'",
                      "MAGE_BACKGROUND_EXE: 'rundll32.exe:services.exe:explorer.exe:conhost.exe'",
                      "init --timeout 120", "probe-win32"):
            self.assertIn(token, control)
        self.assertIn("--skip-bootstrap-mono-gecko", control)
        for forbidden in ("netfx40-legacy-ci.yml", "dotNetFx40", "dotnet48",
                          "try_48_msi: true", "SOLIDWORKS installer",
                          "actions/upload-artifact", "workflow_dispatch"):
            self.assertNotIn(forbidden, control)
        self.assertIn("original Microsoft software", control)

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
