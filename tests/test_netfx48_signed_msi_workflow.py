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
