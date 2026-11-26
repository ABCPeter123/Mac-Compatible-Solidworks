"""Regression guard for real Microsoft .NET 4.8 MSI and MSP on Wiage/Rosetta.

This changes installer entrypoint after the observed original 5100 stopblock,
not Microsoft package contents, release markers or success predicates.
"""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
LEGACY = ROOT / ".github" / "workflows" / "netfx40-legacy-ci.yml"
ONCE = ROOT / ".github" / "workflows" / "netfx48-wiage-msi-once-ci.yml"
MODULE = ROOT / "scripts" / "netfx40_to_48_signed_msi.py"


class SignedWiageMSIOnceTests(unittest.TestCase):
    def test_main_only_separate_authentic_x64_installer_trial(self):
        caller = ONCE.read_text(encoding="utf-8")
        self.assertIn("  push:\n    branches: [main]\n    paths:\n"
                      "      - '.github/workflows/netfx48-wiage-msi-once-ci.yml'", caller)
        self.assertIn("uses: ./.github/workflows/netfx40-legacy-ci.yml", caller)
        for selection in (
            "wine_baseline: 'wiage-11.13'",
            "use_macos26_runner: true",
            "host_provenance_only: false",
            "win7_setup: false",
            "try_48_msi: true",
            "try_48_direct: false",
            "try_48_intermediate: false",
            "try_48_payload_host: false",
            "try_wow64_managed: false",
            "signed_msi_timeout_seconds: 420",
            "prepare_48_assembly_cache: true",
            "pause_native_ngen_queue: false",
            "cancel-in-progress: false",
        ):
            with self.subTest(selection=selection):
                self.assertIn(selection, caller)
        self.assertNotIn("workflow_dispatch:", caller)
        self.assertNotIn("pull_request:", caller)
        self.assertNotIn("actions/upload-artifact", caller)
        self.assertNotIn("secrets:", caller)

    def test_wiage_selects_exactly_one_arm_and_rejects_alt_paths(self):
        workflow = LEGACY.read_text(encoding="utf-8")
        anchor = workflow.index('if [[ "$SWCOMPAT_WINE_BASELINE" == "wiage-11.13" ]]; then')
        gate = workflow[anchor:workflow.index("EXPECTED_SHA=d0cea7", anchor)]
        self.assertIn('"$SWCOMPAT_MACOS26" != "true"', gate)
        self.assertIn('"$SWCOMPAT_WIAGE_TRY_INTERMEDIATE" != "false"', gate)
        self.assertIn('"$SWCOMPAT_WIAGE_TRY_PAYLOAD" != "false"', gate)
        self.assertIn('"$SWCOMPAT_HOST_ONLY:$SWCOMPAT_WIAGE_TRY_DIRECT:$SWCOMPAT_WIAGE_TRY_MSI:$SWCOMPAT_WIAGE_TRY_CATALOG"', gate)
        self.assertIn("true:false:false:false|false:true:false:false|false:false:true:false|false:false:false:true)", gate)
        self.assertIn("sha", workflow.lower())
        self.assertIn("SWCOMPAT_NATIVE40_READY == 'yes'", workflow)
        self.assertIn("python3 -m scripts.netfx40_to_48_signed_msi", workflow)
        self.assertIn("--sha256-file build/netfx48.sha256", workflow)
        self.assertIn("native48_candidate", workflow)

    def test_msi_payload_and_release_gates_are_real_and_private(self):
        module = MODULE.read_text(encoding="utf-8")
        for expected in (
            'MSI = "netfx_Full_x64.msi"',
            'MSP = "netfx_Patch_x64.msp"',
            "verify_original_media(installer, digest)",
            'result["install"] == "SUCCESS"',
            'result["patch"] == "SUCCESS"',
            'result["release"] == "NETFX48_RANGE"',
            'result["loader"] == "LOADED"',
            'result["native_only_managed"] == "PASS"',
            'result["clr64_changed"]',
        ):
            self.assertIn(expected, module)
        self.assertIn('result["framework481_confirmed"] is not False', module)
        self.assertNotIn("reg add", module.lower())
        self.assertNotIn("Release /t REG_DWORD", module)
        self.assertNotIn("print(raw)", module)


if __name__ == "__main__":
    unittest.main()
