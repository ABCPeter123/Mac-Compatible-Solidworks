"""Gate the authenticated macOS 26 Wiage original signed .NET 4.8 A/B.

The initial native CLR4 result does not imply .NET 4.8 is installed.
This structural regression ensures no accidental alternate MSI/Winetricks or
unverified artifact upload enters the new signed original installer test.
"""
from pathlib import Path
import unittest

WORKFLOWS = Path(__file__).resolve().parents[1] / ".github" / "workflows"
CALLER = WORKFLOWS / "netfx48-wiage-direct-once-ci.yml"
LEGACY = WORKFLOWS / "netfx40-legacy-ci.yml"


class SignedWiageNetfx48OnceTests(unittest.TestCase):
    def test_caller_is_exactly_main_only_and_selects_signed_direct(self):
        source = CALLER.read_text(encoding="utf-8")
        self.assertIn("  push:\n    branches: [main]\n    paths:\n"
                      "      - '.github/workflows/netfx48-wiage-direct-once-ci.yml'", source)
        self.assertIn("uses: ./.github/workflows/netfx40-legacy-ci.yml", source)
        required = (
            "wine_baseline: 'wiage-11.13'",
            "use_macos26_runner: true",
            "host_provenance_only: false",
            "win7_setup: false",
            "try_48_direct: true",
            "original_48_profile: win7",
            "original_48_setup_args: logged",
            "try_48_msi: false",
            "try_48_intermediate: false",
            "try_48_payload_host: false",
            "try_wow64_managed: false",
            "cancel-in-progress: false",
        )
        for line in required:
            with self.subTest(line=line):
                self.assertIn(line, source)
        self.assertNotIn("workflow_dispatch:", source)
        self.assertNotIn("pull_request:", source)
        self.assertNotIn("actions/upload-artifact", source)
        self.assertNotIn("secrets:", source)

    def test_runtime_gate_keeps_unverified_and_unwanted_paths_blocked(self):
        source = LEGACY.read_text(encoding="utf-8")
        start = source.index('if [[ "$SWCOMPAT_WINE_BASELINE" == "wiage-11.13" ]]; then')
        end = source.index('EXPECTED_SHA=d0cea7ff492dd3801dfa26a2a7d5ed1331e60f65929318d17301a3ce9cbba56c',
                           start)
        gate = source[start:end]
        self.assertIn('"$SWCOMPAT_MACOS26" != "true"', gate)
        self.assertIn('"$SWCOMPAT_HOST_ONLY:$SWCOMPAT_WIAGE_TRY_DIRECT:$SWCOMPAT_WIAGE_TRY_MSI"', gate)
        self.assertIn("true:false:false|false:true:false|false:false:true)", gate)
        self.assertIn('"$SWCOMPAT_WIAGE_TRY_INTERMEDIATE" != "false"', gate)
        self.assertIn('"$SWCOMPAT_WIAGE_TRY_PAYLOAD" != "false"', gate)
        self.assertIn('"$SWCOMPAT_WIAGE_TRY_INTERMEDIATE" != "false"', gate)
        self.assertIn('"$SWCOMPAT_WIAGE_TRY_PAYLOAD" != "false"', gate)
        self.assertIn("SWCOMPAT_NATIVE40_READY == 'yes'", source)
        self.assertIn("python3 -m scripts.netfx40_to_48_direct", source)
        self.assertIn("python3 -m scripts.netfx4x_authenticated_media_fetch", source)
        self.assertIn("--sha256-file build/netfx48.sha256", source)
        self.assertIn("Original signed .NET 4.8 directly on the verified native 4.0", source.replace("Install original signed 4.8", "Original signed .NET 4.8"))
        self.assertIn("inputs.try_48_direct", source)
        self.assertIn("!inputs.try_48_direct", source)
        self.assertIn("!inputs.try_48_intermediate", source)
        self.assertIn("!inputs.try_48_msi", source)


if __name__ == "__main__":
    unittest.main()
