"""Only a verified original CLR4 NGen gate may skip the signed 4.8 MSI.

The reusable workflow must not mistake a planned pre-MSI abort for a missing
vendor installation measurement, and must never call it an installed 4.8.
"""
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
REUSABLE = ROOT / ".github/workflows/netfx40-legacy-ci.yml"


class SignedNgenMSIGateTests(unittest.TestCase):
    def test_validation_step_understands_expected_original_ngen_abort(self):
        source = REUSABLE.read_text(encoding="utf-8")
        step = source.split("- name: Validate that msxml3 cannot fabricate a CLR install", 1)[1]
        for key in (
            "SWCOMPAT_DRAIN_NGEN: ${{ inputs.drain_native40_ngen }}",
            'drain_requested = os.environ.get("SWCOMPAT_DRAIN_NGEN") == "true"',
            "drain_path.is_file() == drain_requested",
            "from scripts.netfx48_native_ngen_drain import valid as valid_drain",
            'assert valid_drain(drain)',
            'assert drain["status"] in {"BLOCKED", "READY"}',
            'drain_ready = drain["ready"]',
            "msi_path.is_file() == (msi_required and drain_ready)",
            'assert valid_msi(msi)',
        ):
            with self.subTest(key=key):
                self.assertIn(key, step)
        self.assertIn('if not drain_ready:', step)
        self.assertIn('assert drain["status"] == "BLOCKED"', step)
        self.assertIn('intermediate_ready = msi["native48_candidate"]', step)
        self.assertIn("4.8.1 is forbidden in host-only mode", step)
        self.assertNotIn("msi_path.is_file() == msi_required", step)

    def test_status_report_prints_only_sanitized_drain_taxonomy(self):
        source = REUSABLE.read_text(encoding="utf-8")
        report = source.split("- name: Summarize", 1)[-1]
        for key in (
            "native40_ngen_drain_{key}",
            "native40_ngen_{arch}_wine_trace_status",
            "native40_ngen_{arch}_wine_trace_signals",
            "native40_ngen_progress_{key}",
            "from scripts.netfx48_ngen_progress import valid as valid_ngen_progress",
            "assert valid_ngen_progress(progress)",
        ):
            with self.subTest(key=key):
                self.assertIn(key, report)
        self.assertIn("assert valid_drain(drain)", report)
        self.assertIn("assert valid_trace(trace)", report)
        self.assertIn("','.join(trace['signals'])", report)
        self.assertNotIn("print(raw)", report)

    def test_drain_artifacts_stay_sanitized_and_separate_from_vendor_payload(self):
        source = REUSABLE.read_text(encoding="utf-8")
        self.assertIn("build/netfx40-native-ngen-drain.json", source)
        self.assertIn("scripts.netfx48_native_ngen_drain", source)
        self.assertIn("scripts.netfx40_to_48_signed_msi", source)
        self.assertNotIn("netfx_Full_x64.msi\n", source)


if __name__ == "__main__":
    unittest.main()
