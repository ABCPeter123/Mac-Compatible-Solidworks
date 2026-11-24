"""Fail-closed workflow contract for one authentic CLR4 fresh-prefix retry."""
from pathlib import Path
from unittest import TestCase

ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = ROOT / ".github/workflows/netfx40-legacy-ci.yml"
CALLER = ROOT / ".github/workflows/netfx48-wiage-ngen-progress-msi-once-ci.yml"


class Native40FreshRetryWorkflowTests(TestCase):
    def test_only_original_signed_msp_one_shot_can_trigger_it(self):
        body = WORKFLOW.read_text(encoding="utf-8")
        caller = CALLER.read_text(encoding="utf-8")
        start = body.index(
            "- name: One genuine CLR4 retry in a second fresh disposable Wine "
            "prefix after 1603")
        end = body.index(
            "- name: Extract unchanged signed .NET 4.0 MSI for private failure "
            "attribution", start)
        block = body[start:end]
        self.assertIn(
            "env.SWCOMPAT_MSXML3_READY == 'yes' && "
            "inputs.signed_msp_win32_exit", block)
        self.assertIn("netfx40_fresh_prefix_retry", block)
        self.assertIn("--agree-disposable-prefix", block)
        self.assertIn('test "$outcome" = "FRESH_PREFIX_REQUIRED"', block)
        self.assertIn('if [[ "$outcome" == "ALREADY_VERIFIED" ]]', block)
        self.assertIn("netfx40-msxml3-runtime-attempt1.json", block)
        self.assertIn("netfx40-msxml3-restart-attempt1.json", block)
        self.assertIn("netfx40-msxml3-retry-logs", block)
        self.assertIn("--skip-bootstrap-mono-gecko", block)
        self.assertIn("scripts.netfx40_prefix_readiness", block)
        self.assertIn("scripts.netfx40_msxml3_prerequisite", block)
        self.assertIn('xml["status"] == "VERB_SUCCEEDED"', block)
        self.assertIn("scripts.netfx40_legacy", block)
        self.assertIn("scripts.netfx40_msxml3_restart", block)
        self.assertIn('r["persistent_native_managed"]', block)
        self.assertIn('r["native_only_managed"] == "PASS"', block)
        self.assertIn('"$RUNNER_TEMP/netfx40-msxml3-prefix"', block)
        self.assertNotIn("|| true", block)
        self.assertNotIn("continue-on-error", block)
        self.assertNotIn("reg add", block.lower())
        self.assertNotIn("rm -rf", block)
        self.assertIn("signed_msp_win32_exit: true", caller)

    def test_original_success_gate_and_private_reports_are_preserved(self):
        body = WORKFLOW.read_text(encoding="utf-8")
        self.assertEqual(body.count(
            "One genuine CLR4 retry in a second fresh disposable Wine prefix "
            "after 1603"), 1)
        self.assertIn(
            '"Original Microsoft CLR4 prerequisite failed; NGen experiment not run"',
            body)
        self.assertIn("NETFX48_RANGE", body)
        self.assertIn("build/netfx40-msxml3-runtime-attempt1.json", body)
        self.assertIn("build/netfx40-msxml3-restart-attempt1.json", body)
        self.assertIn("if: always()", body)
