"""Fail closed on false native-runtime evidence before licensed launch."""
import copy
from pathlib import Path
import unittest
from scripts.netfx481_solidworks_gate import ready


def report():
    return {
        "experimental": True, "strict_cbs_equivalence": False,
        "framework481_confirmed": True, "transaction": "COMPLETED",
        "restart": "COMPLETED", "gac_restart": "COMPLETED",
        "deferred_verified": True, "registry": "AT_LEAST_481",
        "runtime_family": "MICROSOFT_CLR_CANDIDATE", "managed": "PASS", "loader": "LOADED",
        "gac_registration": dict(transport="COMPLETED", directives=274,
                                 unique_payloads=274, cached_after=274,
                                 attempted=274, successful_hresult=274, failed_hresult={}),
        "writes": dict(assemblies=1387, files=1036, deferred=8, values=11125,
                       first_failure_phase="NONE", win32_error="00000000"),
        "original_runtime_payloads": {
            key: {"matches_original": True}
            for key in ("CLR32", "CLR64", "MSCORLIB32", "MSCORLIB64")
        },
    }


class SolidworksGateTests(unittest.TestCase):
    def test_success_and_missing_or_corrupted_evidence(self):
        self.assertTrue(ready(report()))
        for key in report():
            with self.subTest(key=key):
                value = report()
                del value[key]
                self.assertFalse(ready(value))
        for key, bad in (("managed", "NOT_VERIFIED"), ("runtime_family", "MONO"),
                         ("deferred_verified", False), ("transaction", "PARTIAL_OR_FAILED")):
            value = report()
            value[key] = bad
            self.assertFalse(ready(value))
        for section, key, bad in (
            ("gac_registration", "cached_after", 273),
            ("gac_registration", "failed_hresult", {"80004005": 1}),
            ("writes", "files", 1035), ("writes", "values", 11124),
            ("original_runtime_payloads", "CLR64", {"matches_original": False}),
        ):
            value = report()
            value[section][key] = bad
            self.assertFalse(ready(value))

    def test_workflow_private_manual_only_and_same_prefix(self):
        root = Path(__file__).resolve().parents[1]
        caller = (root / ".github/workflows/netfx481-ipd-apply-candidate-ci.yml").read_text()
        body = (root / ".github/workflows/netfx40-legacy-ci.yml").read_text()
        self.assertIn("github.event_name == 'workflow_dispatch' && inputs.try_solidworks_after_ipd", caller)
        first = body.index("      - name: Require verified native framework and complete original GAC before licensed trial")
        end = body.index("      - name: Remove private IPD staged Microsoft content", first)
        block = body[first:end]
        self.assertEqual(block.count("scripts.netfx481_solidworks_gate --report"), 3)
        self.assertIn('PREFIX="$RUNNER_TEMP/netfx40-msxml3-prefix"', block)
        self.assertIn("scripts.solidworks_runtime_gate", block)
        self.assertIn("--require-ready", block)
        self.assertIn("scripts.solidworks_bootstrap_trial", block)
        self.assertNotIn("--serial", block)
        self.assertNotIn("AcceptEULA", block)
        self.assertNotIn("path: build/SolidworksSetup.exe", block)
        self.assertIn("if: github.event_name == 'workflow_dispatch' && inputs.try_solidworks_after_ipd && inputs.try_481_ipd_apply_candidate", block)
