"""Fail-closed workflow contract for one authentic CLR4 fresh-prefix retry."""
import ast
import importlib
import re
import textwrap
from pathlib import Path
from unittest import TestCase

ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = ROOT / ".github/workflows/netfx40-legacy-ci.yml"
CALLER = ROOT / ".github/workflows/netfx48-wiage-ngen-progress-msi-once-ci.yml"


class Native40FreshRetryWorkflowTests(TestCase):
    def test_only_original_signed_msp_or_ipd_apply_can_trigger_it(self):
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
            "if: env.SWCOMPAT_MSXML3_READY == 'yes' && "
            "(inputs.signed_msp_win32_exit || inputs.try_481_ipd_apply_candidate)", block)
        conditions = re.findall(r"(?m)^\s*if: (.+)$", block)
        self.assertEqual(conditions, [
            "env.SWCOMPAT_MSXML3_READY == 'yes' && "
            "(inputs.signed_msp_win32_exit || inputs.try_481_ipd_apply_candidate)"])
        self.assertIn("SWCOMPAT_REQUIRE_NATIVE40_FOR_IPD: ${{ inputs.try_481_ipd_apply_candidate }}", body)
        self.assertIn('"Original Microsoft CLR4 prerequisite failed; IPD apply experiment not run"', body)
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

    def test_authentic_fresh_prefix_heredocs_compile_and_import_existing_apis(self):
        """Compile both executable embedded scripts and resolve real imports.

        A signed Apple Silicon MSI run should not first discover that a new
        prefix preflight imported `validate` instead of the module's `valid`.
        This imports local Python only; no Wine, original media, network,
        registry, installer or actual shell steps are executed.
        """
        body = WORKFLOW.read_text(encoding="utf-8")
        start = body.index(
            "- name: One genuine CLR4 retry in a second fresh disposable "
            "Wine prefix after 1603")
        end = body.index(
            "- name: Extract unchanged signed .NET 4.0 MSI for private failure "
            "attribution", start)
        block = body[start:end]
        snippets = re.findall(
            r"(?ms)^          python3 - <<'PY'\n(.*?)^          PY$",
            block,
        )
        self.assertEqual(len(snippets), 2, "Both preflight/restart verifiers required")
        for number, snippet in enumerate(snippets, 1):
            source = textwrap.dedent(snippet)
            with self.subTest(script=number):
                tree = compile(source, f"<authentic-clr4-retry-{number}>", "exec",
                               flags=ast.PyCF_ONLY_AST)
                for node in ast.walk(tree):
                    if not isinstance(node, ast.ImportFrom):
                        continue
                    self.assertIsNotNone(node.module)
                    if not node.module.startswith("scripts."):
                        continue
                    module = importlib.import_module(node.module)
                    for symbol in node.names:
                        self.assertTrue(
                            hasattr(module, symbol.name),
                            f"{node.module} does not export {symbol.name}")
        self.assertIn(
            "from scripts.netfx40_prefix_readiness import valid as valid_prefix",
            block,
        )
        self.assertIn(
            "from scripts.netfx40_msxml3_prerequisite import validate as valid_msxml",
            block,
        )

    def test_ipd_retry_changes_sync_only_after_exact_clean_failure(self):
        body = WORKFLOW.read_text(encoding="utf-8")
        start = body.index("- name: One genuine CLR4 retry")
        end = body.index("- name: Extract unchanged signed .NET 4.0 MSI", start)
        block = body[start:end]
        verified = block.index('test "$outcome" = "FRESH_PREFIX_REQUIRED"')
        mode = block.index("export WINEMSYNC=0")
        init = block.index("--skip-bootstrap-mono-gecko")
        self.assertLess(verified, mode)
        self.assertLess(mode, init)
        self.assertIn('if [[ "$SWCOMPAT_IPD_SYNC_RETRY" == "true" && "$SWCOMPAT_RETRY_WINE_BASELINE" == "wiage-11.13" ]]', block)
        self.assertIn('echo "WINEMSYNC=0" >> "$GITHUB_ENV"', block)
        self.assertIn('test "${WINEMSYNC:-}" = "1"', block)
        self.assertIn('SWCOMPAT_IPD_SYNC_RETRY: ${{ inputs.try_481_ipd_apply_candidate }}', block)

    def test_exact_second_failure_allows_only_attribution_before_strict_gate(self):
        body = WORKFLOW.read_text(encoding="utf-8")
        start = body.index("- name: One genuine CLR4 retry")
        extract = body.index("- name: Extract unchanged signed .NET 4.0 MSI", start)
        table = body.index("- name: Privately correlate original Microsoft MSI", extract)
        gate = body.index("- name: Gate original 4.8.1 upgrade on restarted native Microsoft 4.0", table)
        apply = body.index("- name: Attempt gated original-payload IPD servicing", gate)
        retry = body[start:extract]
        self.assertIn("outcome = decision(original, r)", retry)
        self.assertIn('assert outcome == "ALREADY_VERIFIED"', retry)
        self.assertIn('assert outcome == "RETRY_ELIGIBLE"', retry)
        self.assertIn("collecting private MSI attribution before failing native CLR gate", retry)
        self.assertIn('SWCOMPAT_REQUIRE_NATIVE40_FOR_SIGNED_MSP:', body[gate:apply])
        self.assertIn("signed MSP experiment not run", body[gate:apply])
        self.assertIn("IPD apply experiment not run", body[gate:apply])
        self.assertIn("SWCOMPAT_NATIVE40_READY == 'yes'", body[apply:apply+400])

    def test_original_success_gate_and_private_reports_are_preserved(self):
        body = WORKFLOW.read_text(encoding="utf-8")
        self.assertEqual(body.count(
            "One genuine CLR4 retry in a second fresh disposable Wine prefix "
            "after 1603"), 1)
        self.assertIn(
            '"Original Microsoft CLR4 prerequisite failed; NGen experiment not run"',
            body)
        self.assertIn("native48_candidate", body)
        self.assertIn("build/netfx40-msxml3-runtime-attempt1.json", body)
        self.assertIn("build/netfx40-msxml3-restart-attempt1.json", body)
        self.assertIn("if: always()", body)
