"""Ensure documentation-only edits do not re-run expensive foundation CI."""
from pathlib import Path
from unittest import TestCase

ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = ROOT / ".github/workflows/compatibility-ci.yml"


class DocsOnlyFoundationFilterTests(TestCase):
    def test_only_markdown_changes_can_skip_foundation(self):
        body = WORKFLOW.read_text(encoding="utf-8")
        head = body.split("\npermissions:", 1)[0]
        self.assertIn("on:\n  push:\n    branches: [main]", head)
        self.assertEqual(head.count("paths-ignore:"), 2)
        self.assertEqual(head.count("- '**/*.md'"), 2)
        self.assertIn("  pull_request:\n    paths-ignore:\n      - '**/*.md'", head)
        self.assertIn("  workflow_dispatch:", head)
        self.assertNotIn("paths:\n", head)

    def test_code_and_workflow_ci_still_present(self):
        body = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("python -m unittest discover -s tests -v", body)
        self.assertIn("xcrun swiftc probes/metal_render_probe.swift", body)
        self.assertIn("sh scripts/build-wgl-probe.sh", body)
        self.assertIn("runs-on: ${{ matrix.os }}", body)
        self.assertIn("cancel-in-progress: true", body)
