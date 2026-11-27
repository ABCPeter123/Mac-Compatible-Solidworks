from pathlib import Path
import unittest

from scripts.netfx481_webview2_render import measure


class SamePrefixRenderTests(unittest.TestCase):
    def test_missing_browser_output_cannot_claim_compatibility(self):
        result = measure("", 124, None, {})
        self.assertEqual(result["result"], "UNEXPECTED_FAILURE")
        self.assertEqual(result["browser_pixels"], "NOT_VERIFIED")
        self.assertFalse(result["diagnostic_complete"])

    def test_same_prefix_workflow_runs_before_private_launch(self):
        body = (Path(__file__).resolve().parents[1] / ".github/workflows/netfx40-legacy-ci.yml").read_text()
        install = body.index("- name: Install verified WebView2")
        render = body.index("- name: Measure browser DOM and composition", install)
        launch = body.index("- name: Launch verified original SOLIDWORKS", render)
        self.assertLess(install, render)
        self.assertLess(render, launch)
        self.assertIn('scripts.netfx481_webview2_render', body[render:launch])
        self.assertIn('netfx40-msxml3-prefix', body[render:launch])
        self.assertIn('build/ipd-webview2-render.json', body[launch:])
        self.assertIn('--target webview2_controller_probe webview2_render_probe', body)
