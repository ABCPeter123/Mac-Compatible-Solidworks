from pathlib import Path
import unittest

from scripts.netfx481_webview2_render import measure, PROFILES


class SamePrefixRenderTests(unittest.TestCase):
    def test_missing_browser_output_cannot_claim_compatibility(self):
        result = measure("", 124, None, {})
        self.assertEqual(result["result"], "UNEXPECTED_FAILURE")
        self.assertEqual(result["browser_pixels"], "NOT_VERIFIED")
        self.assertFalse(result["diagnostic_complete"])

    def test_same_prefix_workflow_runs_before_private_launch(self):
        body = (Path(__file__).resolve().parents[1] / ".github/workflows/netfx40-legacy-ci.yml").read_text()
        install = body.index("- name: Recheck installed WebView2")
        render = body.index("- name: Measure browser DOM and composition", install)
        launch = body.index("- name: Launch verified original SOLIDWORKS", render)
        self.assertLess(install, render)
        self.assertLess(render, launch)
        self.assertIn('scripts.netfx481_webview2_render', body[render:launch])
        self.assertIn('netfx40-msxml3-prefix', body[render:launch])
        self.assertIn('build/ipd-webview2-render.json', body[launch:])
        self.assertIn('--target webview2_controller_probe webview2_render_probe', body)

    def test_browser_first_then_clr_then_live_recheck(self):
        body = (Path(__file__).resolve().parents[1] / ".github/workflows/netfx40-legacy-ci.yml").read_text()
        first = body.index("- name: Install official WebView2 in fresh prefix")
        clr = body.index("- name: Install native msxml3 through original Winetricks verb", first)
        retry = body.index("- name: One genuine CLR4 retry", clr)
        apply = body.index("- name: Attempt gated original-payload IPD servicing", retry)
        recheck = body.index("- name: Recheck installed WebView2", apply)
        self.assertLess(first, clr)
        self.assertLess(clr, apply)
        self.assertLess(apply, recheck)
        self.assertIn("mv build/solidworks-webview2-prerequisite.json build/solidworks-webview2-attempt1.json", body[retry:apply])
        self.assertIn("bash scripts/netfx481_webview2_first.sh", body[retry:apply])
        self.assertIn("scripts.netfx481_webview2_persistence", body[recheck:])

    def test_compositor_profiles_are_synthetic_and_allowlisted(self):
        self.assertEqual(PROFILES["default"], ())
        for profile in PROFILES.values():
            for flag in profile:
                self.assertNotIn("sandbox", flag)
                self.assertNotIn("security", flag)
                self.assertNotIn("certificate", flag)
        body = (Path(__file__).resolve().parents[1] / ".github/workflows/netfx40-legacy-ci.yml").read_text()
        start = body.index("- name: Compare foreground scheduling")
        launch = body.index("- name: Launch verified original SOLIDWORKS", start)
        self.assertIn("github.event_name == 'pull_request'", body[start:launch])
        self.assertIn("--compare-compositor-profiles", body[start:launch])
        self.assertIn("ipd-webview2-compositor-differential.json", body[launch:])
