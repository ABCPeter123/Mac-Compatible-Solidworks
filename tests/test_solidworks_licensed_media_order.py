"""Guard early licensed-media checks and ensure ordinary CI cannot fetch it."""
from pathlib import Path
import unittest


class LicensedMediaOrderTests(unittest.TestCase):
    def test_media_gate_runs_before_expensive_windows_prerequisites(self):
        body = (Path(__file__).resolve().parents[1] / ".github/workflows/netfx40-legacy-ci.yml").read_text()
        job = body.index("  authentic-netfx40-windows:")
        fetch = body.index("- name: Fetch private installer and classify", job)
        signature = body.index("- name: Verify exact SHA256, original PE and Dassault Authenticode signature", fetch)
        controls = body.index("- name: Test safety gate and strict no-leak reporting", signature)
        self.assertLess(fetch, signature)
        self.assertLess(signature, controls)
        self.assertIn("github.event_name == 'workflow_dispatch' && inputs.try_solidworks_after_ipd && inputs.try_481_ipd_apply_candidate", body[fetch:signature])
        self.assertIn("Get-AuthenticodeSignature", body[signature:controls])
        self.assertIn("ipd-solidworks-windows-media-sanitized", body[signature:controls])
        self.assertIn("build/solidworks-windows-fetch.json", body[signature:controls])
        self.assertIn("build/solidworks-windows-media.json", body[signature:controls])
        artifact = body[body.index("name: ipd-solidworks-windows-media-sanitized"):controls]
        self.assertNotIn("SolidworksSetup.exe", artifact)

    def test_private_steps_are_unique_and_shell_is_not_truncated(self):
        body = (Path(__file__).resolve().parents[1] / ".github/workflows/netfx40-legacy-ci.yml").read_text()
        self.assertEqual(body.count("- name: Fetch private installer and classify"), 1)
        self.assertEqual(body.count("- name: Verify exact SHA256, original PE and Dassault Authenticode signature"), 1)
        self.assertEqual(body.count("python -m scripts.solidworks_private_media_fetch --destination build/SolidworksSetup.exe"), 1)
        self.assertIn("if ($env:SWCOMPAT_INSTALLER_SHA256 -notmatch '^[a-fA-F0-9]{64}$')", body)
        self.assertNotIn("\n) { throw", body)
