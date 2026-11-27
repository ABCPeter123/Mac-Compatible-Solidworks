"""Synthetic strict protocol and same-prefix wiring tests."""
from pathlib import Path
import unittest
from scripts.netfx481_cad_prerequisites import parse


def packet(mode="core", bits=64, native="YES", result="PASS", hr="00000000"):
    return (
        "SWCOMPAT_CAD_SCHEMA=1\nSWCOMPAT_CAD_MODE=%s\nSWCOMPAT_CAD_BITS=%d\n"
        "SWCOMPAT_CAD_NATIVE=%s\nSWCOMPAT_CAD_RESULT=%s\nSWCOMPAT_CAD_HRESULT=%s\n"
        % (mode, bits, native, result, hr)
    ).encode("ascii")


class CadPrerequisiteTests(unittest.TestCase):
    def test_accepts_native_only_success_and_architecture(self):
        for bits in (32, 64):
            for mode in ("core", "winforms", "wpf", "wcf", "com"):
                self.assertEqual(parse(packet(mode, bits), 0, mode, bits),
                                 dict(result="PASS", native=True, hresult="00000000"))

    def test_rejects_mono_wrong_architecture_extra_output_and_false_success(self):
        for value, rc in ((packet(native="NO"), 0), (packet(bits=32), 0),
                          (packet(mode="wpf"), 0), (packet(), 1),
                          (packet(hr="80004005"), 0), (packet() + b"private\n", 0)):
            self.assertEqual(parse(value, rc, "core", 64)["result"], "INVALID_OUTPUT")

    def test_preserves_bounded_failure_hresult(self):
        result = parse(packet(mode="wpf", result="FAIL", hr="80004005"), 1, "wpf", 64)
        self.assertEqual(result, dict(result="FAIL", native=True, hresult="80004005"))

    def test_workflow_runs_before_webview_and_restricts_private_launch(self):
        body = (Path(__file__).resolve().parents[1] / ".github/workflows/netfx40-legacy-ci.yml").read_text()
        matrix = body.index("      - name: Measure dual architecture CAD runtime subsystems before WebView2")
        webview = body.index("      - name: Fetch independently verified WebView2 media and pinned SDK loader privately")
        launch = body.index("      - name: Launch verified original SOLIDWORKS bootstrapper with real CLR and WebView2")
        self.assertLess(matrix, webview)
        self.assertLess(webview, launch)
        self.assertIn("scripts.netfx481_cad_prerequisites", body[matrix:webview])
        self.assertIn('WINEDLLOVERRIDES: "mscoree=n;clr=n"', body[launch:launch+650])
        self.assertIn("github.event_name == 'workflow_dispatch' && inputs.try_solidworks_after_ipd", body[launch:launch+650])
