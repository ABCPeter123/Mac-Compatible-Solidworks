"""Synthetic strict protocol and same-prefix wiring tests."""
from pathlib import Path
import unittest
from scripts.netfx481_cad_prerequisites import parse, wpf_diagnostic, MAX_WPF_STDERR


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

    def test_wpf_stage_census_distinguishes_crash_from_managed_exception(self):
        raw = b"SWCOMPAT_WPF_STAGE=DISPATCH\nSWCOMPAT_WPF_STAGE=ENTER\nSWCOMPAT_WPF_STAGE=VISUAL\nprivate path and arguments\n"
        r = wpf_diagnostic(raw, -11)
        self.assertEqual(r["last_stage"], "VISUAL")
        self.assertEqual(r["exit"], "SIGNALLED")
        self.assertFalse(r["managed_exception"])
        self.assertNotIn("private", str(r))
        r = wpf_diagnostic(raw + b"SWCOMPAT_WPF_STAGE=MANAGED_EXCEPTION\nSWCOMPAT_WPF_INNER_HRESULT=80004005\n", 1)
        self.assertTrue(r["managed_exception"])
        self.assertEqual(r["inner_hresult"], "80004005")
        self.assertEqual(wpf_diagnostic(b"SWCOMPAT_WPF_STAGE=VISUAL\n", 0)["last_stage"], "INVALID_MARKERS")
        self.assertEqual(wpf_diagnostic(b"x" * (MAX_WPF_STDERR + 1), 1)["last_stage"], "TRUNCATED")

    def test_disposable_gdi_marker_precedes_gdi_reference_and_webview(self):
        body = (Path(__file__).resolve().parents[1] / ".github/workflows/netfx40-legacy-ci.yml").read_text()
        gate = body.index("      - name: Require verified native framework and complete original GAC")
        gdi = body.index("      - name: Verify same-prefix native Win32 GDI baseline", gate)
        web = body.index("      - name: Install verified WebView2", gdi)
        block = body[gdi:web]
        self.assertLess(block.index('touch "$PREFIX/.swcompat-solidworks-installer-disposable"'),
                        block.index("python3 -m scripts.solidworks_ui_gdi_reference"))
        self.assertIn('test -f "$PREFIX/.swcompat-netfx481-disposable"', block)
        self.assertIn('test ! -L "$PREFIX/.swcompat-solidworks-installer-disposable"', block)

    def test_cad_packet_is_fresh_and_separate_from_console(self):
        source = (Path(__file__).resolve().parents[1] / "probes/netfx481_cad_prerequisites.cs").read_text()
        self.assertIn("FileMode.CreateNew", source)
        self.assertIn("new System.Text.UTF8Encoding(false)", source)
        self.assertIn("else Console.Write(packet)", source)
        self.assertEqual(parse(packet(mode="wpf"), 0, "wpf", 64)["result"], "PASS")
