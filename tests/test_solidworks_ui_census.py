"""Only fixed numeric Win32 window census fields may leave the host."""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from subprocess import CompletedProcess, TimeoutExpired

from scripts.solidworks_bootstrap_trial import parse_window_probe, sample_window_census


def window_sample(processes=1, windows=1, visible=2, child=0, parent_layered=0, parent_no_redirection=0, child_layered=0, child_no_redirection=0):
    return (
        f"SWCOMPAT_SW_UI_CANDIDATE_PROCESSES={processes}\n"
        f"SWCOMPAT_SW_UI_CANDIDATE_WINDOWS={windows}\n"
        f"SWCOMPAT_SW_UI_VISIBLE_LARGE_WINDOWS={visible}\n"
        f"SWCOMPAT_SW_UI_RESPONSIVENESS={'RESPONSIVE' if windows else 'NO_CANDIDATE'}\n"
        f"SWCOMPAT_SW_UI_GDI_CLIENT={'NONUNIFORM' if windows else 'NO_CANDIDATE'}\n"
        f"SWCOMPAT_SW_UI_GDI_FAILURE_STAGE={'NONE' if windows else 'NO_CANDIDATE'}\n"
        f"SWCOMPAT_SW_UI_DIRECT_GETPIXEL={'NONUNIFORM' if windows else 'NO_CANDIDATE'}\n"
        f"SWCOMPAT_SW_UI_PARENT_LAYERED={parent_layered}\n"
        f"SWCOMPAT_SW_UI_PARENT_NO_REDIRECTION={parent_no_redirection}\n"
        f"SWCOMPAT_SW_UI_CHILD_VISIBLE={child}\n"
        f"SWCOMPAT_SW_UI_CHILD_LAYERED={child_layered}\n"
        f"SWCOMPAT_SW_UI_CHILD_NO_REDIRECTION={child_no_redirection}\n"
        f"SWCOMPAT_SW_UI_CHILD_GDI={'NONUNIFORM' if child else 'NO_CHILD'}\n"
        "SWCOMPAT_SW_UI_PROBE=COMPLETE\n"
    )


class Win32WindowCensusTests(unittest.TestCase):
    def test_candidate_window_is_a_heuristic_only(self):
        self.assertEqual(parse_window_probe(window_sample()), {
            "candidate_processes": 1, "candidate_windows": 1,
            "responsiveness": "RESPONSIVE", "gdi_client": "NONUNIFORM",
            "gdi_failure_stage": "NONE", "direct_getpixel": "NONUNIFORM",
            "parent_layered": 0, "parent_no_redirection": 0, "child_visible": 0,
            "child_layered": 0, "child_no_redirection": 0, "child_gdi": "NO_CHILD"})

    def test_absence_does_not_prove_no_ui(self):
        self.assertEqual(parse_window_probe(window_sample(0, 0, 1)), {
            "candidate_processes": 0, "candidate_windows": 0,
            "responsiveness": "NO_CANDIDATE", "gdi_client": "NO_CANDIDATE",
            "gdi_failure_stage": "NO_CANDIDATE", "direct_getpixel": "NO_CANDIDATE",
            "parent_layered": 0, "parent_no_redirection": 0, "child_visible": 0,
            "child_layered": 0, "child_no_redirection": 0, "child_gdi": "NO_CHILD"})

    def test_reject_missing_completed_marker(self):
        self.assertIsNone(parse_window_probe(window_sample().replace(
            "SWCOMPAT_SW_UI_PROBE=COMPLETE\n", "")))

    def test_reject_duplicate_count(self):
        self.assertIsNone(parse_window_probe(window_sample() +
                                             "SWCOMPAT_SW_UI_CANDIDATE_WINDOWS=2\n"))

    def test_reject_unrecognized_raw_window_title_or_license(self):
        self.assertIsNone(parse_window_probe(window_sample() +
                                             "Install SOLIDWORKS serial: 123-456\n"))

    def test_responsive_window_can_have_failed_gdi_readback(self):
        result = parse_window_probe(window_sample()
            .replace("GDI_CLIENT=NONUNIFORM", "GDI_CLIENT=READBACK_FAILED")
            .replace("GDI_FAILURE_STAGE=NONE", "GDI_FAILURE_STAGE=STRETCH_BLT_FAILED"))
        self.assertEqual(result["responsiveness"], "RESPONSIVE")
        self.assertEqual(result["gdi_client"], "READBACK_FAILED")
        self.assertEqual(result["gdi_failure_stage"], "STRETCH_BLT_FAILED")

    def test_unresponsive_window_can_have_uniform_gdi_surface(self):
        result = parse_window_probe(window_sample()
            .replace("RESPONSIVENESS=RESPONSIVE", "RESPONSIVENESS=UNRESPONSIVE")
            .replace("GDI_CLIENT=NONUNIFORM", "GDI_CLIENT=UNIFORM"))
        self.assertEqual(result["responsiveness"], "UNRESPONSIVE")
        self.assertEqual(result["gdi_client"], "UNIFORM")

    def test_reject_inconsistent_no_candidate(self):
        self.assertIsNone(parse_window_probe(window_sample(
            0, 0, 1).replace("RESPONSIVENESS=NO_CANDIDATE", "RESPONSIVENESS=RESPONSIVE")))
        self.assertIsNone(parse_window_probe(window_sample(
            0, 0, 1).replace("GDI_CLIENT=NO_CANDIDATE", "GDI_CLIENT=NONUNIFORM")))

    def test_reject_unknown_or_duplicate_surface_marker(self):
        self.assertIsNone(parse_window_probe(window_sample().replace(
            "GDI_CLIENT=NONUNIFORM", "GDI_CLIENT=UNSAFE")))
        self.assertIsNone(parse_window_probe(window_sample() +
            "SWCOMPAT_SW_UI_GDI_CLIENT=UNIFORM\n"))

    def test_reject_unexplained_readback_failure(self):
        self.assertIsNone(parse_window_probe(window_sample().replace(
            "GDI_CLIENT=NONUNIFORM", "GDI_CLIENT=READBACK_FAILED")))

    def test_getpixel_can_work_when_stretchblt_fails(self):
        result = parse_window_probe(window_sample()
            .replace("GDI_CLIENT=NONUNIFORM", "GDI_CLIENT=READBACK_FAILED")
            .replace("GDI_FAILURE_STAGE=NONE", "GDI_FAILURE_STAGE=STRETCH_BLT_FAILED"))
        self.assertEqual(result["direct_getpixel"], "NONUNIFORM")
        self.assertEqual(result["gdi_client"], "READBACK_FAILED")

    def test_no_device_context_precludes_getpixel(self):
        result = parse_window_probe(window_sample()
            .replace("GDI_CLIENT=NONUNIFORM", "GDI_CLIENT=READBACK_FAILED")
            .replace("GDI_FAILURE_STAGE=NONE", "GDI_FAILURE_STAGE=SOURCE_DC_FAILED")
            .replace("DIRECT_GETPIXEL=NONUNIFORM", "DIRECT_GETPIXEL=READBACK_FAILED"))
        self.assertEqual(result["direct_getpixel"], "READBACK_FAILED")
        self.assertEqual(result["gdi_failure_stage"], "SOURCE_DC_FAILED")

    def test_reject_unknown_or_duplicate_failure_stage(self):
        self.assertIsNone(parse_window_probe(window_sample().replace(
            "GDI_FAILURE_STAGE=NONE", "GDI_FAILURE_STAGE=MY_PRIVATE_DATA")))
        self.assertIsNone(parse_window_probe(window_sample() +
            "SWCOMPAT_SW_UI_GDI_FAILURE_STAGE=CLIENT_RECT_FAILED\n"))

    def test_reject_inconsistent_getpixel_without_candidate(self):
        self.assertIsNone(parse_window_probe(window_sample(0, 0, 1).replace(
            "DIRECT_GETPIXEL=NO_CANDIDATE", "DIRECT_GETPIXEL=NONUNIFORM")))

    def test_child_visible_surface_and_no_redirection_aggregate(self):
        result = parse_window_probe(window_sample(
            child=2, parent_no_redirection=1, child_layered=1, child_no_redirection=1))
        self.assertEqual(result["child_visible"], 2)
        self.assertEqual(result["child_gdi"], "NONUNIFORM")
        self.assertEqual(result["parent_no_redirection"], 1)
        self.assertEqual(result["child_no_redirection"], 1)

    def test_reject_child_surface_without_visible_child(self):
        self.assertIsNone(parse_window_probe(window_sample().replace(
            "CHILD_GDI=NO_CHILD", "CHILD_GDI=NONUNIFORM")))
        self.assertIsNone(parse_window_probe(window_sample(child=1).replace(
            "CHILD_GDI=NONUNIFORM", "CHILD_GDI=NO_CHILD")))

    def test_reject_more_child_layered_than_visible(self):
        self.assertIsNone(parse_window_probe(window_sample(child=1, child_layered=2)))
        self.assertIsNone(parse_window_probe(window_sample(child=1, child_no_redirection=2)))

    def test_reject_parent_layered_without_candidate(self):
        self.assertIsNone(parse_window_probe(window_sample(
            processes=0, windows=0, visible=1, parent_layered=1)))
        self.assertIsNone(parse_window_probe(window_sample(
            processes=0, windows=0, visible=1, child=1)))

    def test_reject_bad_integer(self):
        for bad in ("-1", "1.5", "0x20", "serial123", "999999999999"):
            with self.subTest(value=bad):
                self.assertIsNone(parse_window_probe(
                    window_sample().replace("CANDIDATE_WINDOWS=1",
                                            "CANDIDATE_WINDOWS=" + bad)))

    def test_reject_more_candidate_than_visible(self):
        self.assertIsNone(parse_window_probe(window_sample(2, 3, 1)))

    def test_reject_huge_output(self):
        self.assertIsNone(parse_window_probe(window_sample() + ("x" * 5000)))

    def test_run_original_windows_probe_without_printing_results(self):
        with tempfile.TemporaryDirectory() as d:
            executable = Path(d) / "window-probe.exe"
            executable.write_bytes(b"MZ")
            with patch("scripts.solidworks_bootstrap_trial.subprocess.run") as run:
                run.return_value = CompletedProcess(["wine"], 0, window_sample().encode(), b"")
                outcome = sample_window_census(Path("/wine"), executable, Path(d), {})
                self.assertEqual(outcome["candidate_windows"], 1)
                self.assertEqual(run.call_args.kwargs["timeout"], 15)
                self.assertNotIn("capture_output", run.call_args.kwargs)

    def test_timeout_yields_no_claim(self):
        with tempfile.TemporaryDirectory() as d:
            with patch("scripts.solidworks_bootstrap_trial.subprocess.run") as run:
                run.side_effect = TimeoutExpired("wine", 15)
                outcome = sample_window_census(Path("/wine"), Path(d) / "a.exe", Path(d), {})
                self.assertIsNone(outcome)

    def test_nonzero_probe_is_not_verified(self):
        with tempfile.TemporaryDirectory() as d:
            with patch("scripts.solidworks_bootstrap_trial.subprocess.run") as run:
                run.return_value = CompletedProcess(["wine"], 3, window_sample().encode(), b"")
                self.assertIsNone(sample_window_census(Path("/wine"), Path(d) / "a.exe", Path(d), {}))


if __name__ == "__main__":
    unittest.main()
