"""Only fixed numeric Win32 window census fields may leave the host."""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from subprocess import CompletedProcess, TimeoutExpired

from scripts.solidworks_bootstrap_trial import parse_window_probe, sample_window_census


def window_sample(processes=1, windows=1, visible=2):
    return (
        f"SWCOMPAT_SW_UI_CANDIDATE_PROCESSES={processes}\n"
        f"SWCOMPAT_SW_UI_CANDIDATE_WINDOWS={windows}\n"
        f"SWCOMPAT_SW_UI_VISIBLE_LARGE_WINDOWS={visible}\n"
        f"SWCOMPAT_SW_UI_RESPONSIVENESS={'RESPONSIVE' if windows else 'NO_CANDIDATE'}\n"
        f"SWCOMPAT_SW_UI_GDI_CLIENT={'NONUNIFORM' if windows else 'NO_CANDIDATE'}\n"
        "SWCOMPAT_SW_UI_PROBE=COMPLETE\n"
    )


class Win32WindowCensusTests(unittest.TestCase):
    def test_candidate_window_is_a_heuristic_only(self):
        self.assertEqual(parse_window_probe(window_sample()), {
            "candidate_processes": 1, "candidate_windows": 1,
            "responsiveness": "RESPONSIVE", "gdi_client": "NONUNIFORM"})

    def test_absence_does_not_prove_no_ui(self):
        self.assertEqual(parse_window_probe(window_sample(0, 0, 1)), {
            "candidate_processes": 0, "candidate_windows": 0,
            "responsiveness": "NO_CANDIDATE", "gdi_client": "NO_CANDIDATE"})

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
        result = parse_window_probe(window_sample().replace(
            "GDI_CLIENT=NONUNIFORM", "GDI_CLIENT=READBACK_FAILED"))
        self.assertEqual(result["responsiveness"], "RESPONSIVE")
        self.assertEqual(result["gdi_client"], "READBACK_FAILED")

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
