"""Synthetic validation of full DWORD Win32 installer evidence under Wine."""
import tempfile
from pathlib import Path
from unittest import TestCase, mock
from scripts import netfx481_win32_exit as win32
from scripts import netfx481_trial as trial


def sample(code="00000BC2", child="NOT_OBSERVED", status="EXIT",
           lifecycle=None, child_exit=None):
    if lifecycle is None:
        lifecycle = ("ALL_EXITED" if child == "OBSERVED" else
                     "NOT_OBSERVED" if child == "NOT_OBSERVED" else "UNKNOWN")
    if child_exit is None:
        child_exit = "ALL_ZERO" if lifecycle == "ALL_EXITED" else "NOT_VERIFIED"
    return ("\n".join([
        "SWCOMPAT_WIN32_SETUP_SCHEMA=1",
        "SWCOMPAT_WIN32_SETUP_STATUS=" + status,
        "SWCOMPAT_WIN32_SETUP_EXIT_HEX=" + code,
        "SWCOMPAT_WIN32_SETUP_CHILD_SEEN=" + child,
        "SWCOMPAT_WIN32_SETUP_CHILD_LIFECYCLE=" + lifecycle,
        "SWCOMPAT_WIN32_SETUP_CHILD_EXIT=" + child_exit,
    ]) + "\n").encode("ascii")


class FullExitTests(TestCase):
    def test_exact_3010_survives_wine_unix_truncation(self):
        report = win32.parse(sample(), 0)
        self.assertEqual(report, {
            "status": "EXIT_CAPTURED", "exit_hex": "00000BC2",
            "category": "REBOOT_REQUIRED", "child_seen": "NOT_OBSERVED",
            "child_lifecycle": "NOT_OBSERVED", "child_exit": "NOT_VERIFIED"
        })
        self.assertEqual(win32.termination(report), ("EXIT_NONZERO", 3010))
        self.assertEqual(3010 % 256, 194)
        self.assertTrue(win32.validate(report))

    def test_full_hresult_and_msi_fatal_error(self):
        hresult = win32.parse(sample(code="80070643", child="OBSERVED"), 0)
        self.assertEqual(win32.termination(hresult), ("EXIT_NONZERO", 0x80070643))
        self.assertEqual(hresult["category"], "OTHER")
        self.assertEqual(hresult["child_seen"], "OBSERVED")
        msi = win32.parse(sample(code="00000643"), 0)
        self.assertEqual(msi["category"], "MSI_FATAL_ERROR")
        self.assertEqual(win32.parse(sample(code="00000000"), 0)["category"], "SUCCESS")

    def test_corrupt_duplicate_missing_and_overlong_output_cannot_become_success(self):
        cases = [
            sample() + sample(),
            sample().replace(b"EXIT_HEX=", b"EXIT_HEX=UNKNOWN"),
            sample() + b"SWCOMPAT_WIN32_SETUP_EXTRA=SECRET\n",
            sample().replace(b"SWCOMPAT_WIN32_SETUP_SCHEMA=1\n", b""),
            sample().replace(b"SWCOMPAT_WIN32_SETUP_SCHEMA=1", b"SWCOMPAT_WIN32_SETUP_SCHEMA=2"),
            sample() + b"\x00", sample() + b"x" * 5000,
            b"\xff" + sample(),
        ]
        for raw in cases:
            with self.subTest(raw=raw[:30]):
                self.assertEqual(win32.parse(raw, 0)["status"], "BAD_REPORT")
        self.assertEqual(win32.parse(sample(), 194)["status"], "BAD_REPORT")

    def test_child_not_observed_never_claims_no_child(self):
        result = win32.parse(sample(child="NOT_OBSERVED"), 0)
        self.assertEqual(result["child_seen"], "NOT_OBSERVED")
        self.assertNotIn("did_not_start_child", result)
        self.assertEqual(win32.parse(sample(child="NONE"), 0)["status"], "BAD_REPORT")

    def test_child_lifecycle_must_match_observation_and_exit_state(self):
        running = win32.parse(
            sample(child="OBSERVED", lifecycle="STILL_ACTIVE",
                   child_exit="NOT_VERIFIED"), 0
        )
        self.assertEqual(running["child_lifecycle"], "STILL_ACTIVE")
        self.assertEqual(running["child_exit"], "NOT_VERIFIED")
        self.assertTrue(win32.validate(running))
        exited = win32.parse(
            sample(child="OBSERVED", lifecycle="ALL_EXITED", child_exit="NONZERO"), 0
        )
        self.assertEqual(exited["child_exit"], "NONZERO")
        for kwargs in [
            dict(child="NOT_OBSERVED", lifecycle="ALL_EXITED"),
            dict(child="OBSERVED", lifecycle="NOT_OBSERVED"),
            dict(child="OBSERVED", lifecycle="STILL_ACTIVE", child_exit="ALL_ZERO"),
            dict(child="OBSERVED", lifecycle="ALL_EXITED", child_exit="NOT_VERIFIED"),
        ]:
            with self.subTest(kwargs=kwargs):
                self.assertEqual(win32.parse(sample(**kwargs), 0)["status"],
                                 "BAD_REPORT")

    def test_reboot_requires_child_completion_or_no_observed_child(self):
        old = {"registry": "NOT_FOUND", "clr_family": "MONO", "managed": "PASS"}
        ready = {"registry": "AT_LEAST_481", "clr_family": "MICROSOFT_CLR_CANDIDATE", "managed": "PASS"}
        active = win32.parse(
            sample(child="OBSERVED", lifecycle="STILL_ACTIVE"), 0
        )
        result = trial.combine(
            old, ready, "EXIT_NONZERO", 3010, win32_launch=active,
            wine_restart={"reason": "WIN32_3010_CONFIRMED",
                          "action": "SKIPPED_CHILD_ACTIVE"},
        )
        self.assertFalse(result["new_framework_installation_confirmed"])

    def test_failed_process_does_not_copy_arbitrary_data(self):
        for status in ("START_FAILED", "WAIT_FAILED", "TIMEOUT"):
            self.assertEqual(win32.parse(sample(status=status), 1)["status"], status)
        self.assertEqual(win32.parse(sample(status="EXIT"), 1)["status"], "BAD_REPORT")
        self.assertEqual(win32.parse(sample(status="TIMEOUT"), 0)["status"], "BAD_REPORT")

    def test_run_in_disposable_prefix_and_verified_media_only(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            prefix = root / "prefix"
            (prefix / "drive_c").mkdir(parents=True)
            (prefix / "system.reg").write_text("")
            wine = root / "wine"
            wine.write_bytes(b"wine")
            fixture = root / "netfx481_win32_launch.exe"
            fixture.write_bytes(b"self-authored native")
            original = root / "NDP481-x86-x64-AllOS-ENU.exe"
            original.write_bytes(b"synthetic")
            with mock.patch.object(win32.subprocess, "run") as subprocess_run:
                with self.assertRaises(ValueError):
                    win32.launch(wine, prefix, original, fixture)
                subprocess_run.assert_not_called()
            (prefix / trial.SENTINEL).write_text("")
            with mock.patch("swcompat.wine_paths.windows_media_path", return_value=r"Z:\build\NDP481-x86-x64-AllOS-ENU.exe"), \
                 mock.patch.object(win32.subprocess, "run") as subprocess_run:
                def run(command, **kwargs):
                    self.assertEqual(command[2], r"Z:\build\NDP481-x86-x64-AllOS-ENU.exe")
                    self.assertEqual(kwargs["env"]["WINEPREFIX"], str(prefix))
                    kwargs["stdout"].write(sample())
                    return mock.Mock(returncode=0)
                subprocess_run.side_effect = run
                result = win32.launch(wine, prefix, original, fixture)
            self.assertEqual(result["category"], "REBOOT_REQUIRED")

    def test_exact_win32_3010_needed_for_reboot_claim(self):
        old = {"registry": "NOT_FOUND", "clr_family": "MONO", "managed": "PASS"}
        ready = {"registry": "AT_LEAST_481", "clr_family": "MICROSOFT_CLR_CANDIDATE", "managed": "PASS"}
        restart = {"reason": "WIN32_3010_CONFIRMED", "action": "COMPLETED"}
        win = win32.parse(sample(), 0)
        yes = trial.combine(old, ready, "EXIT_NONZERO", 3010,
                            wine_restart=restart, win32_launch=win)
        self.assertTrue(yes["new_framework_installation_confirmed"])
        no = trial.combine(old, ready, "EXIT_NONZERO", 194,
                           wine_restart={"reason": "UNIX_194_POSSIBLE_3010", "action": "COMPLETED"},
                           win32_launch=win)
        self.assertFalse(no["new_framework_installation_confirmed"])
        unknown = trial.combine(old, old, "EXIT_NONZERO", 3010,
                                wine_restart=restart, win32_launch=win)
        self.assertFalse(unknown["new_framework_installation_confirmed"])
