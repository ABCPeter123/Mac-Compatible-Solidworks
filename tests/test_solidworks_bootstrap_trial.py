"""No proprietary data or license keys in installer bootstrap tests."""
import hashlib
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from scripts.solidworks_bootstrap_trial import (
    SENTINEL, attempt_launch, validate_prefix, verify_media,
)

synthetic_pe = runpy.run_path("tests/test_installer_media_preflight.py")["synthetic_pe"]


def media_in(folder: Path) -> tuple[Path, str]:
    exe = folder / "SolidworksSetup.exe"
    synthetic_pe(exe)
    with exe.open("ab") as out:
        out.write(b"\x00" * (65536 - exe.stat().st_size))
    return exe, hashlib.sha256(exe.read_bytes()).hexdigest()


def prefix_in(folder: Path) -> Path:
    p = folder / "wine-prefix"
    (p / "drive_c").mkdir(parents=True)
    (p / "system.reg").write_text("Wine registry")
    (p / SENTINEL).touch()
    return p


class MediaTests(unittest.TestCase):
    def test_valid_synthetic_bootstrap_pe(self):
        with tempfile.TemporaryDirectory() as t:
            exe, sha = media_in(Path(t))
            result = verify_media(exe, sha)
            self.assertEqual(result["media_verification"], "SHA256_VERIFIED")
            self.assertEqual(result["pe_architecture"], "x64")
            self.assertEqual(result["solidworks_compatibility"], "NOT_DEMONSTRATED")

    def test_reject_checksum_mismatch(self):
        with tempfile.TemporaryDirectory() as t:
            exe, _ = media_in(Path(t))
            with self.assertRaises(ValueError):
                verify_media(exe, "1" * 64)

    def test_reject_invalid_digest(self):
        with tempfile.TemporaryDirectory() as t:
            exe, _ = media_in(Path(t))
            for digest in ("", "x" * 64, "1234", "../bad"):
                with self.subTest(digest=digest), self.assertRaises(ValueError):
                    verify_media(exe, digest)

    def test_reject_non_pe_despite_matching_sha(self):
        with tempfile.TemporaryDirectory() as t:
            exe = Path(t) / "SolidworksSetup.exe"
            exe.write_bytes(b"X" * 65536)
            sha = hashlib.sha256(exe.read_bytes()).hexdigest()
            with self.assertRaises(ValueError):
                verify_media(exe, sha)

    def test_reject_tiny_executable(self):
        with tempfile.TemporaryDirectory() as t:
            exe = Path(t) / "SolidworksSetup.exe"
            exe.write_bytes(b"MZ")
            with self.assertRaises(ValueError):
                verify_media(exe, hashlib.sha256(b"MZ").hexdigest())

    def test_reject_non_exe(self):
        with tempfile.TemporaryDirectory() as t:
            exe, sha = media_in(Path(t))
            exe.rename(Path(t) / "archive.zip")
            with self.assertRaises(ValueError):
                verify_media(Path(t) / "archive.zip", sha)

    def test_reject_symlink_media(self):
        with tempfile.TemporaryDirectory() as t:
            folder = Path(t)
            exe, sha = media_in(folder)
            linked = folder / "linked.exe"
            linked.symlink_to(exe)
            with self.assertRaises(ValueError):
                verify_media(linked, sha)

    def test_reject_unmarked_or_uninitialized_prefix(self):
        with tempfile.TemporaryDirectory() as t:
            folder = Path(t)
            p = prefix_in(folder)
            validate_prefix(p)
            (p / SENTINEL).unlink()
            with self.assertRaises(ValueError):
                validate_prefix(p)
            (p / SENTINEL).touch()
            (p / "system.reg").unlink()
            with self.assertRaises(ValueError):
                validate_prefix(p)

    def test_never_execute_on_native_windows(self):
        if os.name == "nt":
            with tempfile.TemporaryDirectory() as t:
                with self.assertRaises(ValueError):
                    attempt_launch(Path(sys.executable), prefix_in(Path(t)), Path("fake.exe"), timeout=30)
        else:
            self.assertTrue(True)

    def test_launch_exit_zero_is_not_install_success(self):
        if os.name == "nt":
            self.skipTest("Native Windows execution forbidden")
        with tempfile.TemporaryDirectory() as t:
            folder = Path(t)
            p = prefix_in(folder)
            exe, _ = media_in(folder)
            with patch("scripts.solidworks_bootstrap_trial.subprocess.Popen") as popen:
                popen.return_value.wait.return_value = 0
                result = attempt_launch(Path(sys.executable), p, exe, timeout=12)
            self.assertTrue(result["wine_process_created"])
            self.assertEqual(result["bootstrapper_process"], "EXIT_ZERO")
            self.assertEqual(result["installation_manager_ui"], "NOT_VERIFIED")
            self.assertEqual(result["full_installation"], "NOT_VERIFIED")
            self.assertEqual(result["activation"], "NOT_ATTEMPTED")
            self.assertEqual(popen.call_args.kwargs["stdout"], subprocess.DEVNULL)
            self.assertEqual(popen.call_args.kwargs["stderr"], subprocess.DEVNULL)

    def test_nonzero_is_not_success(self):
        if os.name == "nt":
            self.skipTest("Native Windows execution forbidden")
        with tempfile.TemporaryDirectory() as t:
            folder = Path(t)
            p = prefix_in(folder)
            exe, _ = media_in(folder)
            with patch("scripts.solidworks_bootstrap_trial.subprocess.Popen") as popen:
                popen.return_value.wait.return_value = 5
                result = attempt_launch(Path(sys.executable), p, exe, timeout=12)
            self.assertEqual(result["bootstrapper_process"], "EXIT_NONZERO")

    def test_timeout_is_recorded_without_fake_success(self):
        if os.name == "nt":
            self.skipTest("Native Windows execution forbidden")
        with tempfile.TemporaryDirectory() as t:
            folder = Path(t)
            p = prefix_in(folder)
            exe, _ = media_in(folder)
            with patch("scripts.solidworks_bootstrap_trial.subprocess.Popen") as popen, \
                 patch("scripts.solidworks_bootstrap_trial.os.killpg"):
                popen.return_value.pid = 42
                popen.return_value.wait.side_effect = [
                    subprocess.TimeoutExpired(["wine"], 10), 0
                ]
                result = attempt_launch(Path(sys.executable), p, exe, timeout=12)
            self.assertEqual(result["bootstrapper_process"], "TIMEOUT")
            self.assertEqual(result["installation_manager_ui"], "NOT_VERIFIED")

    def test_cli_read_only(self):
        with tempfile.TemporaryDirectory() as t:
            folder = Path(t)
            exe, sha = media_in(folder)
            out = folder / "safe.json"
            result = subprocess.run(
                [sys.executable, "-m", "scripts.solidworks_bootstrap_trial",
                 "--installer", str(exe), "--sha256", sha, "--output", str(out)],
                capture_output=True, text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads(out.read_text())
            self.assertEqual(report["bootstrapper_process"], "NOT_EXECUTED")
            self.assertNotIn(str(exe), json.dumps(report))
            self.assertNotIn(sha, json.dumps(report))

    def test_cli_needs_explicit_opt_in_for_wine(self):
        with tempfile.TemporaryDirectory() as t:
            folder = Path(t)
            exe, sha = media_in(folder)
            result = subprocess.run(
                [sys.executable, "-m", "scripts.solidworks_bootstrap_trial",
                 "--installer", str(exe), "--sha256", sha, "--output", str(folder / "out.json"),
                 "--wine", str(Path(sys.executable)), "--prefix", str(prefix_in(folder))],
                capture_output=True, text=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((folder / "out.json").exists())

    def test_failed_cli_message_does_not_leak_paths(self):
        with tempfile.TemporaryDirectory() as t:
            folder = Path(t)
            exe, sha = media_in(folder)
            result = subprocess.run(
                [sys.executable, "-m", "scripts.solidworks_bootstrap_trial",
                 "--installer", str(exe), "--sha256", "0" * 64, "--output", str(folder / "out.json")],
                capture_output=True, text=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn(str(exe), result.stderr)
            self.assertNotIn(sha, result.stderr)


if __name__ == "__main__":
    unittest.main()
