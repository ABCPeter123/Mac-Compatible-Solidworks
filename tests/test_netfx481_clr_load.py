"""Synthetic independent Win32 LoadLibraryW result tests."""
from pathlib import Path
import tempfile
from unittest import TestCase, mock

from scripts import netfx481_clr_load as loader
from scripts import netfx481_trial as trial


def payload(status="LOADED"):
    return ("SWCOMPAT_CLR_LOAD_SCHEMA=1\n"
            "SWCOMPAT_CLR_LOAD_STATUS=" + status + "\n").encode("ascii")


class ClrLoaderTests(TestCase):
    def test_exact_results(self):
        for status in ("LOADED", "LOAD_FAILED", "NOT_FOUND", "LINKED"):
            with self.subTest(status=status):
                self.assertEqual(loader.parse(payload(status), 0), status)
        for bad in (
            payload("COMPLETELY_READY"), payload("LOADED") + payload("LOADED"),
            payload("LOADED") + b"SWCOMPAT_CLR_LOAD_UNKNOWN=SECRET\n",
            payload("LOADED") + b"\x00", payload("LOADED") + b"x" * 2000
        ):
            self.assertEqual(loader.parse(bad, 0), "NOT_VERIFIED")
        self.assertEqual(loader.parse(payload("LOADED"), 1), "NOT_VERIFIED")

    def test_never_run_on_unmarked_prefix_or_wrong_fixture(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            prefix = root / "prefix"
            (prefix / "drive_c").mkdir(parents=True)
            (prefix / "system.reg").write_text("")
            wine = root / "wine"
            wine.write_text("synthetic")
            fixture = root / "netfx481_clr_load.exe"
            fixture.write_bytes(b"self-authored")
            with mock.patch.object(loader.subprocess, "run") as subprocess_run:
                with self.assertRaises(ValueError):
                    loader.run(wine, prefix, fixture)
                subprocess_run.assert_not_called()
            (prefix / trial.SENTINEL).write_text("")
            with mock.patch.object(loader.subprocess, "run") as subprocess_run:
                def fake_run(args, **kwargs):
                    self.assertEqual(args, [str(wine), str(fixture)])
                    self.assertEqual(kwargs["env"]["WINEPREFIX"], str(prefix))
                    kwargs["stdout"].write(payload())
                    return mock.Mock(returncode=0)
                subprocess_run.side_effect = fake_run
                self.assertEqual(loader.run(wine, prefix, fixture), "LOADED")
            wrong = root / "arbitrary.exe"
            wrong.write_bytes(b"synthetic")
            with self.assertRaises(ValueError):
                loader.run(wine, prefix, wrong)

    def test_loaded_module_cannot_claim_genuine_framework(self):
        prior = {"registry": "NOT_FOUND", "clr_family": "MONO", "managed": "PASS"}
        report = trial.combine(prior, prior, "EXIT_NONZERO", 3010,
                               clr_dll_load="LOADED")
        self.assertEqual(report["clr_dll_load"], "LOADED")
        self.assertFalse(report["framework_runtime_ready"])
        self.assertFalse(report["new_framework_installation_confirmed"])
        with self.assertRaises(ValueError):
            trial.combine(prior, prior, "EXIT_ZERO", 0,
                          clr_dll_load="MICROSOFT_SIGNED_VERIFIED")
