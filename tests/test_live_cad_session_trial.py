"""Regression tests for the integrated Win32/WGL synthetic CAD session."""
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest import mock

from scripts import live_cad_session_trial as stage


def markers(phase="run"):
    if phase == "verify":
        return b"SWCOMPAT_LIVE_INDEPENDENT_REOPEN=PASS\n"
    return ("\n".join(
        "SWCOMPAT_LIVE_" + key + "=PASS" for key in stage.PASS_MARKERS
    ) + "\nSWCOMPAT_LIVE_RESULT=PASS\n").encode("ascii")


class InteractiveCadSessionTests(unittest.TestCase):
    def test_requires_all_framebuffer_checks_not_a_single_success_marker(self):
        self.assertEqual(stage.parse(markers(), 0, "run")["result"], "PASS")
        for name in stage.PASS_MARKERS:
            with self.subTest(name=name):
                raw = markers().replace(
                    ("SWCOMPAT_LIVE_" + name + "=PASS\n").encode(), b"")
                self.assertEqual(stage.parse(raw, 0, "run")["result"], "UNVERIFIED")
        self.assertEqual(stage.parse(markers("verify"), 0, "verify")["result"], "PASS")

    def test_disallows_private_or_malformed_probe_data(self):
        invalid = [
            markers() + b"SWCOMPAT_LIVE_SECRET=C:\\private\n",
            markers() + b"SWCOMPAT_LIVE_RESULT=PASS\n",
            markers() + b"\x00",
            markers() + b"X" * stage.MAX_OUTPUT,
            markers().replace(b"EXTRUDE_REDRAW=PASS", b"EXTRUDE_REDRAW=NO"),
            b"\xff" + markers(),
        ]
        for raw in invalid:
            with self.subTest(sample=raw[:20]):
                self.assertEqual(stage.parse(raw, 0, "run")["result"], "UNVERIFIED")
        self.assertEqual(stage.parse(markers(), 1, "run")["result"], "UNVERIFIED")

    def test_accepts_bounded_failing_stage_without_leaking_log(self):
        raw = (
            b"SWCOMPAT_LIVE_INITIAL_DEPTH=PASS\n"
            b"SWCOMPAT_LIVE_STAGE=ExtrudeAndFrame\n"
            b"SWCOMPAT_LIVE_RESULT=FAIL\n"
        )
        self.assertEqual(stage.parse(raw, 1, "run"),
                         {"result": "FAIL", "reason": "ExtrudeAndFrame"})
        self.assertEqual(stage.parse(raw.replace(b"ExtrudeAndFrame", b"C:\\Users\\me"), 1, "run")["result"], "UNVERIFIED")

    def test_exact_synthetic_3d_model_bytes(self):
        with TemporaryDirectory() as td:
            path = Path(td) / stage.DOCUMENT
            self.assertEqual(stage.model_file_state(path), "ABSENT")
            path.write_bytes(b"SWCAD3D1" + b"\x00" * 36)
            self.assertEqual(stage.model_file_state(path), "MISMATCH")
            path.write_bytes(stage.EXPECTED)
            self.assertEqual(stage.model_file_state(path), "EXACT")
            path.write_bytes(stage.EXPECTED + b"x")
            self.assertEqual(stage.model_file_state(path), "MISMATCH")

    @unittest.skipIf(os.name == "nt", "Mocked disposable Wine environment is POSIX-only")
    def test_separate_windows_process_must_verify_exact_model(self):
        with TemporaryDirectory() as td:
            root = Path(td)
            prefix = root / "prefix"
            (prefix / "drive_c").mkdir(parents=True)
            (prefix / "system.reg").touch()
            (prefix / ".swcompat-netfx481-disposable").touch()
            wine = root / "wine"
            wine.write_bytes(b"fake")
            wine.chmod(0o700)
            fixture = root / stage.EXE_NAME
            fixture.write_bytes(b"fake")
            doc = prefix / "drive_c" / stage.DOCUMENT
            phases = []
            def fake_process(_wine, _fixture, _prefix, phase, _timeout):
                phases.append(phase)
                if phase == "run":
                    doc.write_bytes(stage.EXPECTED)
                return {"result": "PASS", "reason": "NOT_VERIFIED"}
            with (mock.patch.object(stage, "validate_mesa"),
                  mock.patch.object(stage, "process", side_effect=fake_process)):
                report = stage.trial(wine, prefix, fixture)
            self.assertEqual(phases, ["run", "verify"])
            self.assertTrue(stage.validate(report))
            self.assertTrue(report["synthetic_cad_session"])
            self.assertFalse(report["native_solidworks_cad"])
            self.assertFalse(doc.exists())
            corrupt = dict(report, solidworks_compatibility="READY")
            self.assertFalse(stage.validate(corrupt))
            corrupt = dict(report, saved_model="PRESENT")
            self.assertFalse(stage.validate(corrupt))

    @unittest.skipIf(os.name == "nt", "Mocked disposable Wine environment is POSIX-only")
    def test_wrong_model_does_not_trigger_independent_reopen(self):
        with TemporaryDirectory() as td:
            root = Path(td)
            prefix = root / "prefix"
            (prefix / "drive_c").mkdir(parents=True)
            (prefix / "system.reg").touch()
            (prefix / ".swcompat-netfx481-disposable").touch()
            wine = root / "wine"
            wine.write_bytes(b"fake")
            wine.chmod(0o700)
            fixture = root / stage.EXE_NAME
            fixture.write_bytes(b"fake")
            doc = prefix / "drive_c" / stage.DOCUMENT
            def broken_run(*args):
                doc.write_bytes(b"not-the-3d-model")
                return {"result": "PASS", "reason": "NOT_VERIFIED"}
            with (mock.patch.object(stage, "validate_mesa"),
                  mock.patch.object(stage, "process", side_effect=broken_run) as p):
                report = stage.trial(wine, prefix, fixture)
            self.assertEqual(p.call_count, 1)
            self.assertFalse(report["synthetic_cad_session"])
            self.assertFalse(doc.exists())

    @unittest.skipIf(os.name == "nt", "Mocked disposable Wine environment is POSIX-only")
    def test_refuses_preexisting_document_without_deleting(self):
        with TemporaryDirectory() as td:
            root = Path(td)
            prefix = root / "prefix"
            (prefix / "drive_c").mkdir(parents=True)
            (prefix / "system.reg").touch()
            (prefix / ".swcompat-netfx481-disposable").touch()
            wine = root / "wine"
            wine.write_bytes(b"fake")
            wine.chmod(0o700)
            fixture = root / stage.EXE_NAME
            fixture.write_bytes(b"fake")
            doc = prefix / "drive_c" / stage.DOCUMENT
            doc.write_bytes(b"preserve")
            with (mock.patch.object(stage, "validate_mesa"),
                  mock.patch.object(stage, "process") as process):
                with self.assertRaises(ValueError):
                    stage.trial(wine, prefix, fixture)
                process.assert_not_called()
            self.assertEqual(doc.read_bytes(), b"preserve")


if __name__ == "__main__":
    unittest.main()
