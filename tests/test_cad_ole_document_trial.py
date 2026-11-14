"""Safety and regression tests for cross-process synthetic CAD OLE document stage."""
from pathlib import Path
import os
from tempfile import TemporaryDirectory
import unittest
from unittest import mock

from scripts import cad_ole_document_trial as stage


def valid_markers(phase: str, result: str = "PASS", reason: str = "OK") -> bytes:
    return (
        f"SWCOMPAT_CAD_DOC_SCHEMA=1\n"
        f"SWCOMPAT_CAD_DOC_PHASE={phase}\n"
        f"SWCOMPAT_CAD_DOC_RESULT={result}\n"
        f"SWCOMPAT_CAD_DOC_REASON={reason}\n"
    ).encode("ascii")


class CADDocumentStageTests(unittest.TestCase):
    def test_strict_phase_parser(self):
        for phase in stage.PHASES:
            self.assertEqual(stage.parse(valid_markers(phase), 0, phase),
                             {"result": "PASS", "reason": "OK"})
            self.assertEqual(
                stage.parse(valid_markers(phase, "FAIL", "MODEL_MISMATCH"),
                            1, phase),
                {"result": "FAIL", "reason": "MODEL_MISMATCH"})

    def test_reject_arbitrary_strings_private_paths_and_exit_spoof(self):
        examples = [
            (valid_markers("CREATE") + b"SWCOMPAT_CAD_DOC_PATH=C:\\Private\n", 0),
            (valid_markers("CREATE") + b"SWCOMPAT_CAD_DOC_PHASE=CREATE\n", 0),
            (valid_markers("EDIT"), 0),
            (valid_markers("CREATE"), 1),
            (valid_markers("CREATE", "FAIL", "OK"), 1),
            (valid_markers("CREATE", "PASS", "MODEL_MISMATCH"), 0),
            (valid_markers("CREATE") + b"\x00", 0),
            (valid_markers("CREATE") + b"X" * stage.MAX_OUTPUT, 0),
        ]
        for data, code in examples:
            with self.subTest(sample=data[:22], status=code):
                self.assertEqual(
                    stage.parse(data, code, "CREATE"),
                    {"result": "UNVERIFIED", "reason": "BAD_REPORT"})

    def test_compound_file_header_checked_not_just_existing_file(self):
        with TemporaryDirectory() as temp:
            p = Path(temp) / stage.DOC_NAME
            self.assertEqual(stage.file_state(p), "ABSENT")
            p.write_bytes(b"untrusted" * 100)
            self.assertEqual(stage.file_state(p), "INVALID")
            p.write_bytes(stage.CFB_MAGIC + b"\x00" * 512)
            self.assertEqual(stage.file_state(p), "PRESENT_CFB")

    @unittest.skipIf(os.name == "nt", "Wine sandbox mocked on POSIX only")
    def test_three_separate_phases_success_still_not_solidworks(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            prefix = root / "prefix"
            (prefix / "drive_c").mkdir(parents=True)
            (prefix / "system.reg").touch()
            (prefix / ".swcompat-netfx481-disposable").touch()
            wine = root / "wine"
            wine.write_bytes(b"test")
            wine.chmod(0o700)
            exe = root / stage.EXE_NAME
            exe.write_bytes(b"test")
            doc = prefix / "drive_c" / stage.DOC_NAME
            calls = []

            def simulate(_w, _p, _f, phase, _t):
                calls.append(phase)
                if phase == "CREATE":
                    doc.write_bytes(stage.CFB_MAGIC + b"\x00" * 512)
                return {"result": "PASS", "reason": "OK"}

            with mock.patch.object(stage, "execute", side_effect=simulate):
                result = stage.trial(wine, prefix, exe)
            self.assertEqual(calls, ["CREATE", "EDIT", "VERIFY"])
            self.assertTrue(stage.validate(result))
            self.assertTrue(result["synthetic_document_roundtrip"])
            self.assertFalse(result["native_solidworks_document"])
            self.assertFalse(doc.exists())
            bad = dict(result, solidworks_compatibility="READY")
            self.assertFalse(stage.validate(bad))
            bad2 = dict(result, verify={"result": "UNVERIFIED",
                                         "reason": "BAD_REPORT"})
            self.assertFalse(stage.validate(bad2))

    @unittest.skipIf(os.name == "nt", "Wine sandbox mocked on POSIX only")
    def test_reject_preexisting_document_without_modifying_it(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            prefix = root / "prefix"
            (prefix / "drive_c").mkdir(parents=True)
            (prefix / "system.reg").touch()
            (prefix / ".swcompat-netfx481-disposable").touch()
            wine = root / "wine"
            wine.write_bytes(b"test")
            wine.chmod(0o700)
            exe = root / stage.EXE_NAME
            exe.write_bytes(b"test")
            doc = prefix / "drive_c" / stage.DOC_NAME
            doc.write_bytes(b"keep me")
            with mock.patch.object(stage, "execute") as call:
                with self.assertRaises(ValueError):
                    stage.trial(wine, prefix, exe)
                call.assert_not_called()
            self.assertEqual(doc.read_bytes(), b"keep me")


if __name__ == "__main__":
    unittest.main()
