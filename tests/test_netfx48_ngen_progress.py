"""NGen heartbeat reports only bounded log growth, not Microsoft contents."""
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase

from scripts import netfx48_ngen_progress as p
from scripts.netfx48_ngen_log_evidence import _file


class OriginalNgenHeartbeatTests(TestCase):
    def test_no_log_then_x86_growth_then_unchanged_then_growth(self):
        with TemporaryDirectory() as td:
            prefix = Path(td) / "prefix"
            prefix.mkdir()
            progress = p.NgenProgress(prefix)
            progress.sample()
            self.assertEqual(progress.snapshot()["samples"], 1)
            self.assertEqual(progress.snapshot()["x86_last"], "NO_LOG")
            path = _file(prefix, "X86")
            path.parent.mkdir(parents=True)
            path.write_bytes(b"private assembly and path")
            progress.sample()
            report = progress.snapshot()
            self.assertTrue(p.valid(report))
            self.assertEqual(report["x86_growth_windows"], 1)
            self.assertEqual(report["x64_growth_windows"], 0)
            self.assertEqual(report["x86_last"], "GROWING")
            progress.sample()
            self.assertEqual(progress.snapshot()["x86_last"], "UNCHANGED")
            with path.open("ab") as output:
                output.write(b"SECRET")
            progress.sample()
            report = progress.snapshot()
            self.assertEqual(report["x86_growth_windows"], 2)
            self.assertNotIn("SECRET", str(report))
            self.assertNotIn("private", str(report))

    def test_replaced_log_and_symlink_are_not_counted_as_progress(self):
        with TemporaryDirectory() as td:
            root = Path(td)
            prefix = root / "prefix"
            prefix.mkdir()
            path = _file(prefix, "X64")
            path.parent.mkdir(parents=True)
            path.write_bytes(b"x" * 30)
            progress = p.NgenProgress(prefix)
            path.write_bytes(b"x")
            progress.sample()
            self.assertEqual(progress.snapshot()["x64_last"], "RESET")
            path.unlink()
            outside = root / "outside"
            outside.write_bytes(b"private vendor file")
            path.symlink_to(outside)
            progress.sample()
            self.assertEqual(progress.snapshot()["x64_last"], "UNSAFE")
            self.assertEqual(progress.snapshot()["x64_growth_windows"], 0)
            self.assertTrue(p.valid(progress.snapshot()))
            self.assertEqual(outside.read_bytes(), b"private vendor file")

    def test_strict_schema_and_max_samples(self):
        with TemporaryDirectory() as td:
            prefix = Path(td) / "prefix"
            prefix.mkdir()
            progress = p.NgenProgress(prefix)
            for _ in range(p.MAX_SAMPLES + 5):
                progress.sample()
            result = progress.snapshot()
            self.assertEqual(result["samples"], p.MAX_SAMPLES)
            self.assertTrue(p.valid(result))
            self.assertFalse(p.valid({**result, "private_path": "secret"}))
            self.assertFalse(p.valid({**result, "x86_growth_windows": True}))
            self.assertFalse(p.valid({**result, "samples": 100}))
            self.assertFalse(p.valid({**result, "x86_last": "COMPILATION_OK"}))
            self.assertFalse(p.valid({**result, "status": []}))
            self.assertFalse(p.valid({**result, "x86_last": []}))
            self.assertTrue(p.valid(p.blank()))
            self.assertFalse(p.valid({**p.blank(), "samples": 1}))
