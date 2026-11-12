import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest

from swcompat.cli import main, find_wine

class CLITests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.prefix = self.root / "prefix"
        self.logs = self.root / "logs"
        self.wine = self.root / "wine"
        self.boot = self.root / "wineboot"
        self.wine.write_text(
            '#!/bin/sh\n'
            'if [ "$1" = "--version" ]; then echo wine-11-test; exit 0; fi\n'
            'if [ "$1" = "cmd.exe" ]; then echo Microsoft Windows; exit 0; fi\n'
            'case "$1" in *good.exe) echo SWCOMPAT_WGL=PASS; exit 0;; '
            '*bad.exe) echo SWCOMPAT_WGL=FAIL; exit 0;; esac\n'
            'exit 1\n'
        )
        self.boot.write_text('#!/bin/sh\nmkdir -p "$WINEPREFIX"\n')
        self.wine.chmod(0o755)
        self.boot.chmod(0o755)

    def invoke(self, *args):
        output = io.StringIO()
        common = ["--wine", str(self.wine), "--prefix", str(self.prefix),
                  "--logs-dir", str(self.logs)]
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            code = main([*common, *args])
        return code, output.getvalue()

    def test_discovery(self):
        self.assertEqual(find_wine(str(self.wine)), self.wine.resolve())
        self.assertIsNone(find_wine("/a/nonexistent/file/that/is-not-wine"))

    def test_doctor(self):
        code, output = self.invoke("doctor", "--json")
        self.assertEqual(code, 0)
        report = json.loads(output)
        self.assertTrue(report["wine_responds"])
        self.assertEqual(report["wine_version"], "wine-11-test")
        self.assertFalse(report["prefix_exists"])

    def test_prefix_required(self):
        code, output = self.invoke("probe-win32")
        self.assertEqual(code, 2)
        self.assertIn("prefix missing", output)

    def test_init_and_win32(self):
        self.assertEqual(self.invoke("init")[0], 0)
        self.assertTrue(self.prefix.is_dir())
        code, output = self.invoke("probe-win32")
        self.assertEqual(code, 0)
        self.assertIn("PASS", output)
        self.assertEqual(len(list(self.logs.glob("*-win32-*.log"))), 1)

    def test_wgl_requires_success_marker_not_only_exit_zero(self):
        self.assertEqual(self.invoke("init")[0], 0)
        bad = self.root / "bad.exe"
        bad.touch()
        code, output = self.invoke("probe-wgl", "--exe", str(bad))
        self.assertEqual(code, 1)
        self.assertIn("FAIL", output)
        good = self.root / "good.exe"
        good.touch()
        code, output = self.invoke("probe-wgl", "--exe", str(good))
        self.assertEqual(code, 0)
        self.assertIn("PASS", output)

    def test_analyze(self):
        log = self.root / "wine.log"
        log.write_text("0000:err:module:import_dll Library msvcp140.dll not found\n")
        code, output = self.invoke("analyze", str(log))
        self.assertEqual(code, 0)
        self.assertIn("msvcp140.dll", output)

    def test_does_not_run_nonexistent_exe(self):
        self.assertEqual(self.invoke("init")[0], 0)
        self.assertEqual(self.invoke("install", str(self.root / "nonexistent.exe"))[0], 2)

if __name__ == "__main__":
    unittest.main()
