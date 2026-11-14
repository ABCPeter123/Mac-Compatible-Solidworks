"""Self-contained synthetic embedded Microsoft CAB inventory and safety tests."""
from pathlib import Path
import json
import tempfile
from unittest import TestCase, mock

from scripts import netfx481_nested_cab_evidence as nested


def listing(*names):
    data = ["7-Zip", "Path = synthetic.cab", "Type = Cab", "----------"]
    for name in names:
        data.extend([f"Path = {name}", "Size = 1", ""])
    return ("\n".join(data) + "\n").encode("utf-8")


class NativeCabTests(TestCase):
    def test_categorize_only_framework_and_servicing_members(self):
        data = listing("clr.dll", "mscorlib.dl_", "Microsoft-Windows-Servicing.mum",
                       "something.cat", "x64-assembly.manifest", "PRIVATE-USER-NAME.inf")
        r = nested.summarize_cab_listing(data)
        self.assertEqual(r["entries"], 6)
        self.assertTrue(r["features"]["CLR_MEMBER"])
        self.assertTrue(r["features"]["MSCORLIB_MEMBER"])
        self.assertTrue(r["features"]["SERVICING_MANIFEST"])
        self.assertEqual(r["types"]["MUM"], 1)
        self.assertEqual(r["types"]["CAT"], 1)
        self.assertEqual(r["types"]["MANIFEST"], 1)
        self.assertNotIn("PRIVATE", json.dumps(r))
        self.assertNotIn("clr.dll", json.dumps(r))

    def test_cab_scanner_validates_file_and_sevenzip_with_private_output(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            cabdir = root / "cabdir"
            cabdir.mkdir()
            (cabdir / "x64-KB1000000.cab").write_bytes(b"fake cab")
            (cabdir / "second.cab").write_bytes(b"other fake cab")
            exe = root / "7z.exe"
            exe.write_bytes(b"fixture")
            data = [listing("some.dll", "deployment.mum"),
                    listing("clr.dl_", "mscorlib.dll")]
            commands = []
            def run(command, **kwargs):
                commands.append((command, kwargs))
                kwargs["stdout"].write(data[len(commands) - 1])
                return mock.Mock(returncode=0)
            with mock.patch.object(nested.subprocess, "run", side_effect=run):
                report = nested.scan(cabdir, exe)
            self.assertEqual(report["status"], "SCANNED")
            self.assertEqual(report["cab_count"], 2)
            self.assertEqual(report["cabs_listed"], 2)
            self.assertEqual(report["entries"], 4)
            self.assertEqual(report["types"]["DLL"], 2)
            self.assertTrue(report["features"]["CLR_MEMBER"])
            self.assertTrue(report["features"]["MSCORLIB_MEMBER"])
            self.assertTrue(report["features"]["SERVICING_MANIFEST"])
            self.assertTrue(nested.validate(report))
            for command, opts in commands:
                self.assertEqual(command[:3], [str(exe), "l", "-slt"])
                self.assertIs(opts["stderr"], nested.subprocess.DEVNULL)

    def test_read_error_and_missing_files_are_fail_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            cabdir = root / "cabdir"
            cabdir.mkdir()
            exe = root / "7z.exe"
            exe.write_bytes(b"fixture")
            self.assertEqual(nested.scan(cabdir, exe)["status"], "NO_CAB")
            (cabdir / "runtime.cab").write_bytes(b"file")
            with mock.patch.object(nested.subprocess, "run", side_effect=OSError("hidden")):
                r = nested.scan(cabdir, exe)
            self.assertEqual(r["status"], "PARTIAL")
            self.assertEqual(r["entries"], 0)

    def test_invalid_output_schema_and_symlink_rejected(self):
        value = nested.empty()
        self.assertTrue(nested.validate(value))
        value["types"]["DLL"] = 100
        self.assertFalse(nested.validate(value))
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            cabdir = root / "cabdir"
            cabdir.mkdir()
            exe = root / "7z.exe"
            exe.write_bytes(b"fixture")
            file = cabdir / "one.cab"
            try:
                file.symlink_to(exe)
            except (OSError, NotImplementedError):
                return
            with self.assertRaises(ValueError):
                nested.scan(cabdir, exe)
