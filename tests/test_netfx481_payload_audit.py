"""Synthetic CLR-on-disk PE inventory, no Microsoft payloads."""
from pathlib import Path
import struct
import tempfile
import unittest

from scripts import netfx481_payload_audit as audit
from scripts import netfx481_trial as trial


def pe(machine=0x8664, magic=0x20B):
    raw = bytearray(1024)
    raw[:2] = b"MZ"
    struct.pack_into("<I", raw, 0x3C, 128)
    raw[128:132] = b"PE\x00\x00"
    struct.pack_into("<H", raw, 132, machine)
    struct.pack_into("<H", raw, 148, 240)
    struct.pack_into("<H", raw, 152, magic)
    return bytes(raw)


class DotNetPayloadTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.prefix = Path(self.temporary.name) / "prefix"
        (self.prefix / "drive_c").mkdir(parents=True)
        (self.prefix / "system.reg").write_text("")
        (self.prefix / trial.SENTINEL).write_text("")

    def file(self, key):
        result = self.prefix / "drive_c"
        for part in audit.ITEMS[key]:
            result = result / part
        result.parent.mkdir(parents=True, exist_ok=True)
        return result

    def test_pe_architecture_is_validated(self):
        self.assertEqual(audit.pe_type(pe()), "PE_AMD64")
        self.assertEqual(audit.pe_type(pe(0x14C, 0x10B)), "PE_I386")
        self.assertEqual(audit.pe_type(pe(0x8664, 0x10B)), "PE_OTHER")
        self.assertEqual(audit.pe_type(b"x" * 1024), "NOT_PE")
        self.assertEqual(audit.pe_type(b"MZ"), "NOT_PE")
        corrupt = bytearray(pe())
        struct.pack_into("<I", corrupt, 0x3C, 0xFFFF)
        self.assertEqual(audit.pe_type(corrupt), "NOT_PE")

    def test_genuine_install_file_changes_are_reported_without_hashes(self):
        before = audit.snapshot(self.prefix)
        self.assertEqual(before["CLR64"][0], "ABSENT")
        self.file("CLR64").write_bytes(pe())
        self.file("CLR32").write_bytes(pe(0x14C, 0x10B))
        after = audit.snapshot(self.prefix)
        report = audit.compare(before, after)
        self.assertEqual(report["status"], "MEASURED")
        self.assertEqual(report["changes"]["CLR64"], "CREATED")
        self.assertEqual(report["after"]["CLR64"], "PE_AMD64")
        self.assertEqual(report["after"]["CLR32"], "PE_I386")
        self.assertEqual(report["changes"]["MSCORLIB64"], "UNCHANGED")
        import json
        encoded = json.dumps(report)
        self.assertNotIn("sha256", encoded.lower())
        self.assertNotIn(self.temporary.name, encoded)
        self.assertNotIn("clr.dll", encoded)

    def test_changed_and_unchanged_files_not_exposed(self):
        target = self.file("CLR64")
        target.write_bytes(pe())
        before = audit.snapshot(self.prefix)
        same = audit.snapshot(self.prefix)
        self.assertEqual(audit.compare(before, same)["changes"]["CLR64"], "UNCHANGED")
        data = bytearray(pe())
        data[-1] = 1
        target.write_bytes(bytes(data))
        changed = audit.compare(before, audit.snapshot(self.prefix))
        self.assertEqual(changed["changes"]["CLR64"], "CHANGED")

    def test_symlink_and_invalid_files_fail_closed(self):
        target = self.file("CLR64")
        target.write_bytes(b"bad")
        self.assertEqual(audit.snapshot(self.prefix)["CLR64"][0], "INVALID_SIZE")
        target.unlink()
        try:
            target.symlink_to(self.prefix / "system.reg")
        except (OSError, NotImplementedError):
            self.skipTest("symlinks unavailable")
        self.assertEqual(audit.snapshot(self.prefix)["CLR64"][0], "LINKED")

    def test_disposable_prefix_required(self):
        (self.prefix / trial.SENTINEL).unlink()
        with self.assertRaises(ValueError):
            audit.snapshot(self.prefix)

    def test_reject_report_schema_injection(self):
        original = audit.blank()
        self.assertTrue(audit.validate(original))
        original["after"]["CLR64"] = "C:\\Users\\private\\clr.dll"
        self.assertFalse(audit.validate(original))
        with self.assertRaises(ValueError):
            audit.compare({"UNEXPECTED": ("PE_AMD64", "secret")}, audit.blank())
