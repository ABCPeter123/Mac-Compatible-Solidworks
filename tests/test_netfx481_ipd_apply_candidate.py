"""Contract tests only; never execute a servicing transaction."""
import unittest
from scripts.netfx481_ipd_apply_candidate import EXPECTED, preflight_ready, parse_apply, verified_runtime_payloads, deferred_journal, verify_deferred
from scripts.netfx481_ipd_wusa_dryrun import CATEGORIES


class ApplyCandidateTests(unittest.TestCase):
    def report(self):
        return {"dryrun": "FAIL", "ipd_substitutions": 1,
                "servicing_performed": False,
                "events": {**dict.fromkeys(CATEGORIES, 0), **EXPECTED}}

    def test_all_experimental_gates_required(self):
        self.assertTrue(preflight_ready(self.report()))
        for key, value in EXPECTED.items():
            report = self.report()
            report["events"][key] = value + 1
            self.assertFalse(preflight_ready(report), key)
        report = self.report()
        report["dryrun"] = "PASS"
        self.assertFalse(preflight_ready(report))

    def packet(self, started=1, completed=1, phase=0, error="00000000", files=0, deferred=0):
        events = self.report()["events"]
        lines = ["SWCOMPAT_IPD_APPLY_SCHEMA=3",
                 f"SWCOMPAT_IPD_APPLY_STARTED={started}",
                 f"SWCOMPAT_IPD_APPLY_COMPLETED={completed}",
                 f"SWCOMPAT_IPD_APPLY_PHASE={phase}",
                 f"SWCOMPAT_IPD_APPLY_WIN32={error}",
                 f"SWCOMPAT_IPD_APPLY_FILES={files}",
                 f"SWCOMPAT_IPD_APPLY_DEFERRED={deferred}",
                 "SWCOMPAT_IPD_APPLY_KEYS=0", "SWCOMPAT_IPD_APPLY_VALUES=0",
                 "SWCOMPAT_IPD_APPLY_ASSEMBLIES=0",
                 "SWCOMPAT_IPD_DRYRUN_SCHEMA=1", "SWCOMPAT_IPD_DRYRUN_RESULT=FAIL",
                 "SWCOMPAT_IPD_DRYRUN_IPD=1"]
        lines += [f"SWCOMPAT_IPD_DRYRUN_C{i}={events[key]}" for i, key in enumerate(CATEGORIES)]
        return ("\n".join(lines) + "\n").encode("ascii")

    def test_byte_identical_original_payload_is_required(self):
        import hashlib
        import struct
        import tempfile
        from pathlib import Path
        def pe(machine, magic):
            raw = bytearray(512)
            raw[:2] = b"MZ"
            struct.pack_into("<I", raw, 0x3c, 128)
            raw[128:132] = b"PE\0\0"
            struct.pack_into("<H", raw, 132, machine)
            struct.pack_into("<H", raw, 148, 240)
            struct.pack_into("<H", raw, 152, magic)
            return bytes(raw)
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "clr.dll"
            data = pe(0x8664, 0x20b)
            p.write_bytes(data)
            digest = hashlib.sha256(data).hexdigest()
            after = {k: ("ABSENT", None) for k in ("CLR64", "CLR32", "MSCORLIB64", "MSCORLIB32")}
            after["CLR64"] = ("PE_AMD64", digest)
            members = {"amd64_fixture/clr.dll": p}
            result = verified_runtime_payloads(members, after)
            self.assertTrue(result["CLR64"]["matches_original"])
            self.assertFalse(result["MSCORLIB64"]["matches_original"])
            self.assertEqual(result["CLR32"]["candidates"], 0)
            after["CLR64"] = ("PE_AMD64", "0" * 64)
            self.assertFalse(verified_runtime_payloads(members, after)["CLR64"]["matches_original"])

    def test_deferred_replacement_requires_original_bytes_and_consumed_temp(self):
        import tempfile
        from pathlib import Path
        from scripts.netfx481_ipd_wusa_dryrun import windows_path
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp).resolve()
            prefix = base / "prefix"
            stage = base / "stage"
            stage.mkdir()
            source = stage / "original.dll"
            source.write_bytes(b"verified original")
            pending = prefix / "drive_c" / "swcompat-ipd-pending"
            pending.mkdir(parents=True)
            destination = prefix / "drive_c" / "windows" / "fixture.dll"
            destination.parent.mkdir()
            destination.write_bytes(b"old")
            temp = pending / "ipd123.tmp"
            temp.write_bytes(source.read_bytes())
            journal = pending / "queue.bin"
            fields = [windows_path(source), r"C:\windows\fixture.dll",
                      r"C:\swcompat-ipd-pending\ipd123.tmp"]
            journal.write_bytes(("\0".join(fields) + "\0").encode("utf-16-le"))
            members = {"original.dll": source}
            queue = deferred_journal(prefix, stage, members, 1)
            self.assertFalse(verify_deferred(queue))
            temp.write_bytes(b"wrong")
            with self.assertRaises(ValueError):
                deferred_journal(prefix, stage, members, 1)
            temp.write_bytes(source.read_bytes())
            temp.replace(destination)
            self.assertTrue(verify_deferred(queue))
            destination.write_bytes(b"wrong")
            self.assertFalse(verify_deferred(queue))
            fields[1] = r"C:\..\escape.dll"
            journal.write_bytes(("\0".join(fields) + "\0").encode("utf-16-le"))
            with self.assertRaises(ValueError):
                deferred_journal(prefix, stage, members, 1)

    def test_partial_write_reports_preserve_first_failure(self):
        result = parse_apply(self.packet(1, 0, 2, "00000020", 14), 1)
        self.assertEqual(result["writes"]["first_failure_phase"], "COPY_FILE")
        self.assertEqual(result["writes"]["win32_error"], "00000020")
        self.assertEqual(result["writes"]["files"], 14)
        with self.assertRaises(ValueError):
            parse_apply(self.packet(0, 0, 2, "00000020", 14), 1)
        with self.assertRaises(ValueError):
            parse_apply(self.packet(1, 1, 2, "00000020", 14), 0)

    def test_separate_transaction_and_strict_results(self):
        result = parse_apply(self.packet(), 0)
        self.assertTrue(result["completed"])
        self.assertEqual(result["preflight"]["dryrun"], "FAIL")
        self.assertFalse(parse_apply(self.packet(0, 0), 1)["started"])
        with self.assertRaises(ValueError):
            parse_apply(self.packet(0, 1), 0)
        with self.assertRaises(ValueError):
            parse_apply(self.packet(), 1)


if __name__ == "__main__":
    unittest.main()
