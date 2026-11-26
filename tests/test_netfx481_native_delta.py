import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch
import zlib
from scripts import netfx481_native_delta as p


class NativeDeltaTests(unittest.TestCase):
    def test_framing_requires_exact_signature_and_prefix_crc(self):
        for tag in (b"PA19", b"PA30", b"PA31"):
            raw = tag + b"fixture"
            self.assertEqual(p.format_and_offset(raw[:8], raw), (tag.decode().lower(), 0))
            wrapped = zlib.crc32(raw).to_bytes(4, "little") + raw
            self.assertEqual(p.format_and_offset(wrapped[:8], wrapped), (tag.decode().lower(), 4))
            bad = b"\0" * 4 + raw
            self.assertIsNone(p.format_and_offset(bad[:8], bad))
        self.assertIsNone(p.format_and_offset(b"junk", b"junk"))

    def test_decode_output_not_retained_and_failure_not_success(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            codec = root / "ms-delta"
            raw = b"PA30fixture"
            def fake(command, cwd, timeout):
                output = Path(command[-1])
                output.write_bytes(b"synthetic target")
                return True
            with patch.object(p, "run_private", side_effect=fake):
                state, digest = p.decode_one(codec, raw, root, 0)
                self.assertEqual(state, "DECODED")
                self.assertEqual(len(digest), 32)
                self.assertEqual(list(root.iterdir()), [])
            with patch.object(p, "run_private", return_value=False):
                self.assertEqual(p.decode_one(codec, raw, root, 1), ("DECODE_FAILED", None))
                self.assertEqual(list(root.iterdir()), [])

    def test_decoder_refuses_existing_target(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "target-0.bin").write_bytes(b"do not overwrite")
            with self.assertRaises(ValueError):
                p.decode_one(root / "ms-delta", b"PA30fixture", root, 0)


class CixGraphTests(unittest.TestCase):
    def test_reverse_order_basis_and_raw(self):
        from scripts.netfx481_cix_graph import parse, order
        raw = b"""<Container xmlns="urn:test">
        <File id="3" name="dir\\target.dll" length="4"><Delta><Source type="PA30" name="0"/><Basis file="2"/></Delta></File>
        <File id="2" name="base.dll" length="4"><Delta><Source type="RAW" name="raw.dll"/></Delta></File>
        </Container>"""
        entries, unsupported = parse(raw)
        self.assertEqual(unsupported, 0)
        self.assertEqual(order(entries), (["2", "3"], set()))
        self.assertEqual(entries["3"].name, "dir/target.dll")

    def test_cycle_and_missing_basis_blocked(self):
        from scripts.netfx481_cix_graph import Entry, order
        entries = {
            "1": Entry("1", "a", 1, "PA30", "0", "2"),
            "2": Entry("2", "b", 1, "PA30", "1", "1"),
            "3": Entry("3", "c", 1, "PA30", "2", "99"),
            "4": Entry("4", "d", 1, "RAW", "raw", None),
        }
        self.assertEqual(order(entries), (["4"], {"1", "2", "3"}))

    def test_unsafe_paths_and_entity_declarations(self):
        from scripts.netfx481_cix_graph import path_key, parse
        for name in ("../file", "a/../file", "/file", "C:\\file", "x//y", "x."):
            with self.assertRaises(ValueError):
                path_key(name)
        with self.assertRaises(ValueError):
            parse(b'<!DOCTYPE x [<!ENTITY a "test">]><x/>')

    def test_actual_source_argument_and_exact_target_oracle(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            raw, work, oracle = (root / x for x in ("raw", "work", "oracle"))
            for x in (raw, work, oracle):
                x.mkdir()
            (raw / "_manifest_.cix.xml").write_text(
                '<Container><File id="3" name="target.dll" length="4"><Delta>'
                '<Source type="PA30" name="0"/><Basis file="2"/></Delta></File>'
                '<File id="2" name="base.dll" length="4"><Delta>'
                '<Source type="RAW" name="raw.dll"/></Delta></File></Container>')
            (raw / "0").write_bytes(b"PA30fixture")
            (raw / "raw.dll").write_bytes(b"base")
            (oracle / "base.dll").write_bytes(b"base")
            (oracle / "target.dll").write_bytes(b"new!")
            def fake(command, cwd, timeout):
                self.assertIn("--source", command)
                self.assertEqual(Path(command[command.index("--source") + 1]).read_bytes(), b"base")
                Path(command[command.index("--output") + 1]).write_bytes(b"new!")
                return True, "OTHER"
            with patch.object(p, "observe_decoder", side_effect=fake):
                report = p.reconstruct(root / "ms-delta", raw, list(raw.iterdir()), work, oracle)
            self.assertEqual(report["cix_reconstructed"], 2)
            self.assertEqual(report["cix_delta_reconstructed"], 1)
            self.assertEqual(report["cix_oracle_matches"], 2)
            self.assertEqual(report["cix_oracle_mismatches"], 0)


    def test_null_source_retry_is_explicit_and_error_classes_safe(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            raw, work = (root / x for x in ("raw", "work"))
            raw.mkdir()
            work.mkdir()
            (raw / "_manifest_.cix.xml").write_text(
                '<Container><File id="1" name="target.dll" length="4"><Delta>'
                '<Source type="PA30" name="0"/></Delta></File></Container>')
            (raw / "0").write_bytes(b"PA30fixture")
            def fake(command, cwd, timeout):
                if "--source" not in command:
                    return False, "INVALID"
                self.assertEqual(Path(command[command.index("--source") + 1]).read_bytes(), b"")
                Path(command[command.index("--output") + 1]).write_bytes(b"new!")
                return True, "OTHER"
            with patch.object(p, "observe_decoder", side_effect=fake):
                report = p.reconstruct(root / "ms-delta", raw, list(raw.iterdir()), work, None)
            self.assertEqual(report["cix_empty_source_recovered"], 1)
            self.assertEqual(report["cix_delta_reconstructed"], 1)
        self.assertEqual(p.classify_decoder_error(b"unsupported delta at PRIVATE"), "UNSUPPORTED")
        self.assertEqual(p.classify_decoder_error(b"delta integrity check failed: PRIVATE"), "INTEGRITY")
        self.assertEqual(p.classify_decoder_error(b"unexpected argument PRIVATE"), "CLI_USAGE")
        self.assertEqual(p.classify_decoder_error(b"PRIVATE"), "OTHER")


    def test_debug_error_variants_and_exact_reason(self):
        for raw, expected in (
            (b'Error: Integrity("PA30 target hash mismatch")', "TARGET_HASH"),
            (b'Error: Unsupported("PA30 target hash algorithm")', "HASH_ALGORITHM"),
            (b'Error: Limit("PA30 parameter memory")', "PARAMETER_LIMIT"),
            (b'Error: Invalid("unknown")', "INVALID"),
            (b'Error: Unsupported("PA30 unknown transform flag")', "TRANSFORM"),
            (b'Error: Io(Os { code: 2 })', "IO"),
        ):
            self.assertEqual(p.classify_decoder_error(raw), expected)

    def test_external_verifier_requires_exact_independent_reference(self):
        import hashlib
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            raw, work, oracle = (root / x for x in ("raw", "work", "oracle"))
            for x in (raw, work, oracle):
                x.mkdir()
            (raw / "_manifest_.cix.xml").write_text(
                '<Container><File id="1" name="target.dll" length="4"><Delta>'
                '<Source type="PA30" name="0"/></Delta></File></Container>')
            (raw / "0").write_bytes(b"PA30fixture")
            (oracle / "target.dll").write_bytes(b"new!")
            helper = root / "swcompat-verified-delta"

            def decode(command, cwd, timeout):
                self.assertEqual(Path(command[0]), helper)
                self.assertEqual(Path(command[1]).read_bytes(), b"")
                self.assertEqual(command[-2:], ["4", hashlib.sha256(b"new!").hexdigest()])
                Path(command[3]).write_bytes(b"new!")
                return True
            with patch.object(p, "observe_decoder", return_value=(False, "HASH_ALGORITHM")), patch.object(p, "run_private", side_effect=decode):
                report = p.reconstruct(root / "ms-delta", raw, list(raw.iterdir()), work, oracle, helper)
            self.assertEqual(report["cix_external_hash_recovered"], 1)
            self.assertEqual(report["cix_oracle_matches"], 1)

            # An intrinsic digest mismatch must not be routed to the helper.
            work2 = root / "work2"
            work2.mkdir()
            with patch.object(p, "observe_decoder", return_value=(False, "TARGET_HASH")), patch.object(p, "run_private") as fallback, patch.object(p, "native_delta_reference", return_value="MATCH"):
                report = p.reconstruct(root / "ms-delta", raw, list(raw.iterdir()), work2, oracle, helper)
            fallback.assert_not_called()
            self.assertEqual(report["cix_delta_failed"], 1)
            self.assertEqual(report["cix_external_hash_recovered"], 0)
