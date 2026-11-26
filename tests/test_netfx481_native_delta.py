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
