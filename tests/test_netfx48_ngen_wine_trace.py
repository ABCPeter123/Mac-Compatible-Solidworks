"""NGen Wine failure taxonomy must discard private debug output."""
import io
import unittest

from scripts import netfx48_ngen_wine_trace as trace


class NgenWinePrivateTraceTests(unittest.TestCase):
    def test_known_critical_section_seh_rpc_signatures_are_finite(self):
        raw = (b"00ab:err:seh:setup_exception_record stack overflow 756 bytes "
               b"eip 12345678 private path /Users/runner/secret.exe\n"
               b"00ab:err:ntdll:RtlpWaitForCriticalSection section 0x110060 "
               b"wait timed out in thread 0011\n"
               b"00ab:err:ole:ifproxy_release_public_refs "
               b"IRemUnknown_RemRelease failed with error 0x800706be\n")
        report = trace.classify(raw)
        self.assertEqual(report, {"status": "CLASSIFIED",
                                 "signals": ["CRITICAL_SECTION_WAIT",
                                             "RPC_DISCONNECTED",
                                             "STACK_OVERFLOW"]})
        self.assertTrue(trace.valid(report))
        self.assertNotIn("Users", str(report))
        self.assertNotIn("eip", str(report))
        self.assertNotIn("12345678", str(report))

    def test_known_access_violation_and_missing_service_only(self):
        report = trace.classify(b"err:seh: 0xc0000005; err:service: 0x80070424")
        self.assertEqual(report, {"status": "CLASSIFIED",
                                 "signals": ["ACCESS_VIOLATION", "SERVICE_NOT_FOUND"]})
        self.assertTrue(trace.valid(report))

    def test_no_signal_does_not_claim_success(self):
        report = trace.classify(b"random Wine diagnostic without error keys")
        self.assertEqual(report, {"status": "NO_SIGNATURE", "signals": []})
        self.assertTrue(trace.valid(report))
        self.assertEqual(trace.classify(b""), report)

    def test_fail_closed_for_oversized_or_invalid_bytes(self):
        for payload, expected in [
            (b"A" * (trace.MAX_BYTES + 1), "TOO_LARGE"),
            (b"stack overflow\x00private", "UNREADABLE"),
            (b"\xff\xfe", "UNREADABLE"),
        ]:
            with self.subTest(expected=expected):
                report = trace.classify(payload)
                self.assertEqual(report, trace.blank(expected))
                self.assertTrue(trace.valid(report))
        self.assertEqual(trace.classify(None), trace.blank("UNREADABLE"))

    def test_report_schema_rejects_dynamic_private_strings(self):
        self.assertTrue(trace.valid(trace.blank()))
        self.assertFalse(trace.valid({"status": "CLASSIFIED", "signals": []}))
        self.assertFalse(trace.valid({"status": "NO_SIGNATURE", "signals": ["STACK_OVERFLOW"]}))
        self.assertFalse(trace.valid({"status": "CLASSIFIED",
                                      "signals": ["STACK_OVERFLOW", "STACK_OVERFLOW"]}))
        self.assertFalse(trace.valid({"status": "CLASSIFIED", "signals": ["private-file"]}))
        self.assertFalse(trace.valid(dict(trace.blank(), debug_output="private")))

    def test_private_stream_returns_only_taxonomy(self):
        stream = io.BytesIO(b"some original text with 0xc00000fd\nPRIVATE")
        result = trace.classify_private_stream(stream)
        self.assertEqual(result, {"status": "CLASSIFIED",
                                  "signals": ["STACK_OVERFLOW"]})
        self.assertNotIn("PRIVATE", str(result))


if __name__ == "__main__":
    unittest.main()
