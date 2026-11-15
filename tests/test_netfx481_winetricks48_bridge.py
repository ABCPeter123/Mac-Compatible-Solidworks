"""Reject fake Microsoft .NET 4.8.1 from Winetricks recipe exit codes."""
import unittest
from scripts.netfx481_winetricks48_bridge import blank, validate


class Native48BridgeTests(unittest.TestCase):
    def test_failed_winetricks_is_not_481(self):
        for s in ("VERB_FAILED", "VERB_TIMED_OUT", "VERB_START_FAILED",
                  "PREREQUISITE_NOT_READY"):
            with self.subTest(status=s):
                r = blank(s)
                if s == "PREREQUISITE_NOT_READY":
                    r["winetricks48_exit"] = "ZERO"
                self.assertTrue(validate(r))
                self.assertFalse(r["native481_confirmed"])

    def test_3010_no_new_clr_and_no_registration_never_passes(self):
        r = blank("MEASURED")
        r["winetricks48_exit"] = "ZERO"
        r["native48_candidate"] = True
        r["clr64_before481"] = "PE_AMD64"
        r["clr64_after481"] = "PE_AMD64"
        r["clr64_change"] = "UNCHANGED"
        r["native_loader"] = "LOADED"
        r["native_only_managed"] = "PASS"
        r["runtime_family"] = "MICROSOFT_CLR_CANDIDATE"
        r["framework481_registry"] = "NOT_FOUND"
        r["restart"] = "COMPLETED"
        r["setup"] = {
            "status": "EXIT_CAPTURED", "category": "REBOOT_REQUIRED",
            "exit_hex": "00000BC2", "child_seen": "OBSERVED",
            "child_lifecycle": "ALL_EXITED", "child_exit": "REBOOT_REQUIRED",
        }
        self.assertTrue(validate(r))
        self.assertFalse(r["native481_confirmed"])
        self.assertFalse(validate(dict(r, native481_confirmed=True)))
        self.assertFalse(validate(dict(r, private_microsoft_path="SECRET")))

    def test_false_positive_on_nonzero_installer_rejected(self):
        r = blank("MEASURED")
        r.update(winetricks48_exit="ZERO", native48_candidate=True,
                 clr64_before481="PE_AMD64", clr64_after481="PE_AMD64",
                 clr64_change="CHANGED", native_loader="LOADED",
                 native_only_managed="PASS", runtime_family="MICROSOFT_CLR_CANDIDATE",
                 framework481_registry="AT_LEAST_481", restart="NOT_RUN")
        r["setup"] = {"status": "EXIT_CAPTURED", "category": "OTHER",
                      "exit_hex": "000013EC", "child_seen": "OBSERVED",
                      "child_lifecycle": "ALL_EXITED", "child_exit": "NONZERO"}
        self.assertTrue(validate(r))
        self.assertFalse(r["native481_confirmed"])
        self.assertFalse(validate(dict(r, native481_confirmed=True)))


if __name__ == "__main__":
    unittest.main()
