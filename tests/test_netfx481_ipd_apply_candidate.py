"""Contract tests only; never execute a servicing transaction."""
import unittest
from scripts.netfx481_ipd_apply_candidate import EXPECTED, preflight_ready, parse_apply
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

    def packet(self, started=1, completed=1):
        events = self.report()["events"]
        lines = ["SWCOMPAT_IPD_APPLY_SCHEMA=1",
                 f"SWCOMPAT_IPD_APPLY_STARTED={started}",
                 f"SWCOMPAT_IPD_APPLY_COMPLETED={completed}",
                 "SWCOMPAT_IPD_DRYRUN_SCHEMA=1", "SWCOMPAT_IPD_DRYRUN_RESULT=FAIL",
                 "SWCOMPAT_IPD_DRYRUN_IPD=1"]
        lines += [f"SWCOMPAT_IPD_DRYRUN_C{i}={events[key]}" for i, key in enumerate(CATEGORIES)]
        return ("\n".join(lines) + "\n").encode("ascii")

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
