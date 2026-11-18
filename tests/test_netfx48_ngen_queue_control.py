"""Genuine NGen pause/continue never fabricates the original MSI result."""
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase, mock

from scripts import netfx48_ngen_queue_control as q


class OriginalNgenQueueTests(TestCase):
    def paths(self, td):
        root = Path(td)
        prefix = root / "prefix"
        prefix.mkdir()
        for arch in q.ARCS:
            path = prefix / "drive_c" / "windows" / "Microsoft.NET"
            for part in q.ARCS[arch]:
                path = path / part
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"MZ" + b"x" * 4998)
        return root / "wine", prefix

    def test_uses_actual_original_ngen_binary_and_restores_both_queues(self):
        with TemporaryDirectory() as td:
            wine, prefix = self.paths(td)
            calls = []
            def run(args, env, cwd, timeout):
                calls.append((args, env, cwd, timeout))
                return "SUCCESS"
            with mock.patch.object(q, "validate_prefix"):
                before = q.prepare(wine, prefix, {"WINEDEBUG": "-all"}, run)
                self.assertEqual(before["status"], "PREPARED")
                self.assertTrue(q.valid(before))
                after = q.resume(wine, prefix, {}, before, run)
            self.assertEqual(after["status"], "COMPLETE")
            self.assertTrue(q.valid(after))
            self.assertEqual([c[0][-2:] for c in calls], [
                ["queue", "pause"], ["queue", "pause"],
                ["queue", "continue"], ["queue", "continue"]])
            self.assertTrue(all(c[1]["WINEDLLOVERRIDES"] == "mscoree=n;clr=n"
                                for c in calls))
            self.assertTrue(all(c[3] == 40 and c[2] == prefix for c in calls))
            self.assertTrue(all("/Microsoft.NET/" in c[0][1] for c in calls))

    def test_failed_x86_pause_restores_prior_x64_and_never_starts_msi(self):
        with TemporaryDirectory() as td:
            wine, prefix = self.paths(td)
            calls = []
            def run(args, env, cwd, timeout):
                calls.append(args[-1])
                return "EXIT_NONZERO" if len(calls) == 2 else "SUCCESS"
            with mock.patch.object(q, "validate_prefix"):
                outcome = q.prepare(wine, prefix, {}, run)
            self.assertEqual(calls, ["pause", "pause", "continue"])
            self.assertEqual(outcome["status"], "INCOMPLETE")
            self.assertEqual(outcome["x86_pause"], "EXIT_NONZERO")
            self.assertEqual(outcome["x64_continue"], "SUCCESS")
            self.assertTrue(q.valid(outcome))

    def test_failed_process_cleanup_must_not_launch_any_new_wine_process(self):
        with TemporaryDirectory() as td:
            wine, prefix = self.paths(td)
            calls = []
            def bad(args, env, cwd, timeout):
                calls.append(args[-1])
                return "TIMED_OUT_CLEANUP_DENIED"
            with mock.patch.object(q, "validate_prefix"):
                result = q.prepare(wine, prefix, {}, bad)
            self.assertEqual(result["status"], "DIRTY")
            self.assertEqual(calls, ["pause"])
            self.assertTrue(q.valid(result))
            with mock.patch.object(q, "validate_prefix"):
                prepared = {**q.blank(), "status": "PREPARED",
                            "x64_pause": "SUCCESS", "x86_pause": "SUCCESS"}
                dirty = q.resume(wine, prefix, {}, prepared, bad, dirty=True)
            self.assertEqual(dirty["status"], "DIRTY")
            self.assertEqual(calls, ["pause"])
            self.assertTrue(q.valid(dirty))

    def test_missing_symlink_or_non_pe_ngen_is_not_executed(self):
        with TemporaryDirectory() as td:
            wine, prefix = self.paths(td)
            x64, state = q._source(prefix, "x64")
            self.assertEqual(state, "SUCCESS")
            x64.write_bytes(b"wrong" * 1000)
            self.assertEqual(q._source(prefix, "x64")[1], "UNSAFE")
            original = Path(td) / "untrusted"
            original.write_bytes(b"MZ" + b"x" * 4998)
            x64.unlink()
            x64.symlink_to(original)
            self.assertEqual(q._source(prefix, "x64")[1], "UNSAFE")
            self.assertEqual(original.stat().st_size, 5000)
            x64.unlink()
            self.assertEqual(q._source(prefix, "x64")[1], "NOT_FOUND")

    def test_strict_finite_report_and_no_false_pause(self):
        self.assertTrue(q.valid(q.blank()))
        good = {**q.blank(), "status": "COMPLETE",
                "x64_pause": "SUCCESS", "x86_pause": "SUCCESS",
                "x64_continue": "SUCCESS", "x86_continue": "SUCCESS"}
        self.assertTrue(q.valid(good))
        self.assertFalse(q.valid({**good, "native48_candidate": True}))
        self.assertFalse(q.valid({**good, "x86_pause": "PRIVATE_PATH"}))
        self.assertFalse(q.valid({**good, "x64_continue": "NOT_RUN"}))
        self.assertFalse(q.valid({**good, "status": []}))
        self.assertFalse(q.valid({**good, "x86_pause": []}))
        self.assertFalse(q.valid({**q.blank(), "status": "COMPLETE"}))
