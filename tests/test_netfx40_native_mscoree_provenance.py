"""Vendor-free tests for genuine Wine native CLR host provenance categories."""
from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from scripts import netfx40_native_mscoree_provenance as t


def event(dll: str, source: str) -> bytes:
    return (f'0040:trace:loaddll:build_module Loaded '
            f'L"C:\\windows\\system32\\{dll}" at 00007FF0123: {source}\n').encode()


def fixture() -> bytes:
    return (b"SWCOMPAT_NETFX481_SCHEMA=1\n"
            b"SWCOMPAT_NETFX481_REGISTRY=BELOW_481\n"
            b"SWCOMPAT_NETFX481_CLR_FAMILY=MICROSOFT_CLR_CANDIDATE\n"
            b"SWCOMPAT_NETFX481_MANAGED=PASS\n")


class OriginalNativeHostProvenanceTests(unittest.TestCase):
    def test_loads_native_builtin_mixed_and_missing_are_strict_categories(self):
        raw = (event("mscoree.dll", "native") + event("clr.dll", "native") +
               event("kernel32.dll", "builtin"))
        self.assertEqual(t.classify_loads(raw),
                         {"mscoree": "NATIVE_ONLY", "clr": "NATIVE_ONLY"})
        raw = (event("mscoree.dll", "native") +
               event("mscoree.dll", "builtin") +
               event("clr.dll", "builtin"))
        self.assertEqual(t.classify_loads(raw),
                         {"mscoree": "MIXED", "clr": "BUILTIN_ONLY"})
        self.assertEqual(t.classify_loads(b"random message"),
                         {"mscoree": "NOT_OBSERVED", "clr": "NOT_OBSERVED"})
        self.assertEqual(t.classify_loads(b"A" * (t.MAX_OUTPUT + 1)),
                         {"mscoree": "TOO_LARGE", "clr": "TOO_LARGE"})
        self.assertEqual(t.classify_loads(event("unrelated.dll", "native")),
                         {"mscoree": "NOT_OBSERVED", "clr": "NOT_OBSERVED"})

    def test_managed_probe_must_have_all_unique_valid_fields(self):
        self.assertEqual(t.managed_only(fixture(), 0),
                         {"clr_family": "MICROSOFT_CLR_CANDIDATE", "managed": "PASS"})
        self.assertEqual(t.managed_only(fixture(), 1)["managed"], "NOT_VERIFIED")
        self.assertEqual(t.managed_only(fixture() + fixture(), 0)["managed"],
                         "NOT_VERIFIED")
        self.assertEqual(t.managed_only(fixture().replace(b"PASS", b"NOT_REAL"), 0)
                         ["managed"], "NOT_VERIFIED")
        self.assertEqual(t.managed_only(event("mscoree.dll", "native") + fixture(),
                                        0)["managed"], "PASS")

    def test_report_cannot_export_original_paths_or_fake_runtime(self):
        d = t.blank()
        self.assertTrue(t.valid(d))
        self.assertFalse(t.valid(dict(d, original_path="C:\\private\\mscoree.dll")))
        self.assertFalse(t.valid(dict(d, framework48_installed=True)))
        self.assertFalse(t.valid(dict(d, native_host_confirmed=True)))
        self.assertFalse(t.valid(dict(d, status="MEASURED",
                                       native40_persistent=True, process="EXIT_ZERO",
                                       mscoree="NATIVE_ONLY", clr="NATIVE_ONLY",
                                       managed="PASS", family="MICROSOFT_CLR_CANDIDATE",
                                       native_host_confirmed=True)))
        self.assertFalse(t.valid(dict(d, builtin_process="EXIT_ZERO",
                                       builtin_mscoree="BUILTIN_ONLY",
                                       builtin_clr="NOT_OBSERVED",
                                       builtin_managed="PASS",
                                       builtin_family="MONO")))
        self.assertFalse(t.valid(dict(d, status="MEASURED",
                                      native40_persistent=True, process="EXIT_ZERO",
                                      mscoree="NATIVE_ONLY", clr="NATIVE_ONLY",
                                      family="MICROSOFT_CLR_CANDIDATE",
                                      managed="PASS", framework48_installed=True)))
        self.assertNotIn("mscoree.dll", json.dumps(d))

    def test_host_comparison_accepts_only_two_explicit_modes(self):
        with self.assertRaises(ValueError):
            t.execute_private(Path("wine"), Path("prefix"), Path("fixture"), "mscoree=n,b")
        with self.assertRaises(ValueError):
            t.execute_private(Path("wine"), Path("prefix"), Path("fixture"), "mscoree=b;clr=b")

    def test_native_host_must_be_both_native_dlls_and_real_managed_pass(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            wine = root / "wine"
            wine.write_bytes(b"self authored")
            wine.chmod(0o755)
            prefix = root / "prefix"
            (prefix / "drive_c").mkdir(parents=True)
            (prefix / "system.reg").write_bytes(b"")
            (prefix / ".swcompat-netfx481-disposable").write_bytes(b"")
            managed = root / "netfx481_runtime_probe.exe"
            managed.write_bytes(b"self authored")
            raw = (event("mscoree.dll", "native") +
                   event("clr.dll", "native") + fixture())
            invoked = []
            def fake(argv, **kwargs):
                override = kwargs["env"]["WINEDLLOVERRIDES"]
                invoked.append(override)
                self.assertEqual(kwargs["env"]["WINEDEBUG"], "-all,+loaddll")
                if override == "mscoree=n;clr=n":
                    kwargs["stdout"].write(raw)
                elif override == "mscoree=b;clr=n":
                    kwargs["stdout"].write(
                        event("mscoree.dll", "builtin") +
                        fixture().replace(b"MICROSOFT_CLR_CANDIDATE", b"MONO"))
                else:
                    self.fail("Unknown managed CLR host control")
                return mock.Mock(returncode=0)
            with mock.patch.object(t, "validate_native40", return_value=True), \
                 mock.patch.object(t.subprocess, "run", side_effect=fake):
                r = t.audit(wine, prefix, managed, {
                    "persistent_native_managed": True, "native_only_managed": "PASS"
                })
            self.assertTrue(t.valid(r))
            self.assertTrue(r["native_host_confirmed"])
            self.assertEqual(invoked, ["mscoree=n;clr=n", "mscoree=b;clr=n"])
            self.assertEqual(r["builtin_process"], "EXIT_ZERO")
            self.assertEqual(r["builtin_mscoree"], "BUILTIN_ONLY")
            self.assertEqual(r["builtin_clr"], "NOT_OBSERVED")
            self.assertEqual(r["builtin_managed"], "PASS")
            self.assertEqual(r["builtin_family"], "MONO")
            self.assertFalse(r["framework48_installed"])
            for sensitive in (str(root), "C:\\windows", "mscoree.dll"):
                self.assertNotIn(sensitive, json.dumps(r))
            with mock.patch.object(t, "validate_native40", return_value=True):
                self.assertEqual(t.audit(wine, prefix, managed, {
                    "persistent_native_managed": False, "native_only_managed": "FAIL"
                }), t.blank())


if __name__ == "__main__":
    unittest.main()
