"""Vendor-free regressions: media stays on each Mac runner, never in artifacts."""
from __future__ import annotations
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest import mock
from scripts import netfx4x_authenticated_media_fetch as m


class OriginalMediaPrivacyTests(unittest.TestCase):
    def test_catalog_is_only_fixed_microsoft_https_sources(self):
        self.assertEqual(set(m.MEDIA), {"40", "48", "481"})
        for version, (name, sha_file, url) in m.MEDIA.items():
            self.assertTrue(name.endswith(".exe"))
            self.assertTrue(sha_file.endswith(".sha256"))
            self.assertTrue(url.startswith("https://download.microsoft.com/"))
            self.assertNotIn(" ", url)

    def test_checksums_are_exact_and_original_40_remains_pinned(self):
        with tempfile.TemporaryDirectory() as d:
            build = Path(d)
            (build / "netfx40.sha256").write_text(m.KNOWN_ORIGINAL40_SHA256, encoding="ascii")
            self.assertEqual(m.verified_windows_digest(build, "40"),
                             m.KNOWN_ORIGINAL40_SHA256)
            (build / "netfx40.sha256").write_text("A" * 64, encoding="ascii")
            with self.assertRaises(ValueError):
                m.verified_windows_digest(build, "40")
            (build / "netfx48.sha256").write_text("f" * 64 + "\n", encoding="ascii")
            with self.assertRaises(ValueError):
                m.verified_windows_digest(build, "48")
            (build / "netfx48.sha256").unlink()
            (build / "netfx48.sha256").symlink_to(build / "netfx40.sha256")
            with self.assertRaises(ValueError):
                m.verified_windows_digest(build, "48")

    def test_download_accepts_only_matching_authenticated_digest(self):
        with tempfile.TemporaryDirectory() as d:
            build = Path(d)
            payload = b"self-authored-test-bytes"
            digest = hashlib.sha256(payload).hexdigest()
            (build / "netfx48.sha256").write_text(digest, encoding="ascii")
            observed = []
            def fake_curl(args, **kw):
                self.assertEqual(args[0], "curl")
                self.assertEqual(kw["stdout"], m.subprocess.DEVNULL)
                self.assertEqual(kw["stderr"], m.subprocess.DEVNULL)
                self.assertNotIn("shell", kw)
                self.assertTrue(args[-1].startswith("https://download.microsoft.com/"))
                Path(args[args.index("--output") + 1]).write_bytes(payload)
                observed.append(args[-1])
                return mock.Mock(returncode=0)
            with mock.patch.object(m, "MIN_BYTES", 1), \
                 mock.patch.object(m.subprocess, "run", side_effect=fake_curl):
                m.stage(build, ["48"])
            self.assertEqual((build / m.MEDIA["48"][0]).read_bytes(), payload)
            self.assertEqual(len(observed), 1)
            with self.assertRaises(ValueError):
                m.stage(build, ["48"])

    def test_bad_checksum_or_failed_fetch_leaves_no_original_artifacts(self):
        with tempfile.TemporaryDirectory() as d:
            build = Path(d)
            payload = b"source-authored-only"
            (build / "netfx481.sha256").write_text("a" * 64, encoding="ascii")
            def fake_curl(args, **kw):
                Path(args[args.index("--output") + 1]).write_bytes(payload)
                return mock.Mock(returncode=0)
            with mock.patch.object(m, "MIN_BYTES", 1), \
                 mock.patch.object(m.subprocess, "run", side_effect=fake_curl):
                with self.assertRaises(ValueError):
                    m.stage(build, ["481"])
            self.assertFalse((build / m.MEDIA["481"][0]).exists())
            self.assertFalse(any(build.glob(".original-netfx-*")))
            with mock.patch.object(m.subprocess, "run",
                                   return_value=mock.Mock(returncode=22)):
                with self.assertRaises(ValueError):
                    m.stage(build, ["481"])
            self.assertFalse(any(build.glob(".original-netfx-*")))

    def test_manual_workflow_never_uploads_original_microsoft_installers(self):
        workflow = (Path(__file__).resolve().parents[1]
                    / ".github/workflows/netfx40-legacy-ci.yml").read_text(encoding="utf-8")
        self.assertNotIn("authenticated-original-microsoft-netfx40-private", workflow)
        self.assertEqual(workflow.count(
            "name: self-authored-netfx40-probes-and-signed-digests"), 3)
        # Inspect the publisher's exact file list, not download-artifact usage.
        publisher = workflow.split(
            "name: self-authored-netfx40-probes-and-signed-digests", 1)[1]
        publisher = publisher.split("compression-level:", 1)[0]
        for name, _, _ in m.MEDIA.values():
            self.assertNotIn("build/" + name, publisher)
        self.assertNotIn("build/", publisher.split("path: |", 1)[0])
        self.assertIn("build/netfx40.sha256", publisher)
        self.assertIn("build/netfx481.sha256", publisher)
        self.assertIn("build/netfx48.sha256", publisher)
        self.assertEqual(workflow.count(
            "python3 -m scripts.netfx4x_authenticated_media_fetch"), 2)
        self.assertIn('if [ "$SWCOMPAT_PROVENANCE_ONLY" != "true" ]', workflow)
        self.assertIn('if [ "$SWCOMPAT_DIRECT_48" = "true" ]', workflow)

    def test_reject_duplicates_unknown_versions_and_missing_digests(self):
        with tempfile.TemporaryDirectory() as d:
            build = Path(d)
            with self.assertRaises(ValueError):
                m.stage(build, [])
            with self.assertRaises(ValueError):
                m.stage(build, ["40", "40"])
            with self.assertRaises(ValueError):
                m.stage(build, ["evil"])
            with self.assertRaises(ValueError):
                m.stage(build, ["40", "481"])
            self.assertEqual(list(build.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
