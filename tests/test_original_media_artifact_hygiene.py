"""Ensure public Actions artifacts contain no Microsoft redistributable media.

Regression guards cover every workflow, including the manually triggered
experiments. Matching only upload-artifact step bodies avoids confusing
private installer *use* on a runner with public artifact publication.
"""
from __future__ import annotations

from pathlib import Path
import re
import unittest

WORKFLOWS = Path(__file__).resolve().parents[1] / ".github" / "workflows"
PROPRIETARY_INSTALLERS = (
    "dotNetFx40_Full_x86_x64.exe",
    "NDP48-x86-x64-AllOS-ENU.exe",
    "NDP481-x86-x64-AllOS-ENU.exe",
    "SolidworksSetup.exe",
)
UPLOAD_STEP = re.compile(r"(?m)^(?P<spaces> +)- uses: actions/upload-artifact@v4\\s*$")


def uploads(text: str) -> list[str]:
    lines = text.splitlines()
    blocks = []
    for i, line in enumerate(lines):
        match = UPLOAD_STEP.match(line)
        if not match:
            continue
        # Stop at the next sibling workflow step, even when it is not an
        # upload. Nested with: name/path entries must remain inside the block.
        level = len(match.group("spaces"))
        next_line = len(lines)
        for j in range(i + 1, len(lines)):
            if re.match(r"^ {" + str(level) + r"}- (?:uses|name|run|id|if):", lines[j]):
                next_line = j
                break
        blocks.append("\\n".join(lines[i:next_line]))
    return blocks


class PublicArtifactPrivacyTests(unittest.TestCase):
    def test_all_workflows_never_upload_original_microsoft_or_cad_installers(self):
        paths = sorted(WORKFLOWS.glob("*.yml"))
        self.assertGreaterEqual(len(paths), 3)
        for workflow in paths:
            with self.subTest(workflow=workflow.name):
                text = workflow.read_text(encoding="utf-8")
                for block in uploads(text):
                    for filename in PROPRIETARY_INSTALLERS:
                        self.assertNotIn(filename, block)
                    self.assertNotIn("authenticated-original-microsoft-netfx40-private", block)
                    self.assertNotIn("authenticated-original-microsoft-netfx48-private", block)
                    self.assertNotIn("signed-netfx481-original-microsoft-runtime", block)

    def test_relevant_manual_workflows_require_private_identical_media(self):
        cases = {
            "netfx48-baseline-ci.yml": ("48", 1),
            "netfx481-wine-ci.yml": ("481", 3),
        }
        for name, (version, mac_jobs) in cases.items():
            with self.subTest(name=name):
                text = (WORKFLOWS / name).read_text(encoding="utf-8")
                self.assertIn("workflow_dispatch:", text)
                self.assertEqual(
                    text.count("python3 -m scripts.netfx4x_authenticated_media_fetch --version " + version),
                    mac_jobs,
                )
                self.assertIn("build/netfx" + version + ".sha256", text)
                self.assertIn("Get-AuthenticodeSignature", text)
                for block in uploads(text):
                    self.assertIn("retention-days:", block)
                    self.assertNotIn(".exe\\n            build/NDP", block)


if __name__ == "__main__":
    unittest.main()
