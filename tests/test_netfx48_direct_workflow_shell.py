"""Guard the manual signed .NET 4.8 experiment against broken Bash continuations.

This test does not launch Microsoft binaries or require Wine.
"""
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "netfx40-legacy-ci.yml"


class OriginalNetfx48ShellTests(unittest.TestCase):
    def test_original_setup_flags_remain_in_one_shell_command(self):
        source = WORKFLOW.read_text(encoding="utf-8")
        marker = "python3 -m scripts.netfx40_to_48_direct"
        self.assertEqual(source.count(marker), 1)
        command = source.split(marker, 1)[1].split(
            "\n      - name:", 1
        )[0]
        expected = (
            "--wine", "--prefix", "--installer", "--sha256-file",
            "--launcher", "--service-fixture", "--setup-profile",
            "--loader", "--managed",
            "--native40-report", "--output", "--agree-disposable-prefix",
        )
        lines = [line.strip() for line in command.splitlines() if line.strip()]
        for flag in expected:
            self.assertEqual(sum(line.startswith(flag + " ") or line == flag
                                 for line in lines), 1, flag)
        for line in lines[:-1]:
            self.assertTrue(line.endswith("\\"), f"Missing continuation: {line}")
            self.assertFalse(line.endswith("\\ \\"), f"Malformed continuation: {line}")
        self.assertEqual(lines[-1], "--agree-disposable-prefix")


if __name__ == "__main__":
    unittest.main()
