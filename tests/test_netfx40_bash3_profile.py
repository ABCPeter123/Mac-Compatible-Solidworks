"""Guard against macOS Bash 3.2 nounset aborting CLR4 installer experiments."""
from pathlib import Path
import unittest

WORKFLOW = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "netfx40-legacy-ci.yml"


class OriginalClr4MacosBashTests(unittest.TestCase):
    def test_optional_win7_flag_uses_safe_positional_arguments(self):
        source = WORKFLOW.read_text(encoding="utf-8")
        start = source.index("      - name: Retry genuine original Microsoft .NET 4.0 following msxml3")
        end = source.index("      - name: Restart isolated Wine", start)
        step = source[start:end]
        self.assertIn("set -euo pipefail", step)
        self.assertIn("set -- python3 -m scripts.netfx40_legacy", step)
        self.assertIn('set -- "$@" --experiment-win7-setup', step)
        self.assertIn('          "$@"', step)
        self.assertIn("--experiment-private-original-action", step)
        self.assertNotIn("SETUP_PROFILE_ARGS", step)
        self.assertNotIn('''"${SETUP_PROFILE_ARGS[@]}"''', step)


if __name__ == "__main__":
    unittest.main()
