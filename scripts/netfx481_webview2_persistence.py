"""Re-probe a previously authenticated browser after native CLR servicing.

Separate persistence evidence from the original setup transaction. Never
convert a failed installer into a successful one or reinstall the runtime.
"""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
from scripts.netfx481_trial import validate_prefix
from scripts.solidworks_runtime_gate import evaluate
from scripts.webview2_runtime_trial import probe, snapshot, wine_environment
from scripts.webview2_render_gate import load_report


def classify(initial: dict, live: dict) -> dict:
    before = evaluate(initial)["ready"]
    after = (live.get("probe_result") == "COMPLETE"
             and live.get("runtime_discovery") == "VERSION_FOUND"
             and live.get("environment_creation") == "READY"
             and live.get("controller_creation") == "READY"
             and live.get("controller_created") is True)
    return {"schema": 1, "initial_install_verified": before,
            "live": snapshot(live),
            "persistent_controller": before and after,
            "solidworks_compatibility": "NOT_DEMONSTRATED"}


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    for key in ("wine", "prefix", "probe", "initial", "output"):
        p.add_argument("--" + key, required=True, type=Path)
    a = p.parse_args()
    validate_prefix(a.prefix)
    runner = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
    if (os.name == "nt" or a.prefix.is_symlink()
            or a.prefix.resolve() != runner / "netfx40-msxml3-prefix"
            or not (a.prefix / ".swcompat-webview2-disposable").is_file()
            or a.probe.is_symlink() or not a.probe.is_file()
            or a.probe.name != "webview2_controller_probe.exe"
            or a.output.exists() or a.output.is_symlink()
            or a.output.resolve().is_relative_to(a.prefix.resolve())):
        raise ValueError("Unexpected isolated browser persistence inputs")
    initial = load_report(a.initial)
    if not evaluate(initial)["ready"]:
        raise ValueError("Original setup transaction was not verified")
    env = wine_environment(a.prefix)
    env.pop("WINEDLLOVERRIDES", None)
    live = probe(a.wine.resolve(strict=True), a.probe.resolve(strict=True), env)
    result = classify(initial, live)
    a.output.write_text(json.dumps(result, sort_keys=True) + "\n", encoding="ascii")
    print("WebView2 post-CLR persistence " + json.dumps(result, sort_keys=True))
    return 0 if result["persistent_controller"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
