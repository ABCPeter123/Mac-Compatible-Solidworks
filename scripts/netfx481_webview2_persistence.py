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
from scripts.netfx481_webview2_restart_gate import operational, live_ready
from scripts.webview2_runtime_trial import probe, snapshot, wine_environment
from scripts.webview2_render_gate import load_report


def classify(initial: dict, restart: dict, live: dict) -> dict:
    before = operational(initial, restart)
    return {"schema": 1, "initial_install_verified": evaluate(initial)["ready"],
            "initial_operational_verified": before,
            "live": snapshot(live),
            "persistent_controller": before and live_ready(live),
            "solidworks_compatibility": "NOT_DEMONSTRATED"}


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    for key in ("wine", "prefix", "probe", "initial", "restart", "output"):
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
    restart = load_report(a.restart)
    if not operational(initial, restart):
        raise ValueError("Original browser operational restart was not verified")
    env = wine_environment(a.prefix)
    env.pop("WINEDLLOVERRIDES", None)
    live = probe(a.wine.resolve(strict=True), a.probe.resolve(strict=True), env)
    result = classify(initial, restart, live)
    a.output.write_text(json.dumps(result, sort_keys=True) + "\n", encoding="ascii")
    print("WebView2 post-CLR persistence " + json.dumps(result, sort_keys=True))
    return 0 if result["persistent_controller"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
