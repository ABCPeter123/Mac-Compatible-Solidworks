"""Operational browser recovery after authenticated setup, never installer success.

Only a zero exit or the observed timeout with a real controller is eligible.
All Wine processes in the exact disposable prefix must be reaped, Wine must
restart successfully, and a new independent controller must be created.
The original signed installer result is never rewritten.
"""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
from scripts.netfx40_legacy import _terminate_private_setup_wineserver
from scripts.netfx481_trial import validate_prefix, wineboot_restart
from scripts.solidworks_runtime_gate import evaluate
from scripts.webview2_runtime_trial import probe, snapshot, wine_environment
from scripts.webview2_render_gate import load_report


def live_ready(value: object) -> bool:
    return (isinstance(value, dict)
            and value.get("probe_result") == "COMPLETE"
            and value.get("runtime_discovery") == "VERSION_FOUND"
            and value.get("environment_creation") == "READY"
            and value.get("controller_creation") == "READY"
            and value.get("controller_created") is True
            and value.get("environment_hresult") == "0X00000000"
            and value.get("controller_hresult") == "0X00000000")


def eligible(initial: dict) -> bool:
    strict = evaluate(initial)["ready"]
    before = initial.get("before")
    after = initial.get("after")
    return (initial.get("installer_sha256_verified") is True
            and initial.get("controller_transition") == "BECAME_READY"
            and initial.get("browser_controller_confirmed") is True
            and isinstance(before, dict)
            and before.get("probe_result") == "COMPLETE"
            and before.get("runtime_discovery") == "NOT_DISCOVERED"
            and live_ready(after)
            and ((strict and type(initial.get("installer_exit_code")) is int
                  and initial["installer_exit_code"] == 0)
                 or (initial.get("installer_execution") == "TIMEOUT"
                     and initial.get("installer_exit_code") is None
                     and initial.get("runtime_installation_confirmed") is False)))


def operational(initial: dict, restart: dict) -> bool:
    return (eligible(initial)
            and isinstance(restart, dict)
            and restart.get("schema") == 1
            and restart.get("setup_termination") == initial.get("installer_execution")
            and restart.get("installer_transaction_confirmed") is evaluate(initial)["ready"]
            and restart.get("session_quiesced") is True
            and restart.get("restart") == "COMPLETED"
            and live_ready(restart.get("live"))
            and restart.get("operational_ready") is True
            and restart.get("solidworks_compatibility") == "NOT_DEMONSTRATED")


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    for key in ("wine", "prefix", "probe", "initial", "output"):
        p.add_argument("--" + key, required=True, type=Path)
    a = p.parse_args()
    validate_prefix(a.prefix)
    root = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
    if (os.name == "nt" or a.prefix.is_symlink()
            or a.prefix.resolve() != root / "netfx40-msxml3-prefix"
            or not (a.prefix / ".swcompat-webview2-disposable").is_file()
            or a.probe.is_symlink() or not a.probe.is_file()
            or a.probe.name != "webview2_controller_probe.exe"
            or a.output.exists() or a.output.is_symlink()
            or a.output.resolve().is_relative_to(a.prefix.resolve())):
        raise ValueError("Unexpected isolated browser restart inputs")
    initial = load_report(a.initial)
    result = {"schema": 1, "setup_termination": initial.get("installer_execution"),
              "installer_transaction_confirmed": evaluate(initial)["ready"],
              "session_quiesced": False, "restart": "NOT_RUN", "live": None,
              "operational_ready": False, "solidworks_compatibility": "NOT_DEMONSTRATED"}
    if eligible(initial):
        wine = a.wine
        prefix = a.prefix.resolve(strict=True)
        result["session_quiesced"] = _terminate_private_setup_wineserver(wine, prefix)
        if result["session_quiesced"]:
            result["restart"] = wineboot_restart(wine, prefix, timeout=120)
            if result["restart"] == "COMPLETED":
                env = wine_environment(prefix)
                env.pop("WINEDLLOVERRIDES", None)
                result["live"] = snapshot(probe(wine, a.probe.resolve(strict=True), env))
                result["operational_ready"] = live_ready(result["live"])
    a.output.write_text(json.dumps(result, sort_keys=True) + "\n", encoding="ascii")
    print("WebView2 clean restart " + json.dumps(result, sort_keys=True))
    return 0 if operational(initial, result) else 1


if __name__ == "__main__":
    raise SystemExit(main())
