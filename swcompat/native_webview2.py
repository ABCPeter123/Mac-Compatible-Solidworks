"""Functional Microsoft WebView2 preparation in a persistent local Wine prefix.

The existing independent Windows x64 controller probe confirms real COM
browser-controller creation, not merely files or registry entries. The
original Microsoft runtime is provided by the user, SHA-256-verified locally,
and must come from an authorized official source. Authenticode publisher
validation is NOT performed by this local macOS script.
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import time

from scripts.webview2_runtime_trial import (
    probe as controller_probe,
    run_installer as run_microsoft_installer,
    verify_installer as verify_microsoft_installer,
    wine_environment,
)
from swcompat.native_install import initialize_prefix, validate_prefix


def ready(snapshot: dict) -> bool:
    return (
        snapshot.get("probe_result") == "COMPLETE"
        and snapshot.get("runtime_discovery") == "VERSION_FOUND"
        and snapshot.get("environment_creation") == "READY"
        and snapshot.get("controller_creation") == "READY"
        and snapshot.get("controller_created") is True
    )


def validate_controller(probe: Path) -> None:
    if (probe.is_symlink() or not probe.is_file()
            or probe.name.casefold() != "webview2_controller_probe.exe"
            or not (probe.parent / "WebView2Loader.dll").is_file()):
        raise ValueError("WebView2 controller executable or official loader not found")


def check_webview2(wine: Path, prefix: Path, controller: Path, *, run_probe=controller_probe) -> bool:
    """Execute independent Windows x64 controller in exactly this Wine prefix."""
    validate_prefix(prefix)
    validate_controller(controller)
    observed = run_probe(wine, controller, wine_environment(prefix), timeout_seconds=75)
    return ready(observed)


def prepare_webview2(
    wine: Path, prefix: Path, logs: Path, installer: Path, sha256_file: Path,
    controller: Path, *, run_probe=controller_probe,
    installer_runner=run_microsoft_installer, pause=time.sleep,
) -> dict:
    """Install official runtime only when independent browser controller is absent.

    Called with an explicit user request, in their selected persistent prefix.
    Nothing is downloaded automatically, no prefix is erased or reset.
    """
    if os.name == "nt":
        raise ValueError("Native Windows execution not permitted in this local Wine helper")
    if prefix.is_symlink() or controller.is_symlink() or installer.is_symlink() or sha256_file.is_symlink():
        raise ValueError("Symbolic links are not accepted for executable inputs")
    validate_controller(controller)
    if not wine.is_file() or not os.access(wine, os.X_OK):
        raise ValueError("Wine runtime not executable")
    verify_microsoft_installer(installer, sha256_file)
    prefix_status = initialize_prefix(wine, prefix, logs)
    env = wine_environment(prefix)
    before = run_probe(wine, controller, env, timeout_seconds=75)
    if ready(before):
        status, exit_code = "ALREADY_READY", None
        after = before
    else:
        termination, exit_code = installer_runner(wine, installer, env, 240)
        if termination == "EXIT_ZERO":
            pause(5)
        after = run_probe(wine, controller, env, timeout_seconds=75)
        status = ("READY" if termination == "EXIT_ZERO" and ready(after)
                  else "WEBVIEW2_NOT_READY")
    result = {
        "schema": 1,
        "scope": "LOCAL_MACOS_PERSISTENT_WINE_WEBVIEW2",
        "installer_digest": "SHA256_VERIFIED",
        "installer_authenticode": "NOT_VERIFIED_LOCALLY",
        "prefix_state": prefix_status,
        "before_controller": "READY" if ready(before) else "NOT_READY",
        "installer_execution": ("NOT_NEEDED" if status == "ALREADY_READY" else termination),
        "after_controller": "READY" if ready(after) else "NOT_READY",
        "result": status,
        "solidworks_installation": "NOT_VERIFIED",
    }
    logs.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    output = logs / ("native-webview2-" + stamp + "-" + str(os.getpid()) + ".json")
    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2)
        stream.write("\n")
    return result
