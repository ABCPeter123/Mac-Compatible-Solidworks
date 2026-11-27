"""Run the existing synthetic browser render control in the verified IPD prefix.

No private installer, user navigation, browser security flags, or screenshot
artifacts. Classify the same public DOM/Canvas/layout/GDI proof as the older
independent WebView2 workflow, without inventing pixel evidence.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile

from scripts.netfx481_trial import validate_prefix
from scripts.solidworks_runtime_gate import evaluate
from scripts import webview2_render_report as render
from scripts import webview2_canvas_report as canvas
from scripts import webview2_layout_report as layout
from scripts import webview2_gdi_report as gdi
from scripts.webview2_render_gate import classify, load_report


def measure(log: str, exit_code: int, screenshot: bytes | None, runtime: dict) -> dict:
    return classify(runtime, render.summarize(log, exit_code, screenshot),
                    gdi.summarize(log), canvas.summarize(log), layout.summarize(log))


def run(wine: Path, prefix: Path, probe: Path, runtime: dict) -> dict:
    validate_prefix(prefix)
    root = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
    if (os.name == "nt" or prefix.is_symlink()
            or prefix.resolve() != root / "netfx40-msxml3-prefix"
            or wine.is_symlink() or not wine.is_file() or not os.access(wine, os.X_OK)
            or probe.is_symlink() or not probe.is_file()
            or probe.name != "webview2_render_probe.exe"
            or probe.resolve().is_relative_to(prefix.resolve())
            or not (prefix / ".swcompat-webview2-disposable").is_file()
            or not evaluate(runtime)["ready"]):
        raise ValueError("Verified same-prefix browser control inputs required")
    loader = probe.parent / "WebView2Loader.dll"
    if loader.is_symlink() or not loader.is_file():
        raise ValueError("Pinned SDK loader required")
    # The existing probe emits a fixed PNG name in its current directory.
    # Isolate it from all workflow artifacts, and remove it even on failure.
    env = os.environ.copy()
    env.pop("WINEDLLOVERRIDES", None)
    env.pop("WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS", None)
    env.update(WINEPREFIX=str(prefix.resolve()), WINEARCH="win64", WINEDEBUG="-all")
    with tempfile.TemporaryDirectory(prefix="swcompat-ipd-webview-") as directory:
        scratch = Path(directory)
        with tempfile.TemporaryFile() as output:
            try:
                result = subprocess.run([str(wine.resolve()), str(probe.resolve())],
                                        cwd=scratch, env=env, stdin=subprocess.DEVNULL,
                                        stdout=output, stderr=subprocess.STDOUT,
                                        timeout=240, check=False)
                code = result.returncode
            except (OSError, subprocess.TimeoutExpired):
                # Incomplete output can never establish a completed browser test.
                code = 124
            output.seek(0)
            raw = output.read(render.MAX_LOG_BYTES + 1)
        if len(raw) > render.MAX_LOG_BYTES:
            raw = b""
        png = scratch / "swcompat-webview2-preview.png"
        screenshot = None
        if not png.is_symlink() and png.is_file():
            with png.open("rb") as stream:
                screenshot = stream.read(render.MAX_PNG_BYTES + 1)
        result = measure(raw.decode("utf-8-sig", errors="replace"), code, screenshot, runtime)
        # Do not let a timed-out process accidentally meet the known capture
        # blocker exception using partial markers. No onward licensed launch.
        if code == 124:
            result = measure("", code, None, runtime)
        return result


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    for key in ("wine", "prefix", "probe", "runtime", "output"):
        p.add_argument("--" + key, required=True, type=Path)
    a = p.parse_args()
    if (a.output.exists() or a.output.is_symlink()
            or a.output.resolve().is_relative_to(a.prefix.resolve())):
        raise ValueError("Fresh external report required")
    result = run(a.wine, a.prefix, a.probe, load_report(a.runtime))
    a.output.parent.mkdir(parents=True, exist_ok=True)
    a.output.write_text(json.dumps(result, sort_keys=True) + "\n", encoding="ascii")
    print("Same-prefix WebView2 rendering " + json.dumps(result, sort_keys=True))
    # The existing explicitly known capture blocker is diagnostic only.
    return 0 if result["diagnostic_complete"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
