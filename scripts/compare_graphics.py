"""Compare Wine WGL and native macOS CGL results without inventing a root cause."""
from __future__ import annotations

import argparse
import json
from pathlib import Path


def markers(content: str) -> dict[str, str]:
    result = {}
    for line in content.splitlines():
        if line.startswith(("SWCOMPAT_", "OPENGL_")) and "=" in line:
            key, value = line.split("=", 1)
            result[key] = value.strip()
    return result


def interpret(cgl: dict[str, str], wgl: dict[str, str]) -> str:
    host = cgl.get("SWCOMPAT_CGL")
    guest = wgl.get("SWCOMPAT_WGL")
    if host is None and guest is None:
        return "No native OpenGL or Wine graphics probes ran."
    if guest == "PASS":
        return "The basic Wine WGL test succeeded. SOLIDWORKS is still untested."
    if guest != "FAIL":
        return "Wine graphics probe did not return a definite result."
    if host == "UNAVAILABLE":
        return ("Native macOS CGL context creation also failed. Host graphics availability "
                "is a plausible blocker; a physical or GPU-capable Mac is needed to separate causes.")
    if host == "PASS" and wgl.get("SWCOMPAT_PIXELFORMAT_COUNT") == "0":
        return ("Native macOS CGL succeeded, but Wine advertised no WGL formats. "
                "Investigate Wine winemac.drv pixel-format initialization.")
    if host == "PASS":
        return ("Native macOS OpenGL works, while Wine WGL failed. "
                "Investigate Wine's WGL driver and selection criteria.")
    return ("WGL failed and the native OpenGL capability is unknown. "
            "Do not assume a graphics driver bug or hardware limitation.")


def report(cgl_text: str, wgl_text: str) -> dict:
    cgl, wgl = markers(cgl_text), markers(wgl_text)
    return {
        "native_cgl": cgl.get("SWCOMPAT_CGL", "NOT_RUN"),
        "wine_wgl": wgl.get("SWCOMPAT_WGL", "NOT_RUN"),
        "wine_pixel_formats": wgl.get("SWCOMPAT_PIXELFORMAT_COUNT", "UNKNOWN"),
        "wine_failure_stage": wgl.get("SWCOMPAT_STAGE", "UNKNOWN"),
        "wine_window_valid": wgl.get("SWCOMPAT_WINDOW_VALID", "UNKNOWN"),
        "native_renderer": cgl.get("SWCOMPAT_CGL_RENDERER", "UNKNOWN"),
        "wine_renderer": wgl.get("OPENGL_RENDERER", "UNKNOWN"),
        "assessment": interpret(cgl, wgl),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cgl", type=Path, default=Path("build/cgl-probe.txt"))
    parser.add_argument("--logs", type=Path, default=Path("build/logs"))
    parser.add_argument("--output", type=Path, default=Path("build/graphics-comparison.json"))
    parser.add_argument("--summary", type=Path)
    args = parser.parse_args()
    native = args.cgl.read_text(encoding="utf-8", errors="replace") if args.cgl.exists() else ""
    logs = sorted(args.logs.glob("*-wgl-*.log")) if args.logs.exists() else []
    guest = logs[-1].read_text(encoding="utf-8", errors="replace") if logs else ""
    finding = report(native, guest)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(finding, indent=2) + "\n", encoding="utf-8")
    body = ("## Graphics compatibility analysis\n\n"
            f"- Native CGL: **{finding['native_cgl']}**\n"
            f"- Wine WGL: **{finding['wine_wgl']}**\n"
            f"- Wine pixel-format count: `{finding['wine_pixel_formats']}`\n"
            f"- Failure stage: `{finding['wine_failure_stage']}`\n\n"
            f"{finding['assessment']}\n\n"
            "This does not test SOLIDWORKS installation or activation.\n")
    print(body)
    if args.summary:
        with args.summary.open("a", encoding="utf-8") as target:
            target.write(body + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
