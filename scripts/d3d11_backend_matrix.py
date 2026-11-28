"""Bounded backend-specific tests with independent Wine sessions."""
import argparse
import os
from pathlib import Path
import re
import subprocess
import tempfile
from scripts.netfx40_legacy import _terminate_private_setup_wineserver
from scripts.netfx481_trial import wineboot_restart

MARKER = re.compile(r"SWCOMPAT_D3D_(?:HARDWARE|WARP|DWM|DCOMP)_(?:CREATE|TARGET|STAGING|MAP|PRESENT|DEVICE_REMOVED|QUERY|LOAD|HARDWARE|WARP|DXGI_DEVICE|VISUAL|FACTORY|SWAPCHAIN|CONTENT|ROOT|RENDER_TARGET|COMMIT)=[0-9A-F]{8}|SWCOMPAT_D3D_(?:HARDWARE|WARP|DCOMP)_(?:TEXTURE|WINDOW)=(?:MATCH|NOT_VERIFIED|NO_MATCH|API_FAILED)|SWCOMPAT_D3D_DWM_ENABLED=(?:YES|NO|UNKNOWN)|SWCOMPAT_D3D_PROBE=COMPLETE")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--profiles", nargs="+", choices=("default", "gl", "vulkan"), required=True)
    args = parser.parse_args()
    wine = Path(os.environ["SWCOMPAT_WINE"])
    prefix = Path(os.environ["RUNNER_TEMP"]).resolve() / "netfx40-msxml3-prefix"
    all_complete = True
    for profile in args.profiles:
        if not _terminate_private_setup_wineserver(wine, prefix):
            raise ValueError("Unable to quiesce isolated graphics prefix")
        if wineboot_restart(wine, prefix) != "COMPLETED":
            raise ValueError("Unable to restart isolated graphics prefix")
        env = dict(os.environ, WINEPREFIX=str(prefix), WINEARCH="win64", WINEDEBUG="-all,err+winediag,err+wined3d,err+vulkan")
        env.pop("WINE_D3D_CONFIG", None)
        if profile != "default":
            env["WINE_D3D_CONFIG"] = "renderer=" + profile
        with tempfile.TemporaryFile() as log:
            try:
                p = subprocess.run([str(wine), str(Path("build/d3d11_present_probe.exe").resolve())], env=env, stdout=log, stderr=subprocess.STDOUT, timeout=90, check=False)
                rc = p.returncode
            except subprocess.TimeoutExpired:
                rc = 124
            log.seek(0)
            raw = log.read(65537)
        safe = [line for line in raw.decode("ascii", "replace").splitlines() if MARKER.fullmatch(line)] if len(raw) <= 65536 else []
        decoded = raw.decode("ascii", "replace") if len(raw) <= 65536 else ""
        print("Graphics profile:", profile, "exit:", rc)
        print("Wine renderer selection:", "VULKAN" if "Using the Vulkan renderer." in decoded else "OPENGL" if "Using the OpenGL renderer." in decoded else "NOT_OBSERVED")
        print("\n".join(safe))
        Path("build/d3d11-present-" + profile + "-sanitized.txt").write_text("\n".join(safe)+"\n", encoding="ascii")
        complete = (rc == 0 and safe.count("SWCOMPAT_D3D_PROBE=COMPLETE") == 1
                    and all(any(x.startswith("SWCOMPAT_D3D_"+driver+"_CREATE=") for x in safe) for driver in ("HARDWARE", "WARP"))
                    and any(x.startswith("SWCOMPAT_D3D_DCOMP_LOAD=") for x in safe))
        all_complete = all_complete and complete
    if not _terminate_private_setup_wineserver(wine, prefix):
        raise ValueError("Final session cleanup failed")
    return 0 if all_complete else 1

if __name__ == "__main__":
    raise SystemExit(main())
