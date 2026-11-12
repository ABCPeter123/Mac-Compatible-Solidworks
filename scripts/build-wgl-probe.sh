#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
CC=${CC:-x86_64-w64-mingw32-gcc}
command -v "$CC" >/dev/null 2>&1 || { echo "Missing MinGW-w64 cross compiler: $CC" >&2; exit 2; }
mkdir -p "$ROOT/build"
"$CC" -std=c11 -O2 -Wall -Wextra "$ROOT/probes/wgl_probe.c" -o "$ROOT/build/wgl_probe.exe" -lopengl32 -lgdi32 -luser32
"$CC" -std=c11 -O2 -Wall -Wextra "$ROOT/probes/wgl_bitmap_probe.c" -o "$ROOT/build/wgl_bitmap_probe.exe" -lopengl32 -lgdi32 -luser32
"$CC" -std=c11 -O2 -Wall -Wextra -DSWCOMPAT_VERIFY_PIXEL=1 "$ROOT/probes/wgl_probe.c" -o "$ROOT/build/wgl_pixel_probe.exe" -lopengl32 -lgdi32 -luser32
"$CC" -std=c11 -O2 -Wall -Wextra "$ROOT/probes/cad_geometry_probe.c" -o "$ROOT/build/cad_geometry_probe.exe" -lopengl32 -lgdi32 -luser32
"$CC" -std=c11 -O2 -Wall -Wextra "$ROOT/probes/win_gui_session_probe.c" -o "$ROOT/build/win_gui_session_probe.exe" -lopengl32 -lgdi32 -luser32
echo "Built WGL, bitmap, pixel-readback, 3D geometry and event-driven GUI probes"
