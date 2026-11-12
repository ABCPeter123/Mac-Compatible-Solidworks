# Windows OpenGL software rendering on Apple Silicon macOS

**Status:** confirmed for our independent Windows x64 graphics probe, **not** confirmed for SOLIDWORKS installation or CAD functionality.

## Result

[GitHub Actions run 43261277885](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/actions/runs/43261277885) executed our original Windows x64 WGL executable on a GitHub-hosted Apple Silicon macOS 15 runner with Wine 11.21 and Mesa 25.1.9:

- `SWCOMPAT_WGL=PASS`
- `SWCOMPAT_ONSCREEN_OPENGL_FORMATS=128`
- `OPENGL_VENDOR=Mesa`
- `OPENGL_RENDERER=llvmpipe (LLVM 20.1.8, 128 bits)`
- `OPENGL_VERSION=4.5 (Compatibility Profile) Mesa 25.1.9`

Wine successfully created a window, selected and set a pixel format, created and activated an OpenGL context, cleared its color buffer, and swapped buffers. A separate stronger test verifies actual framebuffer pixels using `glReadPixels`; see the newer [software rendering workflow](../.github/workflows/wine-software-opengl.yml).

## Why CPU software rendering?

The official Gcenx macOS Wine bundle used for testing was configured `--without-opengl`. Installing a standalone Windows Mesa `opengl32.dll` and `libgallium_wgl.dll` supplies OpenGL through native Windows DLL interfaces.

The `llvmpipe` Gallium driver executes OpenGL in software instead of requiring Vulkan or Metal graphics features. This avoids the `VK_EXT_robustness2.nullDescriptor` feature gap found with Mesa Zink and MoltenVK in our hosted runners. CPU-based rendering is expected to be slower than hardware acceleration for complex CAD geometry and has not been benchmarked for SOLIDWORKS.

## Runtime source and integrity

| Component | Pinned version | SHA-256 |
| --- | --- | --- |
| Gcenx macOS Wine devel | 11.21, `wine-devel-11.21-osx64.tar.xz` | `9909b486657e10ab66c7279371ae1f990345b596b3b1b3a0cf21f28af24fa0ce` |
| pal1000 Windows Mesa (MinGW) | 25.1.9, `mesa3d-25.1.9-release-mingw.7z` | `5d6cd7fe78c524a534bdfa92bfb437cb914c9d291ab5f4d48185a71f2d8a2210` |

Both are unmodified upstream distributions. Download them directly from their GitHub releases and verify checksums before extraction. No SOLIDWORKS files, Windows images, or proprietary patching are involved.

## Reproducing locally with an available Mac

The source assumes a Python 3.10+ installation, the extracted upstream Wine bundle, a legitimate Mesa release extraction, and the MinGW-compiled `build/wgl_probe.exe` from our CI artifacts.

```sh
# Point to the extracted Wine executable.
export SWCOMPAT_WINE="/path/to/Wine Devel.app/Contents/Resources/wine/bin/wine"
export SWPREFIX="$HOME/Library/Application Support/SWCompat/prefixes/solidworks-lab"

python3 -m swcompat --prefix "$SWPREFIX" init

# Select only the x86-64 Windows Mesa DLLs from the extracted archive.
python3 -m scripts.stage_zink --source "/path/to/mesa-extracted" --prefix "$SWPREFIX"

# Use Mesa CPU rendering instead of the Wine native OpenGL backend.
export WINEDLLOVERRIDES="opengl32,libgallium_wgl,libglapi=n,b"
export GALLIUM_DRIVER=llvmpipe
export MESA_LOADER_DRIVER_OVERRIDE=llvmpipe
export LIBGL_ALWAYS_SOFTWARE=1

python3 -m swcompat --prefix "$SWPREFIX" probe-wgl
```

Use a disposable Wine prefix for testing. The staging script deliberately avoids following links into a shared Wine runtime and preserves existing regular files in `.swcompat-backup` files. It is not a software installation or activation workaround.

For any existing **licensed** Windows `.exe`, you can use the separate launcher rather than exporting graphics settings manually:

```sh
python3 -m scripts.software_launch \
  --wine "$SWCOMPAT_WINE" \
  --prefix "$SWPREFIX" \
  --exe "/path/to/your-program.exe"
```

The launcher checks that the x64 Mesa DLLs are present, then launches using `llvmpipe` and stores Wine logs in the standard SWCompat log directory. Starting a program does **not** demonstrate that it installs, activates, or works correctly. A desktop Mac's GUI activation and performance still require testing.


## Technical milestones

1. Windows x64 process execution: confirmed on hosted macOS.
2. Windowed WGL context creation: confirmed with Mesa `llvmpipe`.
3. Pixel-verified WGL rendering: [test workflow](../.github/workflows/wine-software-opengl.yml).
4. SOLIDWORKS installer and runtime dependency analysis: **not started**.
5. Licensed SOLIDWORKS sketch, extrude, save/reopen, and viewport regression tests: **not started**.

The software rasterizer is a practical fallback for diagnostic progress, not a performance solution for full CAD usage. A Mac test environment with appropriate graphics hardware and legitimate SOLIDWORKS licensing remains necessary for end-to-end validation.
