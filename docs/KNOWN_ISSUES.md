# Observed compatibility results

Updated 2026-11-12. Results here refer to **our independent test executable**, not SOLIDWORKS.

## Confirmed, Intel GitHub-hosted macOS

Experiment [initial run](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/actions/runs/43239479218) and [isolated call run](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/actions/runs/43240516020):

| Step | Result |
| --- | --- |
| Wine devel 11.21 binary started | PASS |
| Create isolated Win64 Wine prefix | PASS |
| Run Windows `cmd.exe /c ver` | PASS |
| Create Win32 test window and obtain device context | PASS |
| `IsWindow(hwnd)` on test window | 1 (valid) |
| `ChoosePixelFormat(hdc, ...)` | Returns 0 |
| `GetLastError()` after `ChoosePixelFormat` | 0 |
| OpenGL context creation | NOT REACHED |

The first probe mislabeled the failure as `SetPixelFormat` because it checked `ChoosePixelFormat` and `SetPixelFormat` together. The updated probe establishes that **format selection itself** fails.

**Do not interpret the original 1400 result as the root cause.** It was produced by the original combined error check.

## Native host OpenGL results

Both Intel and Apple Silicon cloud runners independently created native OpenGL contexts using Apple's software renderer:

- `SWCOMPAT_CGL=PASS`
- `SWCOMPAT_CGL_RENDERER=Apple Software Renderer`
- `SWCOMPAT_CGL_VERSION=2.1 APPLE-21.1.1`
- Wine 11.21 reported `SWCOMPAT_PIXELFORMAT_COUNT=12` on both.
- The first Wine format has descriptor flags `0x78`, identifying it as bitmap-capable, GDI-compatible, OpenGL-capable, and generic, **without** the required window-drawing flag.
- All five tested WGL selection criteria returned `0`.

This rules out a complete absence of host OpenGL. It does **not** prove that the hosted graphics system offers any onscreen OpenGL formats. The enumeration of all 12 formats is designed to distinguish those cases.

We are also testing offscreen bitmap rendering under Wine. Even if that succeeds, it will not establish an interactive SOLIDWORKS viewport.

Evidence: [experiment 43242045116](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/actions/runs/43242045116).

## Diagnostics added in follow-up

- `DescribePixelFormat` reports how many WGL formats Wine exposes.
- The Windows probe tries multiple color/depth/double-buffer requirements.
- A native macOS `CGLChoosePixelFormat` probe checks whether the *host itself* can create an OpenGL context, independent of Wine.
- Both the Intel and Apple Silicon hosted workflows collect Metal, CGL, and WGL results separately.
- `scripts/compare_graphics.py` produces a comparison report. It explicitly marks the root cause as unknown if the evidence is inconclusive.

The potential causes include Wine's macOS pixel-format enumeration and headless or virtualized runner graphics limits. Neither is confirmed yet. A green CI badge for Python tests or a native Metal device does not imply Windows OpenGL support.

## Next technical decision

1. If CGL is unavailable on a hosted runner, prioritize a GPU-capable interactive Mac test environment before changing Wine internals.
2. If CGL works but Wine exposes zero formats, instrument `winemac.drv` pixel-format initialization.
3. If Wine exposes formats but fails selection, compare descriptor flags and supported capabilities.
4. After an actual WGL context works, test OpenGL rendering and only then investigate licensed SOLIDWORKS installation.

## Boundaries

No proprietary SOLIDWORKS files, Windows images, activation keys, or activation bypasses are required for these probes. This is an interoperability research project; no complete SOLIDWORKS compatibility has been achieved.
