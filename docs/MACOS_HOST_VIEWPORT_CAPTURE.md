# macOS host compositor visibility, separate from WGL framebuffer readiness

**Question:** Does the original Win32 CAD-style application's 3D OpenGL viewport become visible in an **actual macOS window screenshot**, not merely in the Windows OpenGL back buffer?

The [integrated synthetic CAD experiment](LIVE_CAD_3D_SESSION.md) has already verified selection, geometry widening, zoom, rotation, depth-buffer pixels, saving and independent model reopening on Apple Silicon Wine. That is an internal Windows framebuffer result. It does not establish display composition on macOS.

This new independent host experiment uses [the macOS host-viewport workflow](../.github/workflows/macos-host-viewport-ci.yml):

1. Compile the original Windows x64 CAD fixture on native Windows with MSVC and obtain the same pinned x64 Mesa CPU OpenGL as previous successful tests.
2. On hosted Apple Silicon, create a marked disposable Wine prefix, stage the renderer, run the ordinary complete synthetic CAD workflow, then compile an original Swift AppKit/Quartz host capture helper.
3. The Swift helper first creates a **native AppKit control window** of a known RGB color and attempts to capture that *window only* with the operating system's `screencapture -l` API. It compares a center pixel with the known color. This calibrates availability of actual window capture in the test session.
4. The same Windows executable runs in a dedicated bounded **capture** mode. It completes depth, selection, extrusion, zoom, rotation and saved model validation, flushes a deterministic READY marker, and leaves the final green viewport open for at most 25 seconds while handling the Win32 event loop.
5. A separate Swift host process locates **only** the Wine test window by its exact self-authored title, captures **only that window** using Quartz's window number and `screencapture -l`, and checks a known green center pixel. It does not claim success if the window is undiscoverable, the screen capture API fails or a pixel differs.
6. The Windows application exits, a separate Windows process independently verifies the exact saved model bytes, and the temporary document is removed.

**Privacy:** Both screenshots are created under a unique temporary filename, inspected locally, and deleted immediately. No screenshot, arbitrary Wine output, window catalog or user path is uploaded or printed. CI artifacts and workflow summaries contain only strict finite status enums and a boolean for host screenshot visibility.

## Result interpretation

- `native_control: PASS`, `wine_host_pixels: PASS`, `host_window_visibility_proven: true`: real screenshots verified the expected native AppKit control pixel and the **Wine test window** viewport pixel.
- `native_control: CAPTURE_UNAVAILABLE`: the GitHub runner cannot demonstrate a working macOS window screenshot environment. The result is **not evidence that Wine is broken**.
- `wine_host_pixels: WINDOW_NOT_FOUND`: macOS window enumeration did not expose the exact synthetic test window. This may be a host session or window identification limitation, not necessarily a CAD rendering failure.
- `wine_host_pixels: PIXEL_MISMATCH`: a captured Wine window center pixel did not match the expected rendered color. Investigate compositor, capture scaling, window geometry and window occlusion before attributing the cause.
- `wine_host_pixels: CAPTURE_UNAVAILABLE`: even with a window number, screenshot capture was not available or returned no decoded image. This is **unverified**, not automatically a rendering failure.
- `windows_3d_session: PASS`, `independent_model_reopen: PASS` with `host_window_visibility_proven: false`: internal Windows rendering and state persistence work, but **host window presentation is still not demonstrated**.

A default GitHub Actions run is diagnostic: it requires the Windows CAD application and saved model roundtrip, but reports unavailable host screenshot evidence honestly. A manual workflow dispatch with `require_macos_window_pixels=true` fails unless both native and Wine host screenshot pixels are verified.

This experiment uses only original synthetic Windows C code, original Swift host code, pinned open-source Wine and Mesa. It does **not** use or establish compatibility of proprietary SOLIDWORKS binaries, installed Microsoft .NET Framework, licensed activation, physical Mac mouse/keyboard input, native SLDPRT files, full-screen accessibility or performance. A physical Mac with an interactive desktop may be required to meaningfully test on-screen presentation when the hosted CI desktop cannot be captured.
