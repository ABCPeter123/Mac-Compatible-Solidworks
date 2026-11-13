# Verify actual WebView2 HTML, DOM and pixel rendering

WebView2 *runtime discovery* and *controller creation* are distinct from page loading and visible rendering. This experiment adds a stricter gate to [the genuine Microsoft-signed Evergreen Runtime trial](WEBVIEW2_RUNTIME_INSTALL.md).

## Test implementation

The original Windows x64 C++ source [webview2_render_probe.cpp](../probes/webview2_render_probe.cpp) uses Microsoft.Web.WebView2 SDK 1.0.4314.35, builds with MSVC on the hosted Windows reference, and calls the real WebView2 COM APIs. All content is generated inside the probe itself. No remote URLs, external scripts, fonts, images, or end-user browser content are used.

The test:

1. Creates a visible Win32 top-level window and an STA COM apartment with a message loop.
2. Loads the authenticated Microsoft WebView2Loader.dll and creates a genuine browser environment and controller.
3. Navigates via NavigateToString to a self-contained HTML document with a blue background and a centered green rectangle.
4. Waits for NavigationCompleted to confirm navigation succeeded.
5. Calls ExecuteScript and checks an exact JSON-encoded result derived from the actual DOM, element text, document data attribute, and computed CSS.
6. Attempts WebView2 CapturePreview. If its callback fails or times out, independently requests a PNG using Chromium's documented Page.captureScreenshot DevTools protocol and decodes only the base64 image field. The report keeps the screenshot source distinct; it does not claim CapturePreview succeeded when the fallback is used.
7. Verifies the PNG with Python standard-library zlib and CRC checking, including exact dimensions, valid scanline filters and actual RGB colors at two separated positions.

The synthetic background is RGB (19, 83, 147) and the rectangle is RGB (29, 205, 91). The validator tolerates small pixel-color variations. A blank, corrupted, swapped-color, or wrong-color screenshot is **not** a pass. For safety, image files and raw process logs are **not uploaded**; only bounded and fixed-schema JSON results are retained as GitHub Actions artifacts.

## Cloud verification

The [WebView2 Evergreen workflow](../.github/workflows/webview2-runtime-install-ci.yml) builds the controller and rendering executables using the authenticated Microsoft SDK and x64 loader. It checks actual local HTML, JavaScript DOM access and preview pixels on:

- Native Windows Server 2025 as a strict reference.
- Apple Silicon macOS 15 with Wine 11.21 after verified Microsoft Evergreen standalone Runtime installation in an isolated prefix.

The workflow separately continues to report the previously verified *negative* Linux Wine installer result. Linux rendering is not claimed when the browser runtime is absent.

Initial Apple Silicon CI [run 43352756493](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/actions/runs/43352756493) reached a genuine Chromium page but WebView2 CapturePreview timed out. That means browser controller creation and DOM execution are not sufficient to prove the preview API or actual pixels work. The independent CDP screenshot fallback tests whether the Chromium page image can be captured even though Wine's WebView2 CapturePreview completion callback did not fire.

The next verified Apple Silicon attempt ([run 43354162956](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/actions/runs/43354162956)) also timed out at the independent Chromium DevTools Page.captureScreenshot callback. Both screenshot APIs failed to complete in the default hosted Wine/Chromium graphics configuration, although the DOM test had already returned the expected result. **No macOS framebuffer-pixel success has yet been demonstrated.**

The next diagnostic sets the documented WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS override to disable GPU acceleration, GPU compositing and Vulkan for the synthetic browser only. These are test-only rendering flags, not a production recommendation. They do not disable browser security protections or affect SOLIDWORKS binaries.

A completed controller test is not interchangeable with a successful local HTML/DOM/pixel test. Native and macOS rendering test steps must **fail CI** if the DOM marker, CapturePreview call, PNG decode or either pixel sample fails.

## Independent Win32 GDI readback experiment, issue #26

The current [render probe](../probes/webview2_render_probe.cpp) now samples two fixed synthetic-page pixels **before** calling either browser screenshot API. It uses Win32 GDI `BitBlt` to read the HWND's client device context and separately the desktop device context at the transformed client coordinates. Each method samples the blue background at (48, 32) and green central rectangle at (240, 160) within the 480-by-320 browser surface. It compares actual RGB values against the expected colors with a small per-channel tolerance.

GDI observations have their own bounded markers, `SWCOMPAT_WV2_GDI_CLIENT` and `SWCOMPAT_WV2_GDI_DESKTOP`, each classified as `PIXELS_MATCH`, `NO_MATCH` or `API_FAILED`. The independent privacy-preserving [GDI reporter](../scripts/webview2_gdi_report.py) accepts only those exact states and verifies all markers are present once. The GDI report runs even if the later `CapturePreview` or Chromium DevTools call times out, since that later failure should not erase prior readback observations.

A `PIXELS_MATCH` proves two matching readbacks from that GDI device context, **not** that the WebView2 browser screenshot API works. A `NO_MATCH` does **not** prove there is no browser rendering: Chromium may use a DirectComposition/Metal surface that Win32 GDI cannot read, especially on an unattended hosted Mac. Both methods can be unavailable on a headless runner.

Neither GDI method copies user data, loads an external page, or exports a screenshot. Raw logs and pixel bytes remain unuploaded. The CI artifact contains only a fixed-schema JSON outcome. This is a separate diagnostic and **does not turn red browser screenshot CI green** when screenshot proof remains absent.

Tracked in [issue #26](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/issues/26).

## Outcome classification

The sanitized reporter scripts/webview2_render_report.py accepts only the original probe's exact markers and a bounded PNG. It reports navigation and DOM outcomes only when the original probe completed successfully, and reports screenshot rendering as PASS only when the two expected color regions actually appear in the decoded PNG. Failures expose only a fixed stage label such as NAVIGATION_CALLBACK, SCRIPT_DOM or PREVIEW_CALLBACK; they cannot leak the raw log or user's filesystem paths.

The test does not verify hyperlinks, online web requests, user clicks, keyboard focus, WebView2 browser security under production load, or WebView2 integration inside the real SOLIDWORKS application. It cannot establish that a licensed SOLIDWORKS installer will run or that CAD geometry is usable.

## Next integration gate

Once a synthetic page renders on Apple Silicon Wine, test input and browser events within an isolated WebView2 controller, then reproduce a legitimate SOLIDWORKS installer failure using local media and the existing installer preflight/log triage scripts. Preserve original software activation and licensing.

Microsoft reference: https://learn.microsoft.com/en-us/microsoft-edge/webview2/reference/win32/icorewebview2
