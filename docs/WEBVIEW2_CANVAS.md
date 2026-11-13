# Browser-internal Canvas 2D versus window presentation

The primary blocker for a native SOLIDWORKS compatibility layer on Apple Silicon is still **unverified embedded Chromium pixels**. The signed Microsoft WebView2 runtime installs in a disposable Wine 11.21 prefix, and the controller, HTML navigation and DOM JavaScript work. Nevertheless, both browser screenshot APIs time out, GDI HWND readback yields no expected colors, and GDI desktop readback fails on the GitHub-hosted Mac.

This experiment distinguishes drawing *inside Chromium's Canvas backing store* from showing those pixels through Chromium's window compositor and the macOS desktop.

## Independent programmatic test

The original x64 WebView2 C++ render probe now uses two additional \`ExecuteScript\` calls after DOM navigation, before either GDI or Chromium screenshots:

1. A fresh 64-by-48 HTML \`canvas\` obtains a normal 2D rendering context. \`fillRect\` paints an RGB (19, 83, 147) blue background and an RGB (29, 205, 91) green central rectangle. \`getImageData\` returns the actual RGBA bytes at two distinct positions. The JavaScript callback returns the exact fixed \`SWCOMPAT_CANVAS_PIXELS_OK\` marker only if the pixels match.
2. On that same Canvas, \`toDataURL("image/png")\` must return a well-formed PNG data URL prefix and nontrivial encoded content. Its asynchronous WebView2 \`ExecuteScript\` callback must return the exact fixed \`SWCOMPAT_CANVAS_PNG_OK\` marker.

Neither check calls a WebView2 screenshot API, \`BitBlt\`, or interacts with a physical screen. These tests establish browser-internal Canvas drawing and basic encoding only. They do **not** demonstrate CSS compositing, DOM element display, browser window presentation, hardware acceleration, input, or SOLIDWORKS.

The C++ probe emits allowlisted \`SWCOMPAT_WV2_CANVAS_2D\`, \`SWCOMPAT_WV2_CANVAS_PNG\` and \`SWCOMPAT_WV2_CANVAS_PROBE\` markers *before* screenshot calls. The [Canvas reporter](../scripts/webview2_canvas_report.py) independently parses these markers from locally retained logs. Malformed, duplicate, absent or unexpected values fail. No screenshot bytes, log lines, browser version, filesystem paths or user information are exported in artifacts.

## CI requirements

The existing [signed WebView2 Runtime workflow](../.github/workflows/webview2-runtime-install-ci.yml) builds one original Windows x64 executable using Microsoft SDK headers and runs it on Windows Server and in Apple Silicon Wine. Native Windows must pass the Canvas checks **as well as** the PNG and GDI pixel proofs.

On Apple Silicon the new Canvas test must pass before the previous known screenshot-blocker outcome can be classified as a completed diagnostic. The strict \`require_macos_pixels=true\` workflow option continues to reject cases with no verified display pixels.

The [fail-closed renderer classifier](../scripts/webview2_render_gate.py) now consumes four independent reports: verified runtime/controller, internal browser Canvas, browser screenshot, and GDI window readback. It must never reinterpret successful Canvas drawing as physical window pixels.

## Interpretation

| Canvas readback and PNG encoding | Browser screenshot / GDI | Conclusion |
| --- | --- | --- |
| PASS | Pixel proof PASS | Canvas works, tested screenshot or GDI pixels verified |
| PASS | Known negative | Chromium Canvas computes correct pixels internally; window presentation remains unverified |
| FAIL | Any result | Canvas internal drawing/encoding is an additional compatibility blocker, not a known screenshot-only failure |

A Canvas internal PASS can coexist with failed compositor paths; this points to a narrower window presentation issue but does not establish a specific root cause or that the entire rendering engine works. A Canvas FAIL requires investigation of the particular Canvas stage, independent of screenshot issues.

See [WebView2 graphics issue #26](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/issues/26) and [existing rendering diagnostics](WEBVIEW2_RENDERING.md).

No proprietary SOLIDWORKS binary, installer, activation data or licensing mechanisms are altered or bundled.
