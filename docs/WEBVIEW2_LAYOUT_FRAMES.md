# WebView2 browser CSS layout and animation-frame isolation

The earlier [Canvas internal-pixel probe](WEBVIEW2_CANVAS.md) demonstrated that Chromium can draw, read and PNG-encode Canvas 2D pixels through Microsoft WebView2 on Apple Silicon Wine. Nevertheless, real browser window screenshots time out and Windows GDI readback cannot verify page pixels in the hosted Mac environment.

This experiment tests two additional stages of Chromium's browser pipeline before attempting any screenshot, independently of Canvas pixel computation.

## CSS geometry and hit testing

The original Windows x64 C++ WebView2 probe runs inline JavaScript in a real browser:

- Locate the fixed synthetic #swcompat-marker element on the offline HTML page.
- Check its actual computed box using getBoundingClientRect against fractional viewport geometry (left=25%, top=25%, width=50%, height=50%). Use tolerance to allow subpixel layout.
- Confirm elementFromPoint at the viewport center hits the marker while a point outside the marker does not.
- Confirm position:absolute and the expected computed green background.

The marker \`SWCOMPAT_WV2_LAYOUT_CSS=PASS\` is emitted only after the real browser's ExecuteScript completion callback returns the exact expected result. This establishes CSS layout and DOM hit-testing internally, **not actual painted pixels**.

## Animation frame scheduling

A second script creates an isolated JS counter, installs a requestAnimationFrame callback, and requests up to three callbacks. The original Win32 host pumps its STA message loop for 1.8 seconds, then independently queries the counter through a later ExecuteScript completion.

\`SWCOMPAT_WV2_LAYOUT_RAF\` is one of:

- \`TICKED\`: at least two requestAnimationFrame callbacks ran.
- \`STALLED\`: the callback counter remained under two within the sampling window.
- \`SCRIPT_FAILED\`: the sampling callback could not complete or returned an unexpected value.

These three states are recorded separately. A stalled callback could be due to hosted Mac throttling, background visibility, or other timing limits. It is **not** by itself proof of a faulty graphics compositor. A ticking callback is also not proof that the browser window painted the page.

## Evidence and CI

The probe emits bounded fixed-value lines before the GDI and WebView2 screenshot attempts. The independent [layout reporter](../scripts/webview2_layout_report.py) accepts only the specified marker names and values and exports a privacy-safe JSON report. Duplicate, malformed, unknown or absent markers cause diagnostic failure.

The [signed WebView2 CI workflow](../.github/workflows/webview2-runtime-install-ci.yml) runs the original x64 executable on native Windows and hosted Apple Silicon Wine 11.21 with the official Microsoft Evergreen Runtime. The [fail-closed renderer classifier](../scripts/webview2_render_gate.py) requires valid runtime/controller, Canvas, CSS layout/frame, GDI and screenshot reports before it can classify the exact known screenshot timeout as a *completed diagnostic*. Missing CSS proof fails the job. The explicit manual \`require_macos_pixels=true\` acceptance switch continues to require **real browser window RGB pixels** and does not accept layout, animation frames, or internal Canvas pixels as substitutes.

No WebView2 screenshot content, user HTML, proprietary installer, license information, or unfiltered process output is uploaded.

## Verified results, November 13, 2026

[Hosted GitHub Actions run 43378297592](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/actions/runs/43378297592) completed the authentic Microsoft-signed WebView2 Runtime installation and all CI jobs. The original same Windows x64 probe was executed on native Windows Server 2025 and macOS 15 Apple Silicon under Wine 11.21.

| Stage | Native Windows | Apple Silicon Wine |
| --- | --- | --- |
| WebView2 Runtime environment / controller | READY | READY |
| HTML navigation / DOM JavaScript | PASS | PASS |
| CSS box geometry and elementFromPoint | PASS | **PASS** |
| requestAnimationFrame callback counter | TICKED | **TICKED** |
| Canvas getImageData RGBA and PNG encoding | PASS | PASS |
| WebView2/browser screenshot pixel evidence | VERIFIED | NOT_VERIFIED (`CDP_TIMEOUT`) |
| GDI display pixel evidence | VERIFIED | NOT_VERIFIED |
| Classification | Native pixel verification | `KNOWN_CAPTURE_BLOCKER` |

**Finding:** The browser's CSS layout engine, element hit testing, internal Canvas 2D readback and normal animation-frame scheduling work in this tested Apple Silicon Wine configuration. This rules out a blanket lack of requestAnimationFrame callbacks or an inability to calculate the static test page's layout. It does **not** prove that any frame reaches an onscreen macOS window or rule out all compositor-related defects.

In the CI run, 14 layout-report tests and 26 stricter renderer-classifier tests passed on native Windows. The hosted Mac rendering diagnostic completed and still reported `browser_pixels=NOT_VERIFIED`; strict `require_macos_pixels=true` therefore remains unmet.

## Interpretation and next step

If Canvas, CSS geometry and requestAnimationFrame all work while screenshot/GDI fail, the blocker is more likely in surface composition, capture or macOS window presentation, but these tests cannot isolate a specific Wine or Chromium implementation fault. If requestAnimationFrame stalls while CSS geometry succeeds, test with an interactive Mac window server before treating scheduling as broken.

Tracked in [issue #26](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/issues/26). None of these probes tests licensed SOLIDWORKS installation, activation, user interaction or CAD geometry.
