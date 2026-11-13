# WebView2 environment and controller interoperability

This experiment is the next gate after [Microsoft WebView2 loader discovery](WEBVIEW2_LOADER.md). The previous probe confirmed that the official WebView2 SDK DLL's version-query API can run under Wine, but did **not** create a browser environment.

The new original C++ test in probes/webview2_controller_probe.cpp calls the public Microsoft WebView2 SDK APIs. It uses a real Win32 window, COM single-threaded apartment, and Windows message pump. It does not contain SOLIDWORKS binaries, a WebView2 browser runtime, activation code or a Windows installation image.

## What is exercised

1. Load the checksum-pinned Microsoft x64 WebView2Loader.dll and resolve its runtime-query and environment-creation exports.
2. Initialize the COM STA and create a real Win32 top-level window.
3. Ask the loader whether a browser runtime version is available without exporting the version string.
4. Invoke CreateCoreWebView2EnvironmentWithOptions with a temporary user-data folder and an asynchronous COM callback. Pump the Windows message queue while awaiting the callback.
5. Only if an environment is created, call ICoreWebView2Environment::CreateCoreWebView2Controller and wait for its asynchronous callback.
6. Only if a controller is created, retrieve ICoreWebView2 and set its bounds and visibility.
7. Release COM interfaces and destroy the window. The disposable CI system discards the temporary user-data folder.

A completed diagnostic with a missing runtime is **not a passed browser test**. The result separately states whether the environment and controller reached READY. Timeouts and failed HRESULTs are recorded as bounded categories and public hexadecimal codes.

No HTML navigation, page rendering, JavaScript execution, physical input, SOLIDWORKS installation or activation is tested.

## Reproducible hosted tests

[WebView2 environment/controller CI](../.github/workflows/webview2-controller-ci.yml) builds the original Windows x64 C++ executable against official Microsoft.Web.WebView2 SDK 1.0.4314.35 headers with the hosted Windows MSVC compiler. The official NuGet archive SHA-256 and WebView2Loader.dll SHA-256 are verified against fixed values documented in the [loader test](WEBVIEW2_LOADER.md).

The same compiled Windows executable runs on:

- Windows Server 2025, as a native Win32 baseline. The workflow requires an actual controller to become READY.
- Ubuntu Wine with an Xvfb display in a disposable prefix. A missing runtime is recorded as a negative finding, not claimed as compatibility.
- Apple Silicon Wine 11.21 on a GitHub-hosted Mac, again using a disposable prefix.

Windows Server 2025 is **not** an officially supported SOLIDWORKS Design client configuration, and hosted macOS is not equivalent to an interactive user Mac.

## Verified CI results, November 12, 2026

The [six-job hosted run](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/actions/runs/43336566332) passed, using the same original x64 executable and a checksum-pinned official SDK.

| Host | Runtime query | Environment | Controller | Interpretation |
| --- | --- | --- | --- | --- |
| Windows Server 2025 | VERSION_FOUND | READY | READY | Real WebView2 environment and controller were created |
| Ubuntu 24.04 Wine | NOT_DISCOVERED | REQUEST_FAILED | NOT_REACHED | No WebView2 environment was created |
| Apple Silicon Wine 11.21 | NOT_DISCOVERED | REQUEST_FAILED | NOT_REACHED | No WebView2 environment was created |

The Windows runner required `--require-controller` and exited successfully only after the WebView2 controller became READY. Both Wine environments ran the same API test and produced coherent **negative** results. In particular, a green Wine CI job does **not** establish browser runtime availability, HTML rendering or WebView2 controller support. Running a genuine runtime installer and then repeating this test is the next dependency gate.

## Diagnostic report

The independent validator scripts/webview2_controller_report.py converts probe output to a bounded, sanitized JSON report. It accepts only fixed marker identifiers and valid HRESULT-shaped codes. It does not export arbitrary stderr, filenames, runtime version strings, serials, user-data paths or private input.

For a local probe log:

~~~sh
python3 -m scripts.webview2_controller_report \
  --input /private/location/webview2-controller.log \
  --exit-code 0 \
  --output /private/location/webview2-controller.json
~~~

Use --require-controller when a real controller is required, as on the native Windows reference. Without that flag, a COMPLETE diagnostic may still show REQUEST_FAILED, CALLBACK_FAILED, TIMEOUT, or NOT_REACHED. Such outcomes must never be reported as WebView2 compatibility PASS.

## Next acceptance gate

If the Wine prefix cannot discover a runtime, use an official Microsoft WebView2 Runtime installer in a legitimately authorized, isolated host test and record whether it installs and starts. A loader and COM callback test is not a substitute for browser engine startup. Once an embedded controller works, add a local HTML navigation and DOM verification test before attributing any SOLIDWORKS UI compatibility to WebView2.

Official references:
- https://learn.microsoft.com/en-us/microsoft-edge/webview2/get-started/win32
- https://learn.microsoft.com/en-us/microsoft-edge/webview2/concepts/distribution
- https://learn.microsoft.com/en-us/microsoft-edge/webview2/reference/win32/icorewebview2environment
