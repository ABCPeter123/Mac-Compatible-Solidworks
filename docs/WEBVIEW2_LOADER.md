# Microsoft Edge WebView2 loader research

Status: independent, **read-only** WebView2 SDK loader discovery. No SOLIDWORKS, licensed installer, Microsoft browser/runtime installer, activation components or patches are used.

## Why this test

SOLIDWORKS Design 2026 lists Microsoft Edge WebView2 among its installation prerequisites. The existing Windows prerequisites probe does not validate it. Microsoft provides an architecture-specific WebView2Loader.dll in the Microsoft.Web.WebView2 SDK NuGet package. The loader offers the documented GetAvailableCoreWebView2BrowserVersionString API to discover an available browser runtime.

This experiment obtains SDK version 1.0.4314.35 from the official NuGet v3 distribution endpoint, verifies fixed SHA-256 checksums for the NuGet package and the extracted Windows x64 DLL, extracts only the Windows x64 loader DLL, and runs an independently authored Windows x64 executable. Archive SHA-256: `90778deb1b77e36292828b4b5833c9255c27533f40e0ddd55891ae718944edc4`. Loader SHA-256: `d3fce90bdeecb08596e377dea6a316354dd8949e32ff09b89d51be00c14e21b6`.

The DLL is not committed to GitHub and is retained only as a short-lived CI build artifact. Our test executable is compiled from probes/webview2_loader_probe.c with MinGW.

The test performs exactly one loader API call, with NULL as the browser path. It does **not** install a runtime, create an ICoreWebView2Environment, create a browser controller, render HTML or use any network-based application content.

## What the status means

- WEBVIEW2_LOADER=PASS: the SDK DLL loaded and its expected exported function was callable.
- WEBVIEW2_RUNTIME=VERSION_FOUND: the loader returned a nonempty runtime/browser version. The numeric version is deliberately not copied into CI reports.
- WEBVIEW2_RUNTIME=NOT_DISCOVERED: the call returned a failing HRESULT. This does not distinguish a missing runtime from a registry, Wine, DLL or browser startup problem.
- WEBVIEW2_PROBE=COMPLETE: the small API test completed with internally coherent markers. Runtime presence is **not** required for this marker, and the marker is not evidence of SOLIDWORKS compatibility.
- WEBVIEW2_PROBE=FAIL: the loader or its export could not be used, or the API returned an internally inconsistent reply.

The Python validator scripts/webview2_report.py accepts only exact, documented marker names and a bounded input log. The generated JSON does not contain arbitrary log lines, local paths, license data, installed browser versions or unknown text.

## Environments

The [WebView2 loader CI](../.github/workflows/webview2-loader-ci.yml) runs the same original executable and official SDK DLL on:

1. Native Windows Server 2025, used as a Windows API reference rather than a supported SOLIDWORKS client.
2. Linux Wine in a disposable prefix.
3. Apple Silicon macOS Wine 11.21 in a disposable prefix.

The workflow does not download or install the WebView2 Evergreen browser runtime. A clean Wine prefix may legitimately report NOT_DISCOVERED. **A green CI run can mean that the SDK loader worked while no WebView2 runtime was available.**

## Further test gate

An independent test that actually starts a WebView2 environment and embeds a controller is required before claiming WebView2 functionality. Only then would it make sense to try a properly licensed SOLIDWORKS Installation Manager and inspect its logs. Use official Microsoft redistributables and preserve the application license and security requirements.

References:
- Microsoft WebView2 distribution guidance: https://learn.microsoft.com/en-us/microsoft-edge/webview2/concepts/distribution
- Microsoft WebView2 NuGet package: https://www.nuget.org/packages/Microsoft.Web.WebView2/1.0.4314.35
- SOLIDWORKS official prerequisites: https://help.solidworks.com/2026/english/Installation/install_guide/c_prep_clients_admin_images.htm?id=0.2.2.0
