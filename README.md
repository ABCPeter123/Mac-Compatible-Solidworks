# SOLIDWORKS macOS Compatibility Lab

An open-source engineering testbed for running the **original, licensed Windows SOLIDWORKS application** on macOS, without rebuilding SOLIDWORKS or requiring a commercial VM.

**Status: independent Windows x64 execution, OpenGL 4.5 pixel rendering and depth-buffered geometry are verified on Apple Silicon. SOLIDWORKS installation, activation and CAD functionality have NOT been demonstrated.**

## Why this exists

The goal is to identify and fix missing interfaces between SOLIDWORKS, Wine, and macOS. First we establish basic Windows x64 execution and Windows OpenGL/WGL support, then investigate dependencies and installer behavior. We do not try to reverse-engineer Windows in its entirety.

## Cloud-first development

You do **not** need a Mac to develop this project. GitHub Actions runs tests on macOS Apple Silicon (`macos-15`), macOS Intel (`macos-15-intel`), and Linux. It builds an independent Windows x64 OpenGL probe and uploads machine reports. An optional Linux Wine/WGL smoke test runs through manual workflow dispatch.

Go to [Actions](../../actions) and select **Compatibility foundation**, or see [cloud testing](docs/CLOUD_TESTING.md).

Hosted test runners have limited GPU, interactivity, and licensing capabilities. Passing CI **does not mean SOLIDWORKS works**. Eventually we need a licensed physical Mac or equivalent suitable interactive environment.

## Experimental Wine execution on hosted Macs

The separate [macOS Wine experiment](.github/workflows/wine-macos-experimental.yml) downloads the upstream Wine 11.21 development bundle on hosted Intel and Apple Silicon machines. The exact 225 MB archive is pinned to its SHA-256 digest and is not committed to this repository. This workflow tries actual Win32 execution and a WGL/OpenGL context under Wine, collecting logs even if either operation fails.

[Inspect the experiment's workflow runs](../../actions/workflows/wine-macos-experimental.yml). A passing dependency or download step is not equivalent to a passing WGL probe, and neither proves SOLIDWORKS compatibility.

## Graphics backend research

Our first hosted macOS tests proved Windows x64 execution but **not** WGL graphics: the tested Gcenx Wine 11.21 package explicitly disables OpenGL (`--without-opengl`). Native Metal framebuffer rendering has passed on both hosted Mac architectures.

We now test **Mesa Zink → Vulkan/MoltenVK → Metal**, using an independent Windows x64 OpenGL probe and a checksum-pinned Mesa 26.2.6 Windows distribution. See the [Zink experiment](.github/workflows/wine-zink-macos.yml) and [documented evidence](docs/KNOWN_ISSUES.md). Test logs are published as workflow artifacts. The experiment uses only open-source runtime DLLs and a disposable Wine prefix, never SOLIDWORKS binaries.

### Confirmed Apple Silicon Windows OpenGL software-rendering fallback

Our [macOS and Linux experiment](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/actions/runs/43261277885) succeeded at **Windows x64 WGL OpenGL 4.5 context creation** on hosted Apple Silicon, using Wine 11.21 plus Mesa 25.1.9 with the `llvmpipe` software renderer. This avoids the missing Vulkan features that blocked the newer Mesa Zink path. The independent Windows program creates a context, selects a pixel format, clears the viewport, and swaps buffers. The stricter pixel-readback test and latest CI results are tracked in [the software OpenGL workflow](.github/workflows/wine-software-opengl.yml).

See [software OpenGL installation and launching](docs/SOFTWARE_OPENGL.md) for a reproducible test configuration and `scripts.software_launch` launcher. This is still experimental, potentially slow CPU rendering. **The actual SOLIDWORKS installer, activation, and CAD functions have not been tested.**

## Event-driven Windows GUI compatibility probe

The original [Win32 GUI/WGL session test](docs/GUI_SESSION.md) exercises a real Windows window and child button, a message pump, synthetic mouse/selection input, viewport resize, two pixel-verified OpenGL frames and Win32 state save/reopen. It runs using the existing Mesa llvmpipe path on Linux Wine and Apple Silicon Wine. Compile it with `sh scripts/build-wgl-probe.sh`, then run:

```sh
python3 -m swcompat --prefix "$SWPREFIX" probe-wgl --exe build/win_gui_session_probe.exe
```

A passing test does not demonstrate physical Mac input, the SOLIDWORKS GUI or a real CAD document.

## SOLIDWORKS installer prerequisites research

The [installation prerequisite reconnaissance workflow](.github/workflows/installer-prereq-ci.yml) builds a small read-only Windows x64 executable. It checks Windows Installer, COM, service manager access, VC++ runtime indicators, .NET Framework registry signals, and basic host information on native Windows, Linux Wine, and Apple Silicon Wine.

The reference requirements come from SOLIDWORKS Design 2026. See [installation compatibility findings](docs/INSTALLER_READINESS.md) and the [machine-readable prerequisite catalog](config/prerequisites_2026.json). Run the probe in an existing Wine prefix:

```sh
python3 -m swcompat probe-prereqs
```

The probe needs the Windows x64 executable from CI. A successful probe only confirms its own completion, not readiness to install SOLIDWORKS. No proprietary installer or licensing material is used in public CI.

## Offline SOLIDWORKS installation-media preflight

We can now inspect an **authorized local SOLIDWORKS 2026 installer folder** without installing or uploading it:

```sh
python3 -m scripts.installer_media_preflight \
  --media "/path/to/authorized/SOLIDWORKS_2026" \
  --output "$HOME/swcompat-preflight.json"
```

The inventory identifies the Installation Manager entrypoint, official prerequisite filenames, and broad Windows PE import categories. It does not run the installer, expose user paths in JSON, or claim the installation media is complete. See [local media preflight and privacy controls](docs/INSTALLER_MEDIA_PREFLIGHT.md) and its [synthetic-media CI tests](.github/workflows/installer-media-preflight.yml).

## Local SOLIDWORKS installation-log analysis

When an authorized Installation Manager run produces `IM_Logs.zip`, you can generate a redacted, **offline** diagnostic report:

```sh
python3 -m scripts.solidworks_log_triage \
  --logs "/path/to/IM_Logs.zip" \
  --output "$HOME/swcompat-log-report.json"
```

The tool recognizes a fixed set of MSI, COM, service, runtime, and WebView2 error patterns. It never exports raw log lines, user paths, license tokens, or unknown error codes. See [log collection and safe triage](docs/INSTALLATION_LOG_TRIAGE.md). A recognized error remains a possible diagnostic, not proof of its root cause.

## Offline installer evidence correlation

After generating either sanitized report, use the [offline evidence correlator](docs/INSTALLER_EVIDENCE_REPORT.md) to prioritize the next compatibility investigation:

```sh
python3 -m scripts.installer_evidence_report \
  --media-report "$HOME/swcompat-preflight.json" \
  --log-report "$HOME/swcompat-log-report.json" \
  --output "$HOME/swcompat-evidence.json"
```

Either input report is optional if unavailable. The output contains only known diagnostic categories and fixed next-step guidance. It never claims that SOLIDWORKS is installed or usable.

## Microsoft WebView2 loader compatibility research

The [Windows WebView2 SDK loader probe](docs/WEBVIEW2_LOADER.md) tests the genuine Microsoft loader's browser-version API on Windows Server, Linux Wine, and Apple Silicon Wine using the independent x64 executable. It distinguishes a callable SDK loader from a runtime that could not be discovered. This is a narrower prerequisite check, **not** a WebView2 browser-controller test or a SOLIDWORKS installation.

## WebView2 environment and controller creation test

The [WebView2 Win32 controller compatibility experiment](docs/WEBVIEW2_CONTROLLER.md) now tests real asynchronous COM environment creation, controller creation inside an HWND, and access to the controller's WebView2 interface. It builds an independent Windows x64 executable against Microsoft's checksum-pinned SDK, then compares native Windows Server with Linux Wine and Apple Silicon Wine.

The report distinguishes an API test that **completed** from a browser controller that actually reached **READY**. No HTML rendering, SOLIDWORKS installation, licensing or CAD workflows are claimed.

## Local development

Requires Python 3.10+:

```sh
python3 -m unittest discover -s tests -v
python3 -m swcompat doctor --json
```

With a compatible externally installed Wine binary:

```sh
python3 -m swcompat init
python3 -m swcompat probe-win32
```

With an x86_64 MinGW-w64 cross-compiler:

```sh
./scripts/build-wgl-probe.sh
python3 -m swcompat probe-wgl
```

Use `--wine /path/to/wine` if Wine is not found. Wine prefixes and logs are isolated from `~/.wine`. For a properly licensed installer, `python3 -m swcompat install /path/to/installer.exe` starts an investigation and logs errors. It does **not** promise a successful installation. Analyze failures with `python3 -m swcompat analyze /path/to/logfile`.

## Scope and licensing

This project neither includes SOLIDWORKS nor distributes its binaries, activation keys, Windows files, or copy-protection bypasses. Use only installers and software you are licensed to run. Wine and any dependencies retain their own licenses. Project-authored code is MIT licensed. This project is not affiliated with Dassault Systèmes.
