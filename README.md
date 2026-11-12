# SOLIDWORKS macOS Compatibility Lab

An open-source engineering testbed for running the **original, licensed Windows SOLIDWORKS application** on macOS, without rebuilding SOLIDWORKS or requiring a commercial VM.

**Status: experimental foundation. SOLIDWORKS installation, activation, graphics rendering and CAD functionality have NOT been demonstrated.**

## Why this exists

The goal is to identify and fix missing interfaces between SOLIDWORKS, Wine, and macOS. First we establish basic Windows x64 execution and Windows OpenGL/WGL support, then investigate dependencies and installer behavior. We do not try to reverse-engineer Windows in its entirety.

## Cloud-first development

You do **not** need a Mac to develop this project. GitHub Actions runs tests on macOS Apple Silicon (`macos-15`), macOS Intel (`macos-15-intel`), and Linux. It builds an independent Windows x64 OpenGL probe and uploads machine reports. An optional Linux Wine/WGL smoke test runs through manual workflow dispatch.

Go to [Actions](../../actions) and select **Compatibility foundation**, or see [cloud testing](docs/CLOUD_TESTING.md).

Hosted test runners have limited GPU, interactivity, and licensing capabilities. Passing CI **does not mean SOLIDWORKS works**. Eventually we need a licensed physical Mac or equivalent suitable interactive environment.

## Experimental Wine execution on hosted Macs

The separate [macOS Wine experiment](.github/workflows/wine-macos-experimental.yml) downloads the upstream Wine 11.21 development bundle on hosted Intel and Apple Silicon machines. The exact 225 MB archive is pinned to its SHA-256 digest and is not committed to this repository. This workflow tries actual Win32 execution and a WGL/OpenGL context under Wine, collecting logs even if either operation fails.

[Inspect the experiment's workflow runs](../../actions/workflows/wine-macos-experimental.yml). A passing dependency or download step is not equivalent to a passing WGL probe, and neither proves SOLIDWORKS compatibility.

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
