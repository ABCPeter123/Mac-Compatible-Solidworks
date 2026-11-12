# SOLIDWORKS installation-media preflight

**Status:** read-only, offline diagnostic. It does not install SOLIDWORKS, access entitlement, activate a license, modify Wine, or test CAD functionality.

This project has independently verified Windows x86/x64 execution, graphics, MSI installation, managed-code execution, COM activation with an isolated Wine workaround, MSVC runtime behavior, and a narrow Windows service lifecycle on Apple Silicon. The actual SOLIDWORKS installer has **not** been provided or run.

## What to inspect

SOLIDWORKS Design 2026 documentation says that a complete download directory should be installed using **SOLIDWORKS Installation Manager** via `setup.exe`. Installing individual component MSIs manually is not supported. SOLIDWORKS also distributes a self-extracting bootstrapper, sometimes named `SolidworksSetup.exe`. Its presence alone does not establish that the full media has been downloaded.

The [official Windows 11 administrative-image prerequisite list](https://help.solidworks.com/2026/english/Installation/install_guide/c_prep_clients_admin_images.htm?id=0.2.2.0) includes:

| Public prerequisite filename | Diagnostic group |
| --- | --- |
| `vc_redist.x64.exe` | Visual C++ 2022 x64 |
| `vc_redist.x86.exe` | Visual C++ 2022 x86 |
| `vba71.msi`, `vba71_1033.msi` | Visual Basic for Applications 7.1 |
| `CEF for SOLIDWORKS Applications.msi` | SWCEF |
| `MicrosoftEdgeWebView2RuntimeInstallerX64.exe` | WebView2 |
| `WPTx64-x86_en-us.msi` | Windows Performance Toolkit |

The same source lists `.NET Framework 4.8.1` as included in the supported Windows 11 operating system. Its standalone `ndp481-x86-x64-allos-enu.exe` prerequisite is listed for Windows Server 2022. The scanner reports that filename as a separate indicator, **not** as a mandatory Windows 11 media requirement.

These files may be absent from a partial download, or the installer may obtain prerequisites separately. A filename's presence does not demonstrate that a valid package is installed or executes.

Sources: [installation on individual computers](https://help.solidworks.com/2026/english/Installation/install_guide/c_installing_on_individual_computers.htm), [2026 prerequisite list](https://help.solidworks.com/2026/english/Installation/install_guide/c_prep_clients_admin_images.htm?id=0.2.2.0), [why not to invoke MSI files manually](https://help.solidworks.com/2025/English/Installation/install_guide/c_sldim_download_folder.htm?id=0ae7d856d99047e3ab6f582f74ecd687).

## Run locally, without sharing media

Run the following from the repository root on a computer that can access **legitimately obtained** installer media. You may use Windows, Linux, or macOS. A macOS machine is not required to scan an existing installer directory.

Windows PowerShell:

```powershell
py -3 -m scripts.installer_media_preflight --media "D:\\SOLIDWORKS_2026" --output "$HOME\\Desktop\\swcompat-preflight.json"
```

Linux/macOS terminal:

```sh
python3 -m scripts.installer_media_preflight --media "/path/to/SOLIDWORKS_2026" --output "$HOME/swcompat-preflight.json"
```

The `--media` argument also accepts a single locally held `SolidworksSetup.exe` bootstrapper, but this cannot inventory the rest of an unextracted installation package.

Only share the resulting **sanitized JSON report**, not the installer, serial number, activation information, or unrestricted installation logs.

## What the scanner records

- Whether a root-level `setup.exe`, nested `setup.exe`, or `SolidworksSetup.exe` was observed.
- Counts of files by broad extension and presence of specific **published** prerequisite filenames.
- The selected entrypoint's PE architecture, if recognizable, and broad categories of standard imported Windows DLLs.
- Whether scan limits were reached or symlinks were skipped.

It **does not** record original directory paths, non-whitelisted filenames, raw imported DLL names, file hashes, license information, or binary contents. No network request is made. It never runs an executable. The JSON output is refused when its path is inside the installation-media directory.

The PE import parser only reads up to 32 MiB of the entrypoint and covers a bounded set of standard import descriptors. It is **not** a complete dependency graph. Dynamic `LoadLibrary` calls, delay-loaded imports, encrypted installers, internal embedded MSI payloads, and installers downloaded at runtime may not appear.

A named file's presence does not establish completeness, authenticity, installation readiness, entitlement, or compatibility. An empty or incomplete scan is not a failure diagnosis for SOLIDWORKS.

## Automated regression

[Installer-media preflight CI](../.github/workflows/installer-media-preflight.yml) tests this code on Ubuntu and Windows using **synthetic** PE headers and placeholder files. No proprietary SOLIDWORKS artifacts appear in CI.

## What we do after an authentic local preflight

1. Compare its sanitized report with the [known Windows dependencies](INSTALLER_READINESS.md).
2. Identify the actual Installation Manager entrypoint and the components present in the media.
3. With proper licensing and an interactive Mac, run the authentic Installation Manager and capture sanitized failures.
4. Address real Windows API or service deficiencies from observed installer behavior, then test sketch, extrusion, save/reopen and viewport responsiveness.

The scan does not bypass licensing or replace the official Installation Manager.
