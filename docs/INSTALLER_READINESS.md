# SOLIDWORKS 2026 installer compatibility research

We use SOLIDWORKS Design 2026 as the reference version until an exact legitimately licensed release is available. No SOLIDWORKS binaries, installer media, or license keys are in this repository.

## Official listed prerequisites

| Component | Classification | Our test |
| --- | --- | --- |
| Windows 11 x64 | Supported client platform | Win64 process architecture and reported OS version |
| Microsoft Visual C++ Redistributable 2022 x64 and x86 | Required | Registry installation signals and selected DLL loadability |
| Microsoft .NET Framework 4.8.1 | Required | Registry release indication and CLR API export |
| Visual Basic for Applications 7.1 | Listed prerequisite | Not tested |
| SOLIDWORKS CEF (Chromium Embedded Framework) | Listed prerequisite | Not tested |
| Microsoft Edge WebView2 | Listed prerequisite | Not tested |
| Visual Studio Tools for Applications 2022 | Optional | Not tested |
| Windows Installer | Installation component | MSI DLL export check only |
| COM interfaces | Supporting Windows subsystem | COM apartment and ShellLink object |
| Service Control Manager | Supporting Windows subsystem | Connect-only, read-only |

Official sources:
- https://www.solidworks.com/support/system-requirements
- https://help.solidworks.com/2026/english/Installation/install_guide/c_prep_clients_admin_images.htm?id=0.2.2.0
- https://help.solidworks.com/2026/english/Installation/install_guide/c_installing_on_individual_computers.htm

The machine-readable requirements are in config/prerequisites_2026.json.

## What the diagnostics establish

The source file probes/win_prereq_probe.c is a read-only Windows x64 executable. It checks API availability and runtime registry indicators without installing anything or modifying Windows. Each result is a limited signal rather than proof that SOLIDWORKS can install.

Wine may simulate registry version values and provide API exports without a fully functional implementation. We must test actual managed code, MSI operations, and COM behaviors before declaring them compatible.

The report generator scripts/prereq_report.py produces JSON and Markdown from an explicit completed probe run. Unsupported checks are identified as NOT_TESTED, not marked as failures.

## Cross-platform comparison

The Installer prerequisite reconnaissance GitHub Actions workflow compiles one independent Windows x64 executable and runs it on:
- a GitHub Windows Server 2025 runner as a Win32 API reference, not an officially supported SOLIDWORKS desktop environment;
- Linux Wine on Ubuntu 24.04;
- Wine 11.21 on GitHub-hosted Apple Silicon macOS 15.

CI stores the diagnostic evidence as artifacts without distributing any proprietary SOLIDWORKS installation media.

From a prepared Wine prefix after obtaining the probe executable from CI:

    python -m swcompat --prefix /path/to/prefix --logs-dir build/logs probe-prereqs

## Wine's Windows 11 version profile

The initial Apple Silicon Wine 11.21 probe reported Windows 10 build 19045, even though the official SOLIDWORKS 2026 client target is Windows 11. Wine supports setting its reported global Windows version within a disposable prefix:

    python -m swcompat --prefix /path/to/prefix set-winver win11
    python -m swcompat --prefix /path/to/prefix probe-prereqs

The dedicated CI job tests this setting and checks that the reported build is at least 22000. The baseline and altered-profile reports are retained separately for comparison.

**Version emulation is not actual Windows 11 compatibility.** The setting may satisfy simple installer version checks but does not provide unavailable Windows API implementations, drivers, .NET functionality, or license mechanisms. Never use version reporting as evidence of SOLIDWORKS installation success.

## Next gate

1. Compare MSI, COM, SCM, .NET, and VC++ evidence across the three environments.
2. Replace superficial symbol-presence tests with functionality checks for failing interfaces.
3. Test an authentic, appropriately licensed SOLIDWORKS installer when available, in a controlled interactive Mac environment.
4. Record sanitized installer failures and identify unsupported Windows APIs. Avoid bypassing activation or modifying proprietary program binaries.
5. Verify sketch, extrusion, model rotation, and save/reopen functionality before claiming usable CAD compatibility.

The proven Mesa llvmpipe 3D test establishes Windows OpenGL operation on hosted Apple Silicon, not SOLIDWORKS product compatibility.
