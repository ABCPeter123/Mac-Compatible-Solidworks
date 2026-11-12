# Functional installer and managed-runtime compatibility

Status: experimental cross-platform evaluation. No actual SOLIDWORKS installer or licensed application has been executed.

## Why functional tests are needed

The earlier prerequisite probe established that Wine exports Windows Installer, COM, CLR and service interfaces, and sometimes reports .NET Framework 4.8.1 and VC++ registry values. Those observations do not prove that Windows applications can use these components.

This test suite uses only two programs authored for this repository.

### MSI installation round trip

- Build a small x64 MSI package using the open-source wixl tool.
- Install one marker file into the user's LocalAppData directory, and register a test product with Windows Installer.
- Query the installed product state using MsiQueryProductStateW.
- Read and verify the marker file content.
- Uninstall the package and confirm both file removal and product deregistration.

The installer does not execute custom actions, install drivers, register services, modify system files, or access any SOLIDWORKS content. All Wine tests use isolated prefixes, and the harness attempts cleanup on failure. A passing test demonstrates this narrow MSI lifecycle only.

### Managed Framework executable

The C# test is compiled on the GitHub-hosted Windows Server 2025 runner against the Windows .NET Framework compiler. It exercises Task.Run, System.Xml parsing, SHA256 hashing, temporary file writes and reads, and managed exception handling. Successful execution confirms the independent test program can use those APIs. It does not confirm all SOLIDWORKS managed dependencies work.

The clean Wine prefix is tested first. Its managed-code failure is retained as independent evidence. The workflow then installs the open-source Wine Mono 11.3.0 runtime from a pinned x86 MSI, and repeats the managed test. Wine Mono is a substitute implementation, not an official Microsoft .NET Framework 4.8.1 installation.

Verified Wine Mono SHA-256 (x86 MSI):
df2dfc1665c2511882e7cabd56eafd0c0a3d94e5a7e86f969277f6c189d418d3

Official project: https://github.com/wine-mono/wine-mono

## Current results

First run: https://github.com/ABCPeter123/Mac-Compatible-Solidworks/actions/runs/43276248202

| Host | MSI install + removal | Managed Framework sample |
| --- | --- | --- |
| Windows Server 2025 | PASS, including file and registration checks | PASS |
| Ubuntu 24.04 Wine 9.0, clean prefix | PASS, including file and registration checks | FAIL, process exit 255 |
| Apple Silicon Wine 11.21 | Pending | Pending |
| Wine with explicitly installed Wine Mono 11.3.0 | Follow-up in progress | Follow-up in progress |

When the GitHub workflow finishes, detailed test results are attached as JSON artifacts and displayed in the step summaries. The Windows reference is not a supported client operating system for SOLIDWORKS Design.

## Running

On a configured Linux/macOS Wine prefix, download the independently compiled MSI, checker, and managed program from the workflow build artifacts. The script takes separate mode and runtime arguments:

    python -m scripts.functional_smoke msi --host wine --prefix /path/to/prefix --output build/msi-functional.json
    python -m scripts.functional_smoke managed --host wine --prefix /path/to/prefix --output build/dotnet-functional.json

On native Windows:

    python -m scripts.functional_smoke msi --host native --output build/msi-functional.json

The current Mac CI environment has no official SOLIDWORKS installation or activation credentials.

## Decision gate

1. Establish repeatable MSI and managed runtime behavior on Apple Silicon.
2. Validate additional installer behaviors that prove important to SOLIDWORKS: COM registration, 32-bit VC++ prerequisites, services and WebView2.
3. When an authentic licensed installer becomes available, conduct a controlled interactive test and inspect sanitized errors before writing compatibility patches.
4. Never bypass SOLIDWORKS licensing, distribute proprietary files, or claim CAD compatibility from standalone smoke tests.
