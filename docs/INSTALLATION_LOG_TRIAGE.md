# Offline SOLIDWORKS Installation Manager log triage

This tool classifies a fixed set of known Windows Installer and Windows API error indicators in **local** Installation Manager logs. It never runs SOLIDWORKS, uploads logs, modifies the system, reads activation data intentionally, or exports arbitrary log lines.

## Where to get logs

According to the [SOLIDWORKS 2026 Installation Manager options](https://help.solidworks.com/2026/english/SolidWorks/install_guide/t_set_logging_speed_language.htm?id=36.0.8.1), right-click the SOLIDWORKS icon in the Installation Manager title bar and select **Gather Installation Logs**. The manager saves the files in `IM_Logs.zip`. The same dialog can raise logging detail and enable Windows Installer logs.

The standard installation-log location is under the user's roaming AppData directory, in:

```text
SOLIDWORKS\Installation Logs\<installed_version>\
    SummaryIMLog_....txt
    Other Logs\
```

Official background: [SOLIDWORKS Installation Manager log files](https://help.solidworks.com/2025/english/SolidWorks/install_guide/c_inst_log_files.htm?id=36.0.7.1).

## Run locally

From the repository root in Windows PowerShell:

```powershell
py -3 -m scripts.solidworks_log_triage --logs "C:\Path\To\IM_Logs.zip" --output "$HOME\Desktop\swcompat-log-report.json"
```

You can also point `--logs` to the extracted installation-log directory or an individual `.txt` / `.log` file.

On macOS or Linux:

```sh
python3 -m scripts.solidworks_log_triage --logs "/path/to/IM_Logs.zip" --output "$HOME/swcompat-log-report.json"
```

Use the **generated JSON report** when discussing errors. Do not publish full installation logs or ZIP archives. They may contain personally identifiable information, serial numbers, internal paths and entitlement details.

## Report format

The output contains only stable, allowlisted issue identifiers and their occurrence counts, such as:

- `msi_fatal_1603`: Windows Installer returned error 1603
- `msi_busy_1618`: another MSI installation is in progress
- `com_class_not_registered`: `0x80040154` or known text indicator
- `service_not_found`: `0x80070424` or known text indicator
- `module_not_found`: `0x8007007E`
- `access_denied`: `0x80070005`
- `dotnet_runtime_error`, `vc_runtime_error`, `webview2_error`: narrow prerequisite-error patterns

**These are potential diagnostics, not validated causes.** A generic MSI 1603 error does not tell us what failed. A report with no recognized indicators does **not** imply a successful installation. The scanner does not export unrecognized codes, arbitrary source text, filenames, directory paths, emails, or keys.

This tool is deliberately conservative about privacy. For deeper analysis, keep the raw logs private and inspect them in an authorized environment.

## Bounds and safe handling

- Never extracts ZIP members to disk. Reads only `.txt` and `.log` members.
- Caps each log at 3 MiB, total inspected data at 30 MiB, and the number of logs at 300.
- Marks incomplete/truncated scans in the JSON report.
- Supports UTF-8 and UTF-16 BOM text files.
- Skips symlinks in directories and does not write inside the source log directory.
- Uses only Python's standard library, with no network requests.

[Unit tests and synthetic CI](../.github/workflows/installation-log-triage.yml) run on Ubuntu and Windows with fabricated errors, paths, emails, and license placeholders. No official SOLIDWORKS files or private records enter GitHub CI.

## Relationship to the Mac compatibility project

A real, legally obtained SOLIDWORKS installer is still needed. Once it is run in a controlled interactive Mac Wine prefix with appropriate licensing, its **local** logs can be summarized safely using this utility. We can then map observed failures to concrete Wine APIs and service behavior rather than guessing from generic Windows tests.

No part of this process bypasses licensing or alters SOLIDWORKS proprietary components.
