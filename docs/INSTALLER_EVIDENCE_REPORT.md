# Offline correlation of SOLIDWORKS installer evidence

The local evidence correlator consumes **only** sanitized JSON produced by two existing tools:

- [Installer media preflight](INSTALLER_MEDIA_PREFLIGHT.md) inventories authorized local installer media without executing it.
- [Installation log triage](INSTALLATION_LOG_TRIAGE.md) detects a fixed set of installer log indicators without exporting log lines.

The correlator produces a deterministic shortlist of subsystems to examine, for example COM registration, cross-process service visibility, managed code, MSVC dependencies, WebView2, and generic MSI errors. It never loads SOLIDWORKS, runs an installer, contacts the network, activates software, or changes Wine settings. No SOLIDWORKS binary or proprietary data is committed to GitHub.

## Usage

From the repository root, after running the two local scanners:

~~~sh
python3 -m scripts.installer_evidence_report \
  --media-report /private/location/swcompat-preflight.json \
  --log-report /private/location/swcompat-log-report.json \
  --output /private/location/swcompat-evidence.json
~~~

Either --media-report or --log-report can be omitted if you only have one. The tool does not report the input filenames or their paths. You may share **only** its sanitized swcompat-evidence.json, after reviewing it, instead of private media or original logs.

## Report guarantees and limitations

- Every recommendation is from a fixed public set of action identifiers and text. Input paths, private filenames, log lines, unknown diagnostic codes and source metadata are not copied.
- Inputs are capped at 1 MiB each and must match the scanners' schema 1. Unexpected log diagnostic identifiers and invalid counters cause a safe error.
- A root setup.exe indicates only a possible entrypoint, **not** complete or authentic media. A standalone SolidworksSetup.exe bootstrapper is not equivalent to a complete downloaded installer directory.
- A report with no recognized error indicators is **not** evidence of a successful installation. MSI 1603 is generic and does not establish a root cause.
- Even if both reports contain no apparent problems, installation_and_cad_compatibility is always NOT_DEMONSTRATED. Only a licensed interactive installation and real CAD tests can change that conclusion.

## Next evidence gate

Use this report to select a failing subsystem for an independently reproducible test, rather than changing Wine settings blindly. Existing software OpenGL, MSI, COM, .NET, MSVC and single-process SCM tests cover selected interfaces but do not validate the SOLIDWORKS installer.

The CI workflow tests the correlator with fabricated sanitized reports on Ubuntu and Windows. It never uploads actual installer media or installation logs.
