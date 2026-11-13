# First authentic SOLIDWORKS installer test on Apple Silicon Wine

**Current state:** the workflow and launcher are prepared, but no actual SOLIDWORKS installer has been provided or executed. Passing synthetic CI checks does not establish software installation or UI visibility.

## Getting legitimate installation media

For an eligible student edition license whose serial number **begins with 9020**, use the [official SOLIDWORKS Community Download page](https://www.solidworks.com/support/community-download). Choose **Yes** for already having a 9020 serial, provide the requested personal information to SOLIDWORKS directly, and select the **specific version covered by the license**. Do not assume that a license for an older release is entitled to 2026. Refer to the official [2026 student installation instructions](https://files.solidworks.com/education/SOLIDWORKS_Student_Premium_Instructions_2026_v2.pdf) and [version-specific entitlement FAQ](https://www.solidworks.com/support/frequently-asked-questions?page=1&term_id=422).

The official download produces a self-extracting installer, commonly `SolidworksSetup.exe`. This is **not** necessarily the full multi-gigabyte installation media. Download and terms acceptance must happen through SOLIDWORKS under the user's own authorization. This repository never asks for, stores, validates, or transmits the serial or activation credentials. Do **not** paste them into any repository issue, workflow input or GitHub secret.

## Supply the installer without publishing it

The repository is **public**. Never commit SOLIDWORKS installation media, installer logs, serials or a link that grants unauthorized public access.

1. Obtain the authentic `SolidworksSetup.exe` through the official student download page, using your licensed release.
2. Compute its SHA-256 on your Windows computer:
   `Get-FileHash -Algorithm SHA256 "C:\path\to\SolidworksSetup.exe"`
3. Upload only this already authorized installer to a **private** cloud object store under your control. Make a time-limited, HTTPS-only signed GET URL. It must stay valid long enough for Windows signature verification and the following Mac job. Neither the private URL nor the executable belongs in the Git repository.
4. Open repository **Settings > Secrets and variables > Actions > New repository secret**. Create:
   - `SWCOMPAT_INSTALLER_URL`: the temporary HTTPS download link.
   - `SWCOMPAT_INSTALLER_SHA256`: the exact locally calculated 64-character SHA-256.
5. In repository **Actions > Licensed SOLIDWORKS bootstrapper first-launch trial**, choose **Run workflow** on `main`. This workflow executes the licensed installer only after a human explicitly dispatches it and provides the private media.

You can delete both secrets and private storage object after testing. The workflow never exposes the signed URL, uploads binary bytes or captures screenshot/log data. Only sanitized JSON diagnostics are uploaded.

## What the workflow actually tests

On native Windows Server, it downloads the executable over HTTPS, verifies its full SHA-256 and PE structure, and checks that the Authenticode publisher is valid and identifies SOLIDWORKS or Dassault. **It does not execute the installer on Windows.** A mismatch aborts the Mac test.

On a GitHub-hosted Apple Silicon `macos-15` runner, it retrieves the checksum-pinned Wine 11.21 bundle, initializes a disposable x64 Wine prefix, sets the reported OS version to Windows 11, downloads the same private installer, checks its SHA-256 again, and launches the authentic executable once with a bounded 120-second timeout. No command-line serial number, license key, automated EULA acceptance, activation bypass, unsupported silent-install options, or installer binary modification is performed.

The original installer may return, exit with an error or remain in a UI loop and reach the timeout. The only recorded statuses are `EXIT_ZERO`, `EXIT_NONZERO`, `TIMEOUT` or `START_FAILED`. A launched process or a timeout does **not** prove that the Installation Manager UI appeared, that any package was installed, or that CAD geometry works.

The report always marks `installation_manager_ui=NOT_VERIFIED`, `full_installation=NOT_VERIFIED`, `activation=NOT_ATTEMPTED`, `cad_launch=NOT_TESTED`. Interactive installation and license activation require separate authorized testing.

## Local preflight alternative

If you cannot host media privately, run the existing [offline media scanner](INSTALLER_MEDIA_PREFLIGHT.md) on your Windows machine. It reads the local executable without execution and writes sanitized JSON. This is less evidence than an Apple Silicon installer launch, but does not require uploading proprietary software.

## Safeguards

- Only manual workflow dispatch can use genuine installation media. Pull requests and ordinary pushes run synthetic safety tests only and cannot access the installer secrets.
- An authentic executable is downloaded twice, each time over HTTPS with the same SHA-256, and a native Windows job checks the official publisher signature before the Mac job.
- The launch script refuses native-Windows installation, missing disposable-prefix sentinels, uninitialized prefixes, invalid executables or wrong digests. It redirects process output to null to prevent leakage.
- The temporary hosted runners are deleted after completion. Workflow artifacts contain only fixed allowlisted status fields, never executables or broad logs.
- This cannot demonstrate a fully installed SOLIDWORKS GUI on a physical Mac. No Windows VM is used.

See [graphics blocker issue #26](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/issues/26).
