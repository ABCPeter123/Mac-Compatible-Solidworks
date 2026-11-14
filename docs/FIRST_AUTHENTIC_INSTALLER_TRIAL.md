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

## Troubleshooting an HTTP 404 from a private R2 URL

[GitHub Actions run 43492860260](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/actions/runs/43492860260) reached the original-install media download on native Windows but R2 or the configured download endpoint returned **HTTP 404**. The program never downloaded the installer, and the Apple Silicon launch was correctly skipped. A valid SHA-256 does **not** fix a missing object or a broken temporary URL.

Before starting another run, check the private R2 object key on your **own Windows PC**. In PowerShell, using the R2 AWS CLI profile and endpoint created earlier:

```powershell
$endpoint = "https://YOUR_ACCOUNT_ID.r2.cloudflarestorage.com"
$bucket = "swcompat-installer-private"
$key = "SolidworksSetup.exe"

aws s3api head-object --bucket $bucket --key $key `
  --endpoint-url $endpoint --profile swcompat-r2
```

This must succeed. If the returned object is not found, open Cloudflare R2, check the **exact case-sensitive object name and subfolder**, and update `$key` to match. For example, an object uploaded under `downloads/SolidworksSetup.exe` needs `$key = "downloads/SolidworksSetup.exe"`.

Generate a **new** signed GET URL for the confirmed key and endpoint:

```powershell
$url = aws s3 presign "s3://$bucket/$key" `
  --endpoint-url $endpoint --profile swcompat-r2 `
  --region auto --expires-in 21600
```

Verify the actual executable transfer *on your computer* **before** storing the URL in GitHub. This avoids repeatedly starting a CI job for a broken link:

```powershell
$trial = Join-Path $env:TEMP "swcompat-installer-url-test.exe"
try {
    Invoke-WebRequest -Uri $url -OutFile $trial -ErrorAction Stop
    Get-FileHash -Path $trial -Algorithm SHA256
} finally {
    Remove-Item -LiteralPath $trial -ErrorAction SilentlyContinue
}
```

Confirm the calculated hash matches the original installer SHA-256. Never paste the signed `$url`, R2 credentials, installer, or personal license number into a public GitHub issue, commit, or chat.

Update the `SWCOMPAT_INSTALLER_URL` value in **Settings → Secrets and variables → Actions**: delete the existing secret and recreate it with the new complete signed URL, or edit it if GitHub provides that control. Do **not** change `SWCOMPAT_INSTALLER_SHA256` unless you have downloaded a genuinely different installer and calculated its new hash. Re-run the workflow from `main` before the signed URL expires.

The workflow now uses `scripts/solidworks_private_media_fetch.py` on both Windows and Apple Silicon. It distinguishes `HTTP_404_NOT_FOUND`, `HTTP_403_FORBIDDEN`, `PRESIGNED_URL_EXPIRED`, `TRANSPORT_ERROR`, and a successful download in sanitized artifacts. It does not retry a definitive 404 and never prints signed URLs or response bodies. This diagnostic fix cannot make a missing private object available by itself.

## First original installer result and follow-up probe

[Manual Actions run 43494158179](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/actions/runs/43494158179), executed November 13, 2026, **successfully downloaded and verified the genuine SOLIDWORKS installer on Windows** (expected SHA-256 and valid Dassault/SOLIDWORKS Authenticode). On hosted Apple Silicon macOS 15 / Wine 11.21, the **same installer downloaded, passed SHA-256 again, and the original process started**. It remained running until the deliberate **120-second timeout**, then its process group was terminated.

This is the project's first authentic SOLIDWORKS installer process execution, **not a completed installation**. A timeout can represent a UI waiting for input, installation/bootstrapper work, or a hang. No Mac browser pixels or installation manager UI were verified, no activation was attempted, and no CAD functionality was exercised.

The subsequent Win32 window census improves that evidence: while the same authentic process is running, the workflow launches a newly compiled, read-only Windows x64 probe inside the **same Wine prefix**. It enumerates Win32 processes and visible top-level window rectangles, counts probable installer-related processes by a small explicit executable-name allowlist (including the SOLIDWORKS setup and installation manager names), and samples several times. Its output contains only bounded numeric counts. It does not record window titles, window contents, paths, process command lines, screenshots, user/serial data or binaries.

The sanitized diagnostic fields are `installer_window_census`, `census_samples_complete`, `candidate_installer_processes_max`, and `candidate_visible_windows_max`. `CANDIDATE_WINDOW_SEEN` establishes only that the Wine Win32 window API detected a sufficiently large, visible, installer-associated top-level window in the hosted CI environment. It does **not** establish that the window's pixels were painted on a macOS screen. `NO_CANDIDATE_WINDOW_OBSERVED` may miss helper processes or delayed windows and is not proof that installation UI never exists. The `installation_manager_ui` field remains `NOT_VERIFIED` in either case.

## Verified installer window evidence and new responsiveness/pixel diagnostics

[Original installer manual workflow 43497081980](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/actions/runs/43497081980) **passed all four jobs**. The authentic, publisher-verified SOLIDWORKS bootstrapper was downloaded and executed on hosted Apple Silicon Wine. It remained active to the bounded 120-second timeout. Crucially, the original Win32 process/window census reported `CANDIDATE_WINDOW_SEEN`, with a maximum of **one visible, installer-associated HWND**.

That indicates the Wine Win32 window model recognizes a visible top-level window associated with the genuine installer or an installer child process. It does **not** establish that a physical macOS screen displayed the window, that the contents painted, or that SOLIDWORKS installed.

The next read-only diagnostic distinguishes three layers:
- **Window census**: a visible, sufficiently large Win32 installer-associated HWND exists.
- **Message-loop responsiveness**: a `SendMessageTimeoutW(WM_NULL)` returned within one second. This is only an instantaneous liveness signal. It does not prove that installation is progressing or that UI interaction works.
- **GDI client-area variation**: a 32×32 transient, in-memory bitmap sampled from the center of the HWND's client DC via `StretchBlt` contained at least two distinct RGB values (`NONUNIFORM`) or fewer (`UNIFORM`). `READBACK_FAILED` indicates the GDI surface could not be read. This is a coarse surface heuristic, **not** proof that the installer content or any macOS desktop pixels were rendered. No bitmap, RGB values, title, paths or image can leave the diagnostic executable.

Each state is independently exported as a fixed allowlisted enum: `installer_hwnd_responsiveness` and `installer_gdi_client_variation`. `macos_onscreen_pixels` remains `NOT_VERIFIED` even when GDI produces a nonuniform surface. The native Windows CI reference uses a **new original synthetic two-color test HWND** to verify that the probe's own responsiveness and readback algorithm works before we trust its diagnostics on Wine.

## Distinguishing a Wine GDI limitation from an installer-specific one

A later authentic installer run, [#43499104522](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/actions/runs/43499104522), confirmed a **responsive installer-associated Win32 window** (`installer_hwnd_responsiveness=RESPONSIVE`) but client-area GDI readback returned `READBACK_FAILED`. This does not demonstrate a frozen installer, and does not prove the user could see or operate the window on macOS.

The next diagnostic runs our **original, synthetic two-color Win32 test window** under the same pinned Apple Silicon Wine environment **before downloading or executing SOLIDWORKS**. This is separate from the actual proprietary installer trial and has no access to installer contents. Its strict status is recorded as `REFERENCE_PASS`, `REFERENCE_FAILED`, `REFERENCE_TIMEOUT`, `REFERENCE_UNAVAILABLE` or `REFERENCE_UNEXPECTED`.

- If synthetic GDI **passes** while genuine installer client GDI **fails**, investigate that installer's HWND, drawing/composition path, and windowless/child-window surfaces.
- If both **fail**, investigate Wine's general Win32 GDI readback and hosted macOS display environment before drawing installer-specific conclusions.
- In either case, passing GDI tests is **not equivalent to macOS onscreen pixel proof**, rendered or interactive Installation Manager UI, installation completion, activation, or CAD operation.

The reference reports fixed allowlisted statuses. Neither full process output nor user paths, window text, screenshots, serial numbers, or RGB values are retained.

## Confirmed contrast: original installer versus a synthetic Wine GDI window

[Manual workflow #43503360082](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/actions/runs/43503360082) completed with all four jobs passing as **diagnostics** on November 13, 2026. The nonproprietary two-color Win32 HWND self-test reported **`REFERENCE_PASS` directly on hosted Apple Silicon Wine**. The same environment then downloaded and verified the authentic, Dassault/SOLIDWORKS-signed installer. The original installer's process started; one installer-associated window was visible to Win32 enumeration and **responsive** to a bounded message, but GDI `StretchBlt`-based client readback was **`READBACK_FAILED`**. The installer remained open until the deliberate 120-second cutoff.

This establishes that the project's basic Win32 GDI client-area probe works **for a synthetic two-color window in the same hosted Wine configuration**. It does **not** establish macOS desktop pixel presentation or prove that all Wine GDI functionality works for all window types. The remaining failure is likely specific to the original installer's HWND, client geometry, readback method or drawing/surface composition, not a universal GDI absence.

The next diagnostic distinguishes the *first failed API stage* in the original window's GDI readback (`CLIENT_RECT_FAILED`, `CLIENT_TOO_SMALL`, `SOURCE_DC_FAILED`, `MEMORY_DC_FAILED`, `DIB_CREATE_FAILED`, `BITMAP_SELECT_FAILED`, or `STRETCH_BLT_FAILED`). It also independently reads a bounded sample through `GetPixel` and reports only `NONUNIFORM`, `UNIFORM`, or `READBACK_FAILED`. The new result fields are `installer_gdi_failure_stage` and `installer_direct_getpixel`; no actual pixel values, window titles, paths, screenshots, executable bytes, license keys or serials are exported.

The readback controls distinguish acquisition of a DC, copying into a DIB, and reading individual pixels. A synthetic test passing or an installer `GetPixel` returning multiple colors **still does not verify painted macOS window pixels, successful installation, or CAD functionality**.

## Genuine installer Win32 drawing failure and child-window follow-up

The November 13, 2026 user-authorized [manual run #43550466404](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/actions/runs/43550466404) verified the authentic publisher/digest and passed the original synthetic GDI reference on hosted Apple Silicon Wine (`REFERENCE_PASS`). The real installer started with one visible, responsive Win32 window and stayed active to the bounded 120-second timeout. Both direct `GetPixel` and client `StretchBlt` readback failed; the first recorded failed operation was **`STRETCH_BLT_FAILED`**. The window's DC was obtained and a bitmap was created and selected successfully before copying failed. This narrows the original Win32 GDI readback limitation but **does not prove that macOS screen pixels cannot render or that installation is impossible**.

The next diagnostic checks whether content may live on **child HWNDs** of the installer window, potentially an embedded browser or other composed UI. It enumerates at most 128 descendants of each candidate installer HWND, aggregates only visible children with window rectangles at least 100×100, and attempts the same bounded GDI client sample on up to eight child HWNDs total. It also counts the `WS_EX_LAYERED` and `WS_EX_NOREDIRECTIONBITMAP` extended styles on candidate parent/child HWNDs. These are **window-structure hints**, not evidence of the actual graphics backend or successfully painted macOS pixels.

The sanitized statuses are `installer_child_visible_max`, `installer_child_gdi`, `installer_parent_layered_max`, `installer_parent_no_redirection_max`, `installer_child_layered_max` and `installer_child_no_redirection_max`. No child window text, classes, handles, IDs, pixels, screenshots, paths, URLs or serials are uploaded. If a child GDI surface can be read while its parent cannot, investigate which child displays the interface; if all client readbacks fail, investigate Wine compositing/redirection or other native display verification. The workflow does not perform license activation or install SOLIDWORKS.

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
