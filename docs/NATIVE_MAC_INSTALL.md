# Local SOLIDWORKS installer on macOS (experimental, no VM)

This is the **local Mac/Wine** route, not Remote Desktop. It uses the original SOLIDWORKS installation media and an isolated, **persistent** Wine prefix. It is a practical interactive installation entry point; it does **not** establish that SOLIDWORKS 2026 installs, activates or performs CAD successfully under Wine.

## Requirements

- A Mac with macOS and working x86-64-capable Wine. On Apple Silicon, install Rosetta 2 if your Wine build requires it. Use a Wine distribution compatible with your specific Mac and macOS version. Example installation: `brew install --cask wine@staging`. Our hosted diagnostic uses Wine 11.21, but that pinned CI package is not automatically installed by this local workflow.
- Python 3.10 or newer, the repository cloned locally, and ample free disk space for the actual full SOLIDWORKS installation media.
- An appropriately licensed **original SOLIDWORKS installation image** obtained by you directly from Dassault Systèmes. We recommend *downloaded/extracted complete media*, not only the small `SolidworksSetup.exe` web bootstrapper. Check your product version and entitlement.
- A local graphical login session. GitHub's hosted headless Mac runner is not an alternative to personally stepping through the installer.

## Use on your Mac

Open Terminal in the repository directory and inspect the media first:

```bash
python3 -m swcompat native-audit "/Users/you/Downloads/SOLIDWORKS_MEDIA"
```

The audit reports fixed status keys for the installer launcher and the official prerequisite **files**. It deliberately does not print paths, serial numbers, installers, hashes or arbitrary package data. `PRESENT` means the expected filename exists, not that the executable is genuine, installed or functional. Verify the media source yourself.

Then start the local interactive installation session:

```bash
python3 -m swcompat native-install "/Users/you/Downloads/SOLIDWORKS_MEDIA"
```

That command:

1. Creates a **persistent** isolated Wine prefix at `~/Library/Application Support/SWCompat/prefixes/solidworks-lab` if it does not exist. It initializes the Wine prefix and sets reported Windows 11 on first creation; it never deletes an existing prefix.
2. Leaves prerequisite installation to the original SOLIDWORKS Installation Manager by default. If the genuine image includes every named package and you explicitly choose `--install-prerequisites`, runs the original x64/x86 Visual C++, .NET Framework 4.8.1, WebView2, VBA, and SWCEF installers **one at a time with interactive dialogs**. It does not supply command-line EULA acceptance, license data, activation workarounds or modifications to binaries.
3. With this optional advanced prerequisite mode, stops at the first nonzero prerequisite installer exit. Even zero is **not** proof that a runtime is functional, especially with .NET 4.8.1 and Wine. Genuine Windows 11 images may omit the standalone .NET installer because Windows already includes it, but Wine does not become Windows 11 merely by reporting its version. If any required media file is absent, use the normal original Installation Manager launch instead.
4. Launches the original setup executable **from its media directory** so sibling payloads and relative paths can resolve. The process has **no artificial 120-second timeout**. It waits for the setup launcher to exit rather than terminating the user after an arbitrary CI deadline.
5. Saves diagnostic output **locally** under `~/Library/Logs/SWCompat`, never uploads installation output or personal details.

Manual prerequisite installation is an **advanced, opt-in** troubleshooting path. Invoke `python3 -m swcompat native-install "/Users/you/Downloads/SOLIDWORKS_MEDIA" --install-prerequisites` only when using complete official administrative media and after you understand which prerequisites you intend to install. If expected packages are absent or ambiguous, this mode stops before executing anything. The normal command does *not* verify installed prerequisites; the runtime may still be missing.

For the small official web bootstrapper, the script intentionally requires explicit permission because it usually cannot perform a complete offline installation:

```bash
python3 -m swcompat native-install "/Users/you/Downloads/SolidworksSetup.exe" --permit-bootstrapper
```

It may need to download further files, request license details through the original SOLIDWORKS interface and fail under Wine. The program does not handle or store the serial.


## Verify actual WebView2 operation before SOLIDWORKS

The installer needs Windows-compatible browser services. A registry entry or a downloaded Microsoft package is **not sufficient** to prove these services work under Wine. The project now provides a local, functional WebView2 setup and controller test in the **same persistent Wine prefix** that the original SOLIDWORKS installer uses.

1. Obtain the official **Microsoft Edge WebView2 Evergreen Standalone x64 Installer** directly from Microsoft's [WebView2 download page](https://developer.microsoft.com/en-us/microsoft-edge/webview2/). Do not use an untrusted mirror. Keep the original name.
2. Obtain our independently built, original Windows x64 \`webview2_controller_probe.exe\` alongside the official SDK \`WebView2Loader.dll\` from the \`signed-webview2-evergreen-x64-and-controller\` artifact of the [WebView2 runtime CI workflow](../.github/workflows/webview2-runtime-install-ci.yml). The workflow pins the official SDK and verifies the Microsoft publisher signature before producing the artifact. These are not SOLIDWORKS binaries; the artifact expires quickly and may need a new authorized CI run.
3. Pin the hash of your downloaded official runtime file:

   \`\`\`bash
   shasum -a 256 "/path/to/MicrosoftEdgeWebView2RuntimeInstallerX64.exe" | awk '{print $1}' > /path/to/evergreen-installer.sha256
   \`\`\`

   This verifies local file integrity against your recorded digest, **not Microsoft Authenticode**. The local macOS command does not authenticate Microsoft's signature itself; official download provenance and the Windows CI signature verification remain separate.
4. Prepare and test the actual persistent Mac Wine prefix using the original Microsoft executable:

   \`\`\`bash
   python3 -m swcompat native-webview2 \
     --installer "/path/to/MicrosoftEdgeWebView2RuntimeInstallerX64.exe" \
     --sha256-file "/path/to/evergreen-installer.sha256" \
     --probe "/path/to/webview2_controller_probe.exe"
   \`\`\`

   If already functional, it returns \`ALREADY_READY\` without reinstalling. Otherwise it attempts Microsoft's documented silent runtime installer and then runs the independent Windows x64 COM controller probe. A zero installer exit alone is never considered success.
5. When the result is \`READY\`, use an optional fail-closed gate on the original SOLIDWORKS Installation Manager launch:

   \`\`\`bash
   python3 -m swcompat native-install "/path/to/SOLIDWORKS_MEDIA" \
     --require-webview2-probe "/path/to/webview2_controller_probe.exe"
   \`\`\`

This tests real WebView2 environment and controller creation, not actual browser pixels, installer UI, working .NET Framework 4.8.1, activation, or CAD. The runtime report contains only fixed status values in a private local JSON under \`~/Library/Logs/SWCompat\`. The official Microsoft executable stays on your machine.

### Windows Installer path correction

Optional MSI prerequisite installation now converts each actual macOS media path to an **absolute Windows drive path** using Wine's \`winepath\` before invoking \`msiexec.exe\`. A verified \`Z:\` mapping may be used only when the Wine prefix really maps that drive to \`/\`. If neither can resolve the path, the installer stops rather than silently passing an invalid Unix file path. The older \`swcompat launch <package.msi>\` path receives the same correction.

## Important compatibility blockers

Dassault's 2026 guide requires .NET Framework 4.8.1 and both the 32-bit and 64-bit Visual C++ 2022 redistributables; it also identifies WebView2, Visual Basic, SWCEF and other prerequisites. Some installers assume real Windows OS components that Wine may not implement correctly. A successful file scan or process launch is **not** a runtime capability test.

Official prerequisite reference: https://help.solidworks.com/2026/english/Installation/install_guide/c_prep_clients_admin_images.htm

The official SOLIDWORKS application remains supported for Windows, not macOS. The project has not verified an interactive Installation Manager, complete installation, activation or any usable CAD operation on a Mac. Tests for this new local code run on GitHub macOS and Linux using **synthetic files/mocked Wine**, not proprietary product code.

## Next technical gate

After an authorized person runs this on an actual interactive Mac, determine which actual prerequisite installer, Windows API, renderer or activation-independent process first fails. A future candidate fix must be measured against that concrete blocker, then tested through the same public synthetic CI and private, licensed real-product workflow. We will not classify an installer exit status as working SOLIDWORKS.
