# Official WebView2 Evergreen runtime installation trial

The previous [WebView2 environment/controller experiment](WEBVIEW2_CONTROLLER.md) showed that the same original Windows x64 executable creates a real browser controller on native Windows but cannot discover a runtime in fresh Linux Wine or Apple Silicon Wine prefixes. The next question is whether installing Microsoft's supported, unmodified WebView2 Runtime resolves that missing dependency.

## Exactly what this tests

The [Evergreen runtime installation workflow](../.github/workflows/webview2-runtime-install-ci.yml) obtains the official Windows x64 **Evergreen Standalone Installer**, not the online bootstrapper, from:

https://go.microsoft.com/fwlink/?linkid=2124701

On a GitHub-hosted Windows runner, it validates the complete installer using Windows Authenticode, checks for a **valid Microsoft Corporation publisher signature**, and saves the exact downloaded SHA-256. A Windows x64 controller probe is built from source against the previously pinned Microsoft.Web.WebView2 SDK 1.0.4314.35 and verified SDK loader.

The workflow uploads the verified installer, matching digest, original controller probe and loader as a short-lived CI artifact, **never commits these binaries to the repository**. Wine hosts check that exact digest again before executing it. Evergreen binaries change as Microsoft updates the runtime. Consequently the digest is pinned *per workflow run*, not permanently pinned to a stale Evergreen version. This also avoids substituting an unrelated third-party mirror.

Each Linux Wine and Apple Silicon Wine job:

1. Initializes a new Wine prefix in the runner's temporary directory and adds a marker allowing installation only inside that disposable prefix.
2. Executes the original WebView2 environment/controller probe **before** installation.
3. Invokes Microsoft's official standalone installer with the documented /silent /install arguments, without touching host Windows or a user's existing Wine prefix.
4. Records whether the installer's process returned 0, a nonzero status, failed to start, or exceeded a bounded timeout. The shell does not rely on the installer's exit code alone.
5. Runs the same controller probe **after** the attempt and checks the actual browser-runtime discovery, COM environment callback, and controller creation.
6. Uploads only a fixed-schema, sanitized JSON report. No raw installer logs, versions, paths or user data are exported.

The original controller executable runs against the official WebView2 SDK and DLL. The installer is never modified. The test does not patch Wine's security checks or circumvent Microsoft or SOLIDWORKS licensing.

## Verified results, November 12, 2026

[GitHub Actions run 43346665424](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/actions/runs/43346665424) completed its Windows-source verification, Ubuntu Wine installation attempt and Apple Silicon Wine installation attempt.

| Host | Installer execution | Runtime before | Runtime after | Environment after | Controller after |
| --- | --- | --- | --- | --- | --- |
| Ubuntu 24.04 Wine | EXIT_NONZERO, exit code 1 | NOT_DISCOVERED | NOT_DISCOVERED | REQUEST_FAILED | NOT_REACHED |
| Apple Silicon macOS 15 Wine 11.21 | EXIT_ZERO, exit code 0 | NOT_DISCOVERED | VERSION_FOUND | READY | READY |

**Apple Silicon finding:** The genuine, publisher-verified Microsoft WebView2 Evergreen x64 standalone installer succeeded in a fresh Wine prefix, and a real WebView2 controller was created afterward. This is a positive Microsoft WebView2 runtime compatibility result, stronger than merely loading its SDK DLL.

**Linux finding:** The same installer failed with exit code 1 on this Ubuntu Wine configuration, and the runtime/controller state did not change. This does not establish why the installer failed or whether an alternative Wine configuration would succeed.

The exact official x64 installer used in this run was **215,195,856 bytes**, SHA-256:

    1d1c838e5971343c060415da7c630c3c1ca7ad33fbb61cca660f3c1122f4cca8

The Windows CI runner verified that the file's Authenticode signature was valid and signed by Microsoft Corporation. The archive is not committed to the repository, and Microsoft may update the Evergreen download link to newer, different bytes.

No HTML page rendering, JavaScript execution, real end-user input, SOLIDWORKS installation, activation or CAD editing was demonstrated in this test.

## Status semantics

A CI job returning success means only that both independent WebView2 probes produced coherent diagnostics. A **successful installer** is not assumed from a zero exit code or from a green CI job.

- installer_execution: EXIT_ZERO, EXIT_NONZERO, TIMEOUT, or PROCESS_ERROR.
- runtime_installation_confirmed: true only if the installer exited zero, the first probe found no runtime, and the second probe found a runtime. This is still a diagnostic attribution, not proof that all browser components are operational.
- browser_controller_confirmed: true only if the second probe actually returned a READY controller, rather than merely finding a browser version.
- controller_transition: captures whether a controller became usable, remained usable, remained unavailable, regressed, or produced incomplete evidence.
- html_rendering: NOT_TESTED, even with a READY controller.
- solidworks_compatibility: always NOT_DEMONSTRATED.

On a runner that already has a runtime, the script will not attribute it to the installer. If either before/after probe fails or exits abnormally, the trial fails its CI job rather than reporting misleading results.

## Safety and reproducibility

The experiment only runs on disposable Wine prefixes. Manual invocation requires --agree-disposable-prefix, an initialized Wine prefix, and the literal .swcompat-webview2-disposable marker within that prefix. The installer must match a full SHA-256 digest file, have the expected standalone size, and come from a trusted source. The CLI alone does **not** independently verify Authenticode; the CI's native Windows verification step supplies that precondition.

Microsoft documents these standalone installer arguments and the distinction between per-user and elevated installs. Wine may fail earlier because of missing Windows services, registry conventions, runtime dependencies or graphical capabilities. A negative result requires investigation and is not proof of an irreparable problem.

## Next acceptance gate

If the official runtime installer fails or the environment still cannot start, inspect bounded installer return codes and Wine runtime diagnostics. Prioritize one actual failure category at a time. Do not claim SOLIDWORKS macOS compatibility until its legitimate installation, activation and part-editing workflow pass on a suitable Mac.

Microsoft primary reference: [Distribute your app and the WebView2 Runtime](https://learn.microsoft.com/en-us/microsoft-edge/webview2/concepts/distribution).
