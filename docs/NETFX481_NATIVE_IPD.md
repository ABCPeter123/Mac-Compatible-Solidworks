# Native KB5011048 IPD reconstruction

The original Microsoft .NET Framework 4.8.1 catalog update contains an IPD CIX cabinet with 2,446 logical files. CI run [45848826050](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/actions/runs/45848826050) reconstructed all files on Windows and Apple Silicon. Windows Expand independently matched every file; both reconstructed trees produced SHA-256 `2f492b8e9cded7ca527860190fc7b6caa9ac25f86ebd6d521efd0dcaa429010b`.

The portable decoder uses the pinned MIT ms-delta source and a bounded local PA30 compatibility adapter. Four difficult deltas were recovered by intrinsic-hash-verified operand variants. The final delta required 56 algorithm selectors synthesized against the native Windows reference. The checked-in selector JSON is bound to the source and patch SHA-256, contains no original binary payload, and requires the original target hash before returning bytes. This is a package-specific compatibility correction, not a claim of general MSDelta compatibility.

The regular Mac path uses the checked-in recipe and does not call Windows or synthesize recipes. Windows remains an independent regression oracle. Explicit research-only synthesis requires Windows Expand and a separate writable recipe directory. The complete-tree gate is mandatory for this exact package.

## Scope

This milestone proves decompression, not installation. The current inspector keeps reconstructed files in a temporary private directory and removes them at exit. The next integration must safely materialize the original manifest paths for Wine servicing, retain the original package/catalog integrity and independently verify restarted native .NET 4.8.1. No SOLIDWORKS installation is claimed.

## Read-only servicing preflight

PR #278 adds explicit private staging and a separate dry-run-only probe built from Wine 11.13's LGPL WUSA source. The source is pinned by Git blob identity. The host checks the original MSU and the verified complete CIX tree immediately before invoking the probe. The probe substitutes the stage only when Wine's original cabinet scan finds the IPD marker; the original outer update XML and Wine's manifest/dependency processing are retained. The normal installation pass is removed, and only aggregate fixed-category errors are reported. This is not a replacement system WUSA, complete CBS implementation, signature verifier, or proof of a successful install. The current CI tests the pinned Wiage runtime in an isolated macOS 26 prefix, without installing Microsoft .NET or modifying a user prefix. Once the preflight is verified, resolve any actual manifest, dependency, file-path, or registry-expression gaps before allowing any installation trial.

## Native CLR4 baseline reliability

The original Microsoft CLR4 setup produced a verified persistent native runtime on run 45954548511, followed by intermittent exact 1603 failures without CLR files on the same macOS 26 runner image. The successful IPD transaction subsequently registered all 274 original GAC payloads and passed native managed execution. Repeating the same failed configuration does not isolate a cause.

The experimental IPD-only fresh retry now disables Wiage's optional MSYNC backend (see https://github.com/dttdrv/mage). It changes the environment only after the existing exact 1603 gate has safely stopped and archived the first disposable Wine session, before initializing the new prefix. All later Wine clients and the new server retain the same setting. The normal first attempt and signed MSP retry are unchanged. This is a controlled synchronization hypothesis, not a demonstrated fix, and no native runtime acceptance criteria change.

## Reproduced native runtime and CAD subsystem evidence

Run [46048206725](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/actions/runs/46048206725) repeated native original 4.8.1 servicing and all 274 GAC registrations, with exact original CLR/MSCorLib bytes in both architectures. The native-only CAD matrix passed x86/x64 core execution, WinForms bitmap rendering, WCF binding/serialization and COM automation (8/10 tests). Both WPF tests produced INVALID_OUTPUT, not a diagnosed rendering defect. The original Win32 GDI control was refused before launch because its separate disposable marker was created only in the later WebView2 step. Corrected marker ordering and added private, fixed-stage WPF diagnostics. WebView2 and full SOLIDWORKS remain unverified.

## Same-prefix browser rendering integration

Earlier independent WebView2 runs on Apple Silicon Wine 11.21 demonstrated a real controller, DOM execution and Canvas 2D, but not browser window pixels. The integrated experiment now compiles and reuses that original render probe in the actual IPD-serviced native CLR prefix, after the existing official signed Evergreen installation/controller gate. The default browser environment is retained, rather than disabling GPU acceleration, and no browser security options are changed. The existing strict classifier distinguishes verified screenshot/GDI pixels, the explicitly known capture blocker, and unexpected failures. Local probe output and the synthetic PNG remain private. Only sanitized evidence is uploaded. Full SOLIDWORKS is still unverified.

Run 46052072867 verified native GDI and both WPF probes reached COPIED with zero exit, but strict stdout packets remained invalid. A separate fresh result file now avoids mixing GUI diagnostics and protocol bytes. Integrated WebView2 returned nonzero with no browser discovery; the original bounded Windows process launcher now captures the complete DWORD rather than a Unix-truncated exit code. No installation or readiness gate is weakened. Independent run 46054288261 had ready browser and Canvas after timeout, which is not a verified successful installer transaction.
