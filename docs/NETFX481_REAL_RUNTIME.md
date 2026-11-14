# Genuine Microsoft .NET Framework 4.8.1 on Apple Silicon Wine

SOLIDWORKS Design 2026 requires .NET Framework 4.8.1. Earlier Wine managed-code tests passed with Wine Mono, which is not proof of Microsoft's runtime compatibility.

## Authentic components and provenance

The [official .NET 4.8.1 download page](https://dotnet.microsoft.com/en-us/download/dotnet-framework/net481) offers an offline runtime installer. The [dedicated experiment workflow](../.github/workflows/netfx481-wine-ci.yml) downloads the original English package directly from Microsoft's download domain and checks Authenticode is Valid with Microsoft Corporation as the publisher. It also pins the full SHA-256 for that workflow run.

An independent Windows x64 runtime fixture is compiled from probes/netfx481_runtime_probe.cs using Microsoft's C# compiler on a Windows runner. Only official Microsoft installer, checksum and self-authored executable are staged into a short-lived GitHub Actions artifact. No SOLIDWORKS media, serial, activation or license material is used.

## Actual Mac test and evidence

The Apple Silicon macOS runner initializes a new marked disposable Win64 Wine prefix, sets Wine's Windows 11 reported version, and runs the managed fixture before and after the unmodified Microsoft offline installer with bounded /q /norestart arguments. The script never supplies /AcceptEULA and does not claim to accept license terms on behalf of the user.

The fixture distinguishes three requirements:

1. Registry Release at least 533320, a VERSION INDICATOR, never sufficient proof.
2. CLR identity. If Mono.Runtime is exposed, it is MONO. Otherwise CLR v4 is MICROSOFT_CLR_CANDIDATE, not cryptographic proof of Microsoft's code.
3. Actual managed task, XML parsing, hashing and runtime execution, marked PASS or FAIL.

Only all three passing results in framework_runtime_ready=true. A zero installer exit, Wine Mono executing managed code or a simulated registry key cannot independently count as a successful real .NET 4.8.1 installation.

Original installer failure or timeout remains a valid diagnostic outcome. GitHub Actions can be green when framework_runtime_ready=false, because test infrastructure worked and revealed a real compatibility blocker.

No proprietary data, raw Windows installer logs, user file paths, registry contents, serial numbers or original Microsoft binaries are stored in the sanitized report. Only fixed schema statuses are retained.

## First genuine Apple Silicon result, November 14, 2026

[GitHub Actions run 43561243779](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/actions/runs/43561243779) downloaded the publisher-verified Microsoft installer and executed it inside disposable Apple Silicon Wine 11.21. The installer returned EXIT_ZERO, the registry reported .NET 4.8.1 or higher, and independent managed tasks/XML/SHA-256 completed. But the managed fixture reported **MONO** as the runtime actually executing the code. Therefore **framework_runtime_ready was FALSE**. This is concrete evidence that installer status and registry state can be misleading under Wine. The Microsoft CLR has not yet been proven to run.

## Native CLR loading A/B experiment

The follow-up run now launches the same self-authored managed executable after installation in three independent processes, without altering the original Microsoft installer or changing the prefix's global DLL preferences:

1. Wine default DLL resolution: existing Mono-first behavior.
2. Native DLL preference using `WINEDLLOVERRIDES=mscoree=n,b;clr=n,b`.
3. Native DLL only using `WINEDLLOVERRIDES=mscoree=n;clr=n`.

The report exposes `after_native_first` and `after_native_only` plus separate readiness booleans. These scoped environment settings are a hypothesis to investigate, not a compatibility fix until the managed fixture actually executes with a Microsoft CLR candidate. An apparent success still needs stronger Microsoft DLL identity verification and SOLIDWORKS-specific managed COM tests.

## Technical boundaries

The independent fixture does not test every SOLIDWORKS managed feature or COM interop, and running Microsoft's CLR under Wine would still not establish CAD readiness. WebView2 browser pixels, native graphics/window composition, installation manager UI, x86 helper processes and activation remain separate compatibility gates.

Run manually through [the dedicated GitHub Actions workflow](../.github/workflows/netfx481-wine-ci.yml), or inspect its pull-request validation results.
