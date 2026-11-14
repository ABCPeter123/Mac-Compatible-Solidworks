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

[GitHub Actions run 43561243779](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/actions/runs/43561243779) downloaded the publisher-verified Microsoft installer and executed it inside disposable Apple Silicon Wine 11.21. The installer returned EXIT_ZERO, the registry reported .NET 4.8.1 or higher, and independent managed tasks/XML/SHA-256 completed. The sanitized artifact also shows that **before the Microsoft installer ran**, the disposable Wine prefix already reported .NET 4.8.1 in the registry while executing the managed fixture under Mono. **After setup**, both indicators remained unchanged. But the managed fixture reported **MONO** as the runtime actually executing the code. Therefore **framework_runtime_ready was FALSE**. This is concrete evidence that installer status and registry state can be misleading under Wine. The Microsoft CLR has not yet been proven to run.

## Controlled correction for a false pre-existing 4.8.1 indicator

The first genuine run exposed a probable short-circuit: the original Microsoft setup returned EXIT_ZERO but Wine's initial registry had already claimed .NET 4.8.1 and it still used Wine Mono afterward. This can cause setup to skip the actual framework payload.

The revised trial explicitly requests --experiment-clear-false-release, which is allowed **only** inside a prefix containing the .swcompat-netfx481-disposable sentinel. The script removes **only** the Release value below HKLM\Software\Microsoft\NET Framework Setup\NDP\v4\Full, and only when the initial independent fixture observed both AT_LEAST_481 and MONO. It then runs a second registry query and proceeds with the original Microsoft installer only if that specific value is absent. If deletion fails or the value remains present, setup is skipped and the exact fixed failure classification is reported.

Nothing about SOLIDWORKS licensing, system activation, native host macOS registry state, unrelated Wine keys, Windows code signing, or original executable bytes is modified. Do **not** use this experimental key correction in a long-lived user's Wine prefix. Clearing the indicator is a diagnostic method, not a compatibility guarantee; it might disrupt Wine Mono's existing registration.

## Native CLR loading A/B experiment

The follow-up run now launches the same self-authored managed executable after installation in three independent processes, without altering the original Microsoft installer or changing the prefix's global DLL preferences:

1. Wine default DLL resolution: existing Mono-first behavior.
2. Native DLL preference using `WINEDLLOVERRIDES=mscoree=n,b;clr=n,b`.
3. Native DLL only using `WINEDLLOVERRIDES=mscoree=n;clr=n`.

The report exposes `after_native_first` and `after_native_only` plus separate readiness booleans. These scoped environment settings are a hypothesis to investigate, not a compatibility fix until the managed fixture actually executes with a Microsoft CLR candidate. An apparent success still needs stronger Microsoft DLL identity verification and SOLIDWORKS-specific managed COM tests.

## Follow-up: Windows 10 reported-version profile for Framework setup

The initial run found Wine 11.21 reporting .NET 4.8.1 before any genuine Microsoft installation. Removing that one fake Release indicator in a disposable prefix allowed setup to run, but its original executable still returned EXIT_ZERO without providing a native CLR: the registry remained NOT_FOUND and Mono handled managed execution.

The next experiment changes **only the disposable Wine prefix's reported Windows version** from Windows 11 to Windows 10 during genuine Microsoft .NET Framework 4.8.1 setup. Windows 10 is a target platform for the framework installer, unlike the Windows 11 profile which may cause setup to assume the framework is built into Windows already. The same scoped false-release correction runs before setup. After the experiment, the workflow **restores Windows 11** using Wine configuration and reruns the original managed CLR probe.

The sanitized evidence separately reports install_os_profile=WIN10_REPORTED, post_restore_os_profile=WIN11_REPORTED and post_restore_framework_ready. A failure to restore the Win11 profile or capture both results fails the workflow, rather than leaving an apparently ready but unsupported setup. This is an original Microsoft installer experiment only, with no SOLIDWORKS proprietary code, activation or serial.

## Windows 10 installation-profile results, November 14, 2026

[GitHub Actions run 43562117555](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/actions/runs/43562117555) confirmed that the temporary Windows 10 profile was applied for the original Microsoft installer, and the disposable prefix was restored to Windows 11 afterward. The misleading Release indicator was successfully removed before setup.

However, the genuine Microsoft .NET Framework 4.8.1 installer still returned EXIT_ZERO without providing the native CLR. The independent probe afterward reported registry NOT_FOUND, CLR family MONO and managed test PASS; native-first loading remained MONO, native-only loading was NOT_VERIFIED, and the post-restore Windows 11 readiness result was FALSE.

The Windows 10 reported-version hypothesis did not fix the dependency. Further work must identify why Microsoft's installer short-circuits without deploying a usable CLR. Changes to a normal long-lived Mac user prefix are not justified by this result.

## Next fix candidate: separate 32-bit Wine Mono registry view

Winetricks [issue #2367](https://github.com/Winetricks/winetricks/issues/2367) identifies an additional `Wow6432Node` .NET Framework registry key left in Wine-derived prefixes which causes Microsoft Framework installers to refuse or skip the actual install. Our prior tests removed only the 64-bit `Release` indicator. That did not prove the 32-bit registry view was clean.

The new opt-in experiment also inspects `HKLM\\Software\\Wow6432Node\\Microsoft\\NET Framework Setup\\NDP\\v4\\Full` for a `Release` value. It runs only in a marked disposable prefix and only when the independent managed fixture proves Wine Mono is active while the normal registry view falsely reports .NET 4.8.1. It deletes only that individual `Release` value, confirms it is absent with a second Windows registry query, and then launches the original signed Microsoft installer. If the key is absent, it reports NOT_NEEDED and continues. If a query, deletion or verification fails, it refuses to launch the installer.

The report contains only the enums `before`, `action`, and `after`; it includes no raw registry contents, user paths or Microsoft binaries. This is a targeted reproducible test, not a promise that .NET 4.8.1 now installs. Do not run it on your normal persistent SOLIDWORKS Wine prefix.

## Remove Wine Mono itself before attempting native Microsoft .NET

The [upstream Wine Mono README](https://github.com/wine-mono/wine-mono) explicitly states Wine Mono must be removed before installing .NET Framework 4.8.1 and earlier. Wine Mono installs misleading Framework registry entries and Windows Support files intentionally, to prevent Framework installers from replacing its implementation. Our earlier attempts removed registry values but **never uninstalled Wine Mono's actual MSI package**. This was an incomplete prerequisite procedure.

The new controlled experiment enumerates Wine's registered programs using its own `uninstaller --list` interface and requires a structurally valid MSI product GUID with one of exactly three known descriptions: Wine Mono Windows Support, Wine Mono Runtime, Wine Mono. It invokes `wine uninstaller --remove <GUID>` on those products only, then re-enumerates and requires that no registered Wine Mono MSI remains. The original Microsoft 4.8.1 setup is skipped if enumeration fails, an unknown entry is observed, uninstallation fails, or any Wine Mono product remains.

This is a destructive runtime replacement and is therefore permitted only in a newly initialized, marked, **disposable** Wine prefix used exclusively by GitHub CI. It is not offered as a modification to a real user's existing SOLIDWORKS installation. The original Microsoft-signed package remains unmodified and checksum-verified, and post-install verification still requires actual Microsoft CLR candidate execution rather than exit code zero.

No raw uninstaller output, Microsoft installer logs, paths, MSI GUIDs, hashes or product serials are uploaded in the JSON result. Only action enums and counts are reported.

## Technical boundaries

The independent fixture does not test every SOLIDWORKS managed feature or COM interop, and running Microsoft's CLR under Wine would still not establish CAD readiness. WebView2 browser pixels, native graphics/window composition, installation manager UI, x86 helper processes and activation remain separate compatibility gates.

Run manually through [the dedicated GitHub Actions workflow](../.github/workflows/netfx481-wine-ci.yml), or inspect its pull-request validation results.
