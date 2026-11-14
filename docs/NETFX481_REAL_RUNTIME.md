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

## Verified Wine Mono MSI removal and the possible reboot result

The complete [Apple Silicon original-Microsoft setup run 43563308094](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/actions/runs/43563308094) verified both fake Release values were cleared, successfully uninstalled **one registered Wine Mono MSI**, and confirmed there were **zero** remaining registered Wine Mono packages. Unlike prior runs, it reached actual Microsoft Framework setup with Mono's support package removed.

The original Microsoft installer returned raw Unix-side subprocess status **194**, which the existing trial reported as EXIT_NONZERO. The true Windows code **3010** (success, restart required) reduces to 194 when truncated to the lower eight Unix exit-status bits, but raw 194 alone is **not proof** the Windows code was 3010. Microsoft documents 3010 as successful installation requiring a restart. The existing trial did not simulate that restart before its managed verification.

After setup, the managed fixture still executed with Mono, the Framework registry Release was NOT_FOUND and Microsoft CLR readiness was FALSE. The next test should perform an isolated Wine reboot using the supported `wineboot --restart` command when raw status 194 is observed, then retest native CLR identity and real managed operations. A reboot is not considered success unless the independent CLR readiness gate passes.

## Actual Wine reboot experiment for possible native .NET 3010

The completed [genuine signed Microsoft setup run 43563308094](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/actions/runs/43563308094) verified Wine Mono's Windows Support MSI was removed and both false registry Release values were cleared. The native Microsoft installer subsequently returned **Unix process status 194**, without establishing a working Microsoft CLR before any simulated reboot.

Microsoft's [Framework installer deployment guide](https://learn.microsoft.com/en-us/dotnet/framework/deployment/deployment-guide-for-developers#return-codes) defines Windows code **3010** as successful installation requiring a restart. The low eight bits of 3010 are **194**. Because Unix Wine process exit status may be truncated, **194 is only a possible indication of 3010**, not authoritative proof. The original Windows return code is not recovered.

The revised isolated experiment takes this specific signal and performs Wine's documented `wineboot --restart` operation against the **same marked disposable Wine prefix**, under a strict timeout, after verifying that Wine Mono's registered MSI was removed. It **does not restart macOS**. If the executable is absent, times out or fails, the status is recorded and cannot count as successful installation. On completion, the independent native Microsoft CLR / registry / managed runtime fixture is executed again before restoring the Wine prefix's reported Windows 11 version. The existing workflow then restores Windows 11 and probes the managed runtime one final time.

All statuses are fixed-schema enums with no raw installer logs, executable names, paths, serial numbers or contents of the Microsoft installer. The only positive criterion is actual Microsoft CLR candidate operation plus required registry and managed fixture checks after a confirmed Wine restart. The restart does not establish compatibility on its own.

## First real reboot trial and Wine packaging correction

[Mac run 43563699814](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/actions/runs/43563699814) found possible truncated code 3010 (Unix status 194) following successful Wine Mono MSI uninstallation and false registry cleanup, but reported WINEBOOT_MISSING. The macOS Wine application bundle exposes the Wine launch executable without the sibling Unix wineboot wrapper expected by the initial code. No restart happened. The native CLR remained unverified and Mono still handled managed code.

The next run falls back to the standard built-in Windows command `wine wineboot.exe --restart` when the Unix wineboot executable is missing. The fallback has the same strict disposable-prefix marker, bounded runtime, no raw logs and post-restart independent CLR verification. This is still not an assertion that 194 came from true Windows return 3010.

## Final simulated reboot result, November 14, 2026

[GitHub Actions run 43564239857](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/actions/runs/43564239857) validated the updated macOS Wine restart command. The exact sequence was: both registry Release indicators CLEARED, Wine Mono MSI REMOVED, original signed Microsoft 4.8.1 installer returned raw Unix status 194, and Wine's built-in `wineboot.exe --restart` reported **COMPLETED**.

After the actual simulated restart, the independent C# fixture still reported Wine Mono, registry Release NOT_FOUND, and Microsoft CLR readiness FALSE. After restoring the Windows 11 reported version, readiness was still FALSE. Therefore a missing Wine restart **does not explain** why the genuine Microsoft 4.8.1 installer fails to establish the native CLR in this environment. Unix status 194 remains ambiguous; it cannot be promoted into a Windows 3010 success claim.

The next investigation must collect and classify the failing **internal Microsoft installer or CBS/MSI phase** in a private disposable prefix, or test an upstream-supported Winetricks Framework staging chain with a properly isolated native Microsoft runtime. Avoid additional global registry fixes, removing authentic Windows components, or calling SOLIDWORKS compatible based on diagnostics.

## Direct original Microsoft installer error-phase classification

After the verified Wine Mono MSI removal, both 32-bit and 64-bit fake Release cleanup, and a completed Wine reboot, the genuine Microsoft 4.8.1 installer still returns a nonzero Unix status (194) and does not establish a usable Microsoft CLR. Registry, Mono and reboot experiments cannot identify which internal Windows installation phase failed.

Microsoft officially documents the .NET Framework redistributable `/log file` option in its [deployment guide](https://learn.microsoft.com/en-us/dotnet/framework/deployment/deployment-guide-for-developers#command-line-options) and lists setup logs in its [administrator troubleshooting guide](https://learn.microsoft.com/en-us/dotnet/framework/deployment/guide-for-administrators#log-file-locations). The next Apple Silicon CI trial explicitly sends `/log C:\\swcompat-netfx481-private\\framework-setup.txt` with the original authenticated Microsoft installer. The log resides **only** under the marked, disposable Wine prefix on the GitHub runner.

`scripts/netfx481_setup_evidence.py` scans at most 8 MiB from that exact file, recognizes only preapproved public Windows error categories and broad installation phases, emits **only** three fixed-schema fields (`status`, `phase`, `codes`), and discards the original log from the short-lived prefix. No raw text, paths, person names, Windows installer messages, system identifiers or complete Microsoft logs are printed or uploaded. Unknown lines and unknown error codes produce no details. A missing or invalid log is recorded as a negative diagnostic signal, never as installation success.

Allowed phases are servicing, Windows Installer/MSI, extraction, prerequisites, reboot, and unknown. The classifier counts only lines explicitly reporting failures/errors/results. Broad keywords are hints, not proof of which specific Wine API failed. A category matching an error code does not establish root cause without a focused reproduction. The existing independent Microsoft CLR and managed-code readiness gates remain unchanged.

This experimental `/log` option is opt-in, requires successful Wine Mono removal, and is not enabled for a user's existing long-lived Wine prefix. The CI artifact contains the sanitized report only, never the original installer transcript.

## First original Microsoft `/log` result, November 14, 2026

[Real Apple Silicon CI run 43612965379](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/actions/runs/43612965379) validated that Microsoft's original signed .NET Framework installer did produce a private transcript at the explicit Windows `/log` destination. The classifier returned **CLASSIFIED**, but did **not** find an allowlisted error code or identifiable servicing/MSI/extraction/prerequisite stage; the fixed evidence fields were `phase=UNKNOWN` and `codes=[]`. The original setup still returned EXIT_NONZERO, and the independent Microsoft CLR / Windows 11 post-restore readiness checks remained FALSE.

This is a successful diagnostic collection but NOT an identified installer root cause. It is possible the main transcript only covers the outer bootstrapper; Microsoft documents additional internal setup logs under Windows `%TEMP%`. A subsequent experiment should inspect those files only in a marked disposable Wine prefix and continue to upload exclusively fixed-schema, nonverbatim results.

## Follow-up: classify Windows TEMP and CBS logs from the original Microsoft setup

The original `/log` trial captured the main transcript, but its allowed failure categories were empty (`phase=UNKNOWN`). Microsoft's .NET deployment guide documents additional setup logs in `%TEMP%`, and standard servicing diagnostics appear in Windows CBS logs. Some failure stages do not appear in the main setup transcript.

The new experiment scans **only** an isolated disposable prefix's `C:\\users`, `C:\\windows\\Temp`, `C:\\Temp` and `C:\\windows\\logs\\CBS` directories. It matches only bounded, well-known Microsoft Framework setup filenames such as `dd_*`, `NetFxSetupEvents.txt`, Framework Setup `.txt/.html`, and `CBS.log`, skipping unrelated files and symlinks. The scanner caps traversal at 120 directories and 24 matching files, reading at most 2 MiB per file. Excessive files, unsupported encodings or unreadable logs produce a partial classification, never an unbounded scan.

Only four fixed source categories, a bounded file count, broad failure phase and preapproved Windows error categories are stored. Original filenames, user paths, event text, registry values, executable data, serials, raw installer logs and unidentified error codes are **never uploaded**. This is classification, not a root-cause finding until a concrete phase or recognized code emerges. Microsoft CLR readiness remains a separate independent execution check.

## Actual Apple Silicon secondary-log result, November 14, 2026

[GitHub Actions run 43613463661](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/actions/runs/43613463661) completed the authenticated Microsoft installer experiment and bounded secondary log scan on real hosted Apple Silicon Wine. The primary `/log` transcript existed but reported UNKNOWN phase and no recognized Windows error code. The scanner found exactly **one bootstrapper temporary log** and no observed Framework Setup, Setup Events, or CBS logs among the scanned allowlisted paths. That single secondary file also returned UNKNOWN phase and no recognized error categories.

Wine Mono MSI removal succeeded (1 installed, 0 remaining), the original Microsoft installer returned Unix status 194, and the simulated Wine reboot completed, but the independent fixture still ran under Mono with Framework registry NOT_FOUND. Microsoft CLR readiness after restoring Wine's reported Windows 11 version remained FALSE. CI success means the diagnostic and privacy-safe evidence collection worked, **not** that the Microsoft Framework or SOLIDWORKS is installed.

This evidence does **not** show which internal Microsoft package fails, and absence of a scanned log is not proof that a subsystem did not execute. The next target should distinguish the original Windows process's full 32-bit exit status from Wine's Unix status and establish whether the bootstrapper actually launches its child installation payload.

## Exact Win32 bootstrapper exit and best-effort process handoff experiment

Previous macOS Wine runs returned Unix process code 194 from the genuine signed Microsoft Framework 4.8.1 offline installer. The code is ambiguous: the full Windows code could be 3010 (reboot required) or an unrelated 32-bit status truncated by Wine's Unix boundary. The installer never established a verified native CLR, even after a successful Wine reboot.

This experiment builds our own **independent x64 native Windows CreateProcessW fixture** from `probes/netfx481_win32_launch.c` using Microsoft's Windows MSVC toolchain. On a native Windows reference runner it executes a selftest that exits with Windows code 3010, proving `GetExitCodeProcess` captures the complete DWORD `00000BC2` rather than Unix's low-eight-bit 194. The original Microsoft signed setup exe, separately hash-verified and not modified, is then launched by that same fixture under Apple Silicon Wine with a full Wine Windows drive path.

The harness launches only the expected offline installer filename, with fixed `/q /norestart /log` arguments and a predefined private log location. It waits for its original Windows process with a bounded timeout, obtains the **entire Win32 exit DWORD**, and polls Windows process snapshots for a **direct child process observed** indication. `NOT_OBSERVED` does **not** prove the setup lacked child processes; a short-lived child or service-side installation may escape polling. No raw process names, command lines, paths, setup output, product identifiers, license material, or arbitrary stdout are published.

The Python parser in `scripts/netfx481_win32_exit.py` strictly accepts four synthetic evidence markers and returns only an exact uppercase 8-digit hexadecimal code, fixed exit category, capture status and child observation. It cannot fabricate a successful install from an invalid launcher report. A true 3010 triggers the same disposable-prefix Wine restart, but remains **insufficient** for a compatibility claim without the independently executed native Microsoft CLR fixture and registry checks. If the full Win32 code is not 3010, the previous assumed reboot interpretation is discarded.

The original Microsoft setup and bounded secondary log classifiers remain enabled, and the prefix still restores a Windows 11 reported profile afterward. This diagnostic is for a newly initialized and explicitly marked temporary Wine prefix only.

## Confirmed full Win32 3010 and child process on Apple Silicon, November 14, 2026

[Actual original Microsoft installer run 43619819316](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/actions/runs/43619819316) used the self-authored native Windows process monitor on Apple Silicon Wine. The verified original Microsoft Framework 4.8.1 bootstrapper returned **the complete Windows DWORD `0x00000BC2` (3010)**. Thus the earlier Unix code 194 was genuinely truncated Windows reboot-required 3010 in this test, not an unrelated error. `CreateToolhelp32Snapshot` also **observed a direct child process** of the original Microsoft bootstrapper. The observation proves some child activity but does not identify the child, whether it completed, or whether it actually installed the native CLR.

Wine Mono MSI removal, exact false-release cleanup and a subsequent disposable Wine reboot all completed. Despite a **confirmed 3010**, the independently compiled managed fixture still reported **MONO**, the Microsoft Framework Release registry value was **NOT_FOUND**, and native Microsoft CLR readiness after restoring reported Windows 11 was **FALSE**. Microsoft setup `/log` and the single secondary bootstrapper log remained `UNKNOWN` phase with no recognized error code.

The primary CI attempt's final schema-check step failed because its old allowlist did not include the newly verified `WIN32_3010_CONFIRMED` reboot reason. The experiment itself ran and produced a valid result. The schema rule is now corrected and CI re-executed. The next concrete problem is **tracking the observed child installer through its actual completion and error result before reboot**, not assuming the parent process's 3010 means the child finished.

## Follow-up: observe the child installer until completion before reboot

The first native Windows monitor confirmed that the authenticated Microsoft Framework bootstrapper exits with full Windows DWORD `0x00000BC2` (3010, reboot required) and **observes a direct child process**, yet the CLR still runs under Mono afterward. The original monitor captured only existence of a child, not whether that installation child had finished before our simulated Wine reboot.

The next independent native Win32 monitor stores up to 12 validated direct child process handles seen in bounded Toolhelp32 snapshots while the original Microsoft parent installer executes. After the parent exits, it waits at most 1.5 seconds per observed child (18 seconds total), reads completed child exit statuses through `GetExitCodeProcess`, and reports only an allowlisted **lifecycle** (`ALL_EXITED`, `STILL_ACTIVE`, `PARTIAL`, `NOT_OBSERVED`, `UNKNOWN`) and coarse exit classification (`ALL_ZERO`, `REBOOT_REQUIRED`, `NONZERO`, `NOT_VERIFIED`). It never uploads child PIDs, process names, command lines, paths or raw error logs.

The observation is best effort. A child exiting before the initial snapshot, children started by a service, and descendant processes outside the direct parent may not be captured. `NOT_OBSERVED` never means no child was started; `PARTIAL` means at least one status was not safely verified. When full parent Win32 code is 3010, **a child still active or not fully verified blocks the simulated restart**, rather than potentially interrupting pending installation activity. Only the independent Microsoft CLR readiness gate can establish Framework compatibility.

## Actual child-lifecycle result on Apple Silicon, November 14, 2026

[Genuine signed Microsoft setup run 43620738467](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/actions/runs/43620738467) used the new independent Win32 monitor to track direct child processes after original Microsoft Framework 4.8.1 setup returned full Windows `0x00000BC2` (3010). A direct child was **OBSERVED**, the tracked child lifecycle reached **ALL_EXITED**, and the aggregate child exit classification was **REBOOT_REQUIRED**. The subsequent simulated Wine reboot completed. Despite these results, the independent runtime still executed using **Wine Mono**, the expected .NET 4.8.1 Release indicator was unavailable, and native Microsoft CLR readiness remained **FALSE** even after restoring Windows 11.

This evidence rules out a still-running **observed direct child** as the explanation for the premature reboot hypothesis. It does not prove that service-side, descendant, or very short-lived processes completed, and neither parent nor child reboot-required code is evidence that genuine Microsoft CLR files were installed. The next test should independently inspect the **presence and loader identity of actual native Microsoft CLR binaries** before and after setup, not repeat registry or reboot workarounds.

## Native CLR PE payload and LoadLibraryW experiment, November 14, 2026

Microsoft's [Framework version detection guide](https://learn.microsoft.com/en-us/dotnet/framework/install/how-to-determine-which-versions-are-installed) distinguishes the .NET Framework 4.8.1 Release registry indicator from CLR identity, and its [mscorlib assembly path example](https://learn.microsoft.com/en-us/dotnet/api/system.reflection.assembly.location?view=netframework-4.8.1) references `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\mscorlib.dll`.

Prior real Apple Silicon Wine tests established that the signed Microsoft 4.8.1 installer and its observed direct child both return **Win32 3010** and exit before a completed Wine restart, but managed execution still reports Wine Mono and the real Microsoft CLR readiness gate remains false. The new experiment tests whether original Framework DLL payloads actually appear on disk.

`scripts/netfx481_payload_audit.py` inspects exactly four original Framework files: x64/x86 `clr.dll` and x64/x86 `mscorlib.dll` beneath the official Framework v4.0.30319 directories. The snapshot runs **after the disposable Wine Mono MSI uninstall but before Microsoft's setup**, then again after its completed child processes and simulated Wine restart. It checks the PE headers and architecture where available, hashes file contents only locally for a before/after change classification, and publishes **only** fixed file states (`ABSENT`, `PE_AMD64`, `PE_I386`, `PE_OTHER`, `NOT_PE`, `LINKED`, `IO_ERROR`, `INVALID_SIZE`) and differences (`CREATED`, `REMOVED`, `CHANGED`, `UNCHANGED`, `UNVERIFIED`). No hash, byte count, original file, file path, version, installer log, or proprietary data is uploaded. The scanner avoids symlink traversal.

A separate independently authored Windows x64 C fixture invokes `LoadLibraryW` on the standard Windows Framework64 `clr.dll` path. A real Windows reference runner must compile the fixture with MSVC and demonstrate successful loading of its installed CLR DLL. The same self-authored fixture then runs in bounded Apple Silicon Wine and returns only `LOADED`, `LOAD_FAILED`, `NOT_FOUND`, `LINKED`, or `NOT_VERIFIED`. Native DLL loading is tested **in a separate process**, so a broken loader cannot corrupt the main trial.

**Critical limitations:** An executable with a valid PE header could be produced by Wine or another component and does not prove it is a genuine Microsoft-signed DLL. `LoadLibraryW=LOADED` only demonstrates that Windows-style loading succeeded, not that the DLL implements all CLR functionality or that it belongs to Microsoft. Actual CLR identity, .NET Framework 4.8.1 registry state and managed execution remain separate mandatory gates. No DLLs are copied out of Windows or shipped to the user, and none of this proves SOLIDWORKS graphical CAD operation.

## Observed Apple Silicon native CLR payload result, November 14, 2026

The full [real Microsoft .NET 4.8.1 test 43623730956](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/actions/runs/43623730956) completed successfully as a diagnostic (not an installed Framework). The independently MSVC-compiled Win32 `LoadLibraryW` reference first passed on genuine Windows, and the signed original Microsoft offline installer was verified as before.

The real temporary Apple Silicon Wine prefix reported **Framework64 `clr.dll` = ABSENT** immediately before Microsoft's setup and **Framework64 `clr.dll` = ABSENT** after the original signed setup completed, its observed child had exited with Windows code 3010, and Wine's simulated restart completed. The observed file change was **UNCHANGED** (still absent). The original self-authored `LoadLibraryW` x64 CLR probe returned **NOT_FOUND**. The managed fixture still ran under **Wine Mono**, the .NET 4.8.1 Release registry indicator remained missing, and functional native Microsoft Framework readiness after restoring Windows 11 was **FALSE**.

This is stronger evidence than previous registry and loader preference tests: the expected `Framework64/v4.0.30319/clr.dll` was **not present at its standard installed location**, and the Windows loader independently confirmed that path unavailable. A missing file does not prove why Microsoft's bootstrapper or child installer chose not to stage or commit the binary; the actual internal payload extraction and servicing/MSI transaction is the next target.

**No compatibility claim:** a Windows installer returning 3010 and an observed child reporting restart required do not establish that CLR files were copied or registered. Native Framework and SOLIDWORKS remain unverified. The experiment reports no original executable files, hashes, identities, paths or unredacted installer logs.

## Next controlled installation change: Bottles' Fusion builtin-only override

The real Apple Silicon [run 43623730956](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/actions/runs/43623730956) established that signed Microsoft's Framework 4.8.1 setup did not install the standard x64 `clr.dll` at all. The before/after PE audit reported `ABSENT` to `ABSENT`, and independent Windows `LoadLibraryW` reported `NOT_FOUND` after a confirmed Win32 3010 and successful Wine reboot. Windows reference tests proved our native CLR loader successfully loads Microsoft's installed Framework DLL on real Windows.

The upstream [Bottles .NET 4.8.1 dependency recipe](https://github.com/bottlesdevs/dependencies/blob/main/Essentials/dotnet481.yml) uses the **same official Microsoft installer and /q /norestart** but additionally sets `WINEDLLOVERRIDES=fusion=b` in the **installation process environment** and later selects native mscoree loading. The experimental workflow previously removed Wine Mono and corrected false registry indicators, but did not set this Fusion override. The new `--experiment-fusion-builtin` flag applies the exact supported Bottles setting *only to the self-authored Win32 process monitor launching the signed original setup*. It is inherited by Microsoft's child installer, but is not persisted in the Wine registry, user environment, unrelated probes, or native loader test.

The monitored process and original media remain bounded and signature/hash-verified. The workflow repeats the native `clr.dll`/`mscorlib.dll` before/after PE audit, independent `LoadLibraryW`, full Win32 exit/child classification, and functional CLR/managed tests. This is a narrowly scoped compatibility hypothesis; `fusion=b` alone does **not** establish actual Microsoft .NET or SOLIDWORKS readiness. Tests verify that the override is absent for all non-installation subprocesses and that no positive result can be inferred from the setting.

## Apple Silicon result with Bottles Fusion builtin-only override, November 14, 2026

[Real signed Microsoft 4.8.1 CI run 43624232628](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/actions/runs/43624232628) applied Bottles' documented `WINEDLLOVERRIDES=fusion=b` **only while launching the original Microsoft setup**. The sanitized trial verified the scope as `fusion_setup_override=BUILTIN_ONLY`. Wine Mono MSI removal and earlier registry fixes remained in place.

The genuine installer still returned full Windows `3010` (reboot required) and the observed child had completed. The native `Framework64/v4.0.30319/clr.dll` was **ABSENT before** and **ABSENT after** the setup and Wine restart. The independent Windows `LoadLibraryW` probe returned **NOT_FOUND**. The native CLR readiness check and the post-Windows-11-restoration managed runtime check both remained **FALSE**.

The Bottles `fusion=b` dependency recipe therefore **did not fix** the missing CLR payload in this pinned Apple Silicon Wine environment, even though the original installer command and Mono removal matched Bottles' recipe. This result does not invalidate Bottles' recipe on other Wine versions or prefixes; it rules out this single override as a sufficient change under our tested conditions. Further work should isolate the original Microsoft payload extraction/servicing transaction or test a version-staged official Framework installation in an isolated disposable prefix, rather than changing DLL load order again.

## Official Microsoft .NET 4.8.1 redistributable package structure

After PRs #50 and #51, the original Microsoft .NET Framework 4.8.1 offline installer and its observed installation child both return full Win32 3010, but the standard `Framework64/v4.0.30319/clr.dll` remains **ABSENT**, even with Bottles' `fusion=b` installation setting and completed Wine restart. The problem is missing payload deployment, not merely an incorrect DLL search order.

Microsoft's [official offline distribution documentation](https://learn.microsoft.com/en-us/dotnet/framework/install/guide-for-developers) confirms the standalone installer carries all required framework components. Unlike the older 4.8 package which can install on Windows 7, Framework 4.8.1 is supported on recent Windows 10/11 versions, often via Windows servicing packages. This creates a testable distinction between original vendor CAB/MSU/MSI update payloads and direct DLL installation.

A separate [GitHub Actions workflow](../.github/workflows/netfx481-offline-package-ci.yml) downloads and Authenticode-verifies the **same original Microsoft-signed .NET 4.8.1 offline EXE** on an actual Windows runner. It asks the locally installed 7-Zip archive reader to list archive members, **without extracting, executing or uploading Microsoft payloads**. The private listing is classified into fixed categories (CAB, MSU, MSI, MSP, DLL, EXE, OTHER), architecture-specific Windows update markers, and direct `clr.dll` / `mscorlib.dll` member indicators. The file listing is deleted before the job ends. Only an allowlisted JSON document and summary are uploaded. Original filenames, registry keys, file contents, hashes, full paths, installation logs and private data are excluded.

**Evidence limitations:** A top-level archive listing might expose only an intermediate CAB/EXE, while nested Microsoft servicing payloads remain hidden. A `NOT_LISTABLE` result says only that the installed reader could not enumerate this SFX format. Neither a CAB/MSU marker nor an installer's Win32 3010 proves that the real native CLR has been deployed. If Windows servicing packages are confirmed, direct Wine install may require unimplemented Windows servicing behavior; the correct next step is to determine whether these packages extract and register without native Windows Update/CBS support, rather than copying Microsoft DLLs by hand.

## Real signed Microsoft package-archive baseline, November 14, 2026

The first [Windows-based official package inspection run 43625361543](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/actions/runs/43625361543) succeeded. After verifying Microsoft's genuine signature, the 7-Zip archive reader classified **131 outer archive entries**, including **3 CAB packages**, **27 DLL members** and **zero top-level MSI/MSU members**. At least one CAB filename had an x64 Windows update-style marker. No top-level exact `clr.dll` or `mscorlib.dll` member was found. These observations confirm **embedded CAB servicing containers** in the authentic redistributable, but not the contents of those CABs or why Wine fails installation.

The follow-up Windows workflow securely extracts **only these CAB containers** into a temporary, non-uploaded directory, independently lists each CAB without extracting its individual contents, and publishes only bounded counts of embedded DLL/MUM/CAT/MANIFEST/MSI/EXE/OTHER members plus fixed flags for `clr.dll`, `mscorlib.dll`, and Windows servicing manifests. All raw CAB containers, listings and names remain on the disposable Windows runner and are removed. This distinguishes a deeply nested CLR installation payload from a missing Microsoft update/servicing transaction under Wine.

## Technical boundaries

The independent fixture does not test every SOLIDWORKS managed feature or COM interop, and running Microsoft's CLR under Wine would still not establish CAD readiness. WebView2 browser pixels, native graphics/window composition, installation manager UI, x86 helper processes and activation remain separate compatibility gates.

Run manually through [the dedicated GitHub Actions workflow](../.github/workflows/netfx481-wine-ci.yml), or inspect its pull-request validation results.
