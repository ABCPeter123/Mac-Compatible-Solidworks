# Locate original .NET Framework 4.0 internal MSI failure before adding Wine hooks

## Verified background

Our genuine [Microsoft .NET Framework 4.0 Apple Silicon Wine experiment](../.github/workflows/netfx40-legacy-ci.yml) runs the original Microsoft Authenticode-verified, SHA256-pinned offline package under Wine 11.21. The fixture previously captured full original Windows bootstrapper exit code **1603**, observed immediate installer children that all exited and included at least one NONZERO exit, and found no newly installed native Microsoft CLR.

The same Mac Wine configuration exposes `msiserver` SCM registration, `msi.dll` Windows Installer exports and `msiexec.exe`. An independent WiX-authored, benign x64 MSI **installed a real marker with exact content**. This rules out missing basic MSI registration or globally broken simple file-install transactions. It does **not** rule out missing services, COM activation, fusion, GAC or custom-action behavior needed by .NET.

Microsoft's Windows Installer error **1603** is generic and is not an actionable API name. Microsoft's installer diagnostic guidance recommends examining the verbose inner MSI log around **`Action ended HH:MM:SS: <action>. Return value 3.`**. The first non-cascade failed action is a better lead than the outer `INSTALL` or `InstallFinalize` rollback status.

The original .NET 4.0 bootstrapper can write a file like `Microsoft .NET Framework 4 Setup_<timestamp>-MSI_netfx_Core_x64.msi.txt` under Windows TEMP. This test does **not** change the original bootstrapper binary, patch an MSI, intercept Windows registry APIs, fabricate .NET registry entries, or install anything onto macOS. It reads only these short-lived private diagnostic logs after the original Microsoft setup has already completed in a **fresh marked disposable Wine prefix**.

## Implementation

`scripts/netfx40_msi_evidence.py` scans strictly bounded locations under the short-lived prefix's C: drive: user TEMP, Windows TEMP and C: TEMP. It does not follow symlinks. Only exact expected .NET Framework setup/MSI log filenames are eligible. It reads at most 36 matching files, 144 directories and 4 MiB per file.

It detects genuine Windows Installer **Return value 3** markers and maps the first non-cascade failed action to these **fixed, coarse-grained** categories: VERSION_GUARD, SERVICE, REGISTRY_COM, ASSEMBLY_GAC, FILESYSTEM, CUSTOM_ACTION, FINALIZE_CASCADE or UNKNOWN. An allowlist captures common MSI error families, including 1402 (registry access), 1722/1723 (custom-action execution), 1935 (assembly install), 2502/2503 (MSI transaction ordering), and selected HRESULT families such as 0x80131700 (CLR activation). Generic 1603 is retained separately and is **not** a root-cause claim.

The classifier never exports the raw action name, filepath, Windows process command line, nested installer text, MSI log, original media bytes, user account or license. Only fixed enums and bounded counts leave GitHub Actions. No original Microsoft MSI is uploaded. `causality=ACTION_HINT_ONLY` explicitly prevents a mere failed action category from being called a proven missing Wine API.

The new CI gate requires the exact nested MSI schema to validate after the original signed installer runs. If no matching logs remain, the report states `NO_LOG` rather than inventing an action. Unavailable logs alone do not prove an installer bug or justify compatibility hooks.

## How this determines the next concrete hook

- **VERSION_GUARD:** inspect actual .NET version checks in the private isolated prefix. Do not forge CLR installation registry state to bypass the check.
- **REGISTRY_COM:** reproduce the reported action with a minimal self-authored Windows COM/registry fixture, compare native Windows with Wine, and identify missing Wine APIs before implementing a narrowly scoped shim.
- **SERVICE:** check the actual named Windows service and SCM operation in a private follow-up, using a standalone test. Having `msiserver` registered does not prove every service setup method.
- **ASSEMBLY_GAC:** test native Windows Fusion/GAC or installer-managed assembly registration independently. The existing `fusion=b` override is just a Winetricks baseline, not proof of correct assembly installation.
- **FILESYSTEM:** reproduce the failed file operation independently; distinguish permissions, Windows servicing directories and incompatible path behavior.
- **CUSTOM_ACTION / UNKNOWN:** broaden private MSI evidence to error codes and failing custom action's API surface before installing any patch.
- **FINALIZE_CASCADE:** this may be only rollback propagation. Do not misidentify it as the first underlying failure.

**Do not install fake .NET CLR DLLs, suppress arbitrary MSI errors or bypass setup licensing.** A working Microsoft native CLR must appear on disk, load, execute managed code and pass the independent validation before we treat the dependency as addressed. None of these tests establish native SOLIDWORKS CAD compatibility.

References:
- Microsoft, [Diagnosing Installation Errors](https://devblogs.microsoft.com/setup/diagnosing-installation-errors/).
- Microsoft, [.NET Framework Deployment Guide](https://learn.microsoft.com/en-us/dotnet/framework/deployment/deployment-guide-for-developers).
- Wine Mono, [Compatibility README](https://github.com/wine-mono/wine-mono).

## Additional targeted Wine internal MSI error capture

An [upstream Winetricks .NET 4.0 failure report](https://github.com/Winetricks/winetricks/issues/1792) contains a particularly actionable example: Wine could not locate the original `netfx_core.mzz` cabinet needed by an MSI `InstallFiles` action, and several extracted temporary MSI custom-action DLLs failed to load with Windows error 193 (bad executable format). The outer transaction then reported 1603. This was observed in an older Wine build, **not verified as our current Apple Silicon failure**.

The legacy original Microsoft installer trial now scopes `WINEDEBUG=-all,err+msi` only to its signed bootstrapper's execution. The output is stored in a short-lived anonymous private file, with a bounded 8 MiB read; it is **never printed or uploaded**. The classifier emits only these fixed public categories: CABINET_MEDIA_MISSING, CABINET_EXTRACT_FAILED, NETFX_CORE_CAB_MISSING, CUSTOM_ACTION_BAD_EXE, CUSTOM_ACTION_DLL_LOAD, MSI_ACTION_INSTALLFILES, MSI_ACTION_FINALIZE, MSI_CUSTOM_ACTION_UNSUPPORTED or OTHER_MSI_ERROR. A too-large trace produces TRUNCATED rather than a false negative.

This provides a second independent signal when Microsoft installer logs are missing, and helps decide whether to inspect Wine's cabinet resolution, WOW64 custom-action loader or other MSI APIs. An error channel marker alone still does not establish a missing API implementation. A narrow fix should only follow a reproducible failing Windows function or cabinet/media resolution operation in a self-authored minimal test.

A separate [Winetricks issue #2246](https://github.com/Winetricks/winetricks/issues/2246) documents `extract_cabinet FDICopy failed` while extracting `netfx_core.mzz`. That is a **different failure** from a cabinet not being present at all. The classifier deliberately distinguishes `CABINET_EXTRACT_FAILED` from `CABINET_MEDIA_MISSING`. If our own Wine run shows extraction failure, an intermediate fix must target Wine's MSI cabinet handling / FDI extraction and not invent missing media or a general `msiserver` patch.
