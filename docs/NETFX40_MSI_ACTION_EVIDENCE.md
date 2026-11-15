# Follow-up on original .NET 4.0 Windows error 1603: first failing Wine MSI action

## Observed, verified

- Genuine signed .NET Framework 4.0 setup returns full Win32 **1603** on Apple Silicon Wine 11.21 after an immediate child exited NONZERO. The native Microsoft CLR is **not installed**.
- Existing native Windows and Wine tests confirm the MSI service is registered, core MSI exports exist, and a separately authored harmless x64 MSI actually installs its file.
- The original 4.0 TEMP scanner found **four** setup-related logs, one a nested MSI transcript, but no recognized `Return value 3` action. A narrow `err+msi` trace emitted three lines categorized `MSI_ACTION_FINALIZE` plus `OTHER_MSI_ERROR`.
- The [verbose logging policy experiment](../.github/workflows/netfx40-legacy-ci.yml) independently verified that Microsoft's documented `Logging=voicewarmupx` registry value was **APPLIED**, later **REMOVED**, but did not find an additional `MSI*.LOG` or classify a first failing action. A policy applied is **not** proof the Wine MSI engine honored it.

## Why a generic MSI hook is premature

The first failure can occur in a deferred custom action before the final `InstallFinalize` rollback. Wine error channels may contain this evidence even when Windows Installer does not produce a conventional verbose log.

Real upstream Wine failure reports show different root causes that all produce outer 1603, including:
- A missing `netfx_core.mzz` cabinet before `InstallFiles`, or an FDI cabinet extraction failure.
- A temporary MSI custom-action DLL failing to load with Windows error 193.
- A custom action communication pipe failure (`custom_client_thread`) and an invalid return code (`custom_get_thread_return`, e.g. 232).
- A previously reported unimplemented MSI custom-action attribute `msidbCustomActionTypeTSAware`.

These are **independent historical examples** and not evidence that our same Wine build is affected.

## Narrow new evidence experiment

The signed original .NET 4.0 trial now scopes `WINEDEBUG=-all,err+msi,fixme+msi` to setup in a marked disposable prefix. It reads a maximum 8 MiB of the private subprocess diagnostic file and does **not print or upload it**. The fixed-schema classifier recognizes:
- The exact type of the preceding action named in `execute_script ... action L"..." returned 1603`: files, services, registry, assembly/GAC, patching, or custom action.
- Missing or failed cabinet handling, absent compressed MSI files, bad DLL format, custom-action pipe failures and invalid return codes.
- A specific known Wine `fixme:msi` custom-action TSAware gap as a **warning**, not an independent fatal error.

Wine source-format action names may embed private file paths or custom command arguments. Only broad, fixed categories leave the process, never any raw action name or unapproved text. The classification is an action hint; it is **not** a demonstrated Wine API root cause. The experiment does not patch the installer, spoof Microsoft Framework registry values, intercept license checks or alter the user's long-lived Wine prefix.

If the first non-finalize action is identified, write a self-authored x64 MSI regression that reproduces the specific API difference on real Windows and Wine. Only after demonstrating that difference should we consider a narrow Wine patch or shim. Existing CLR-on-disk, LoadLibrary and C# validation must still pass before declaring .NET solved. Native SOLIDWORKS installation is not demonstrated.

References: [Wine .NET MSI pipe example](https://forum.winehq.org/viewtopic.php?t=37789), [Wine custom action error 193 and cabinet example](https://forum.winehq.org/viewtopic.php?t=35503), [Windows Installer Logging](https://learn.microsoft.com/en-us/windows/win32/msi/logging).
