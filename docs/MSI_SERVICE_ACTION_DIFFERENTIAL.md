# Genuine MSI InstallServices and StartServices on Apple Silicon Wine

## Why this is the next discriminating experiment

The authenticated, original Microsoft .NET Framework 4.0 installer consistently returned Windows 1603 on pinned Apple Silicon Wine 11.21. A more precise private Wine MSI trace now identified `MSI_ACTION_SERVICE` and a separate `msidbCustomActionTypeTSAware not handled` warning, alongside a cascading `InstallFinalize` failure. This observation is still an **action hint, not a proven missing function**.

Our repository already verified that ordinary Windows Installer registration, exports and an x64 MSI file-install transaction work. However, in [cross-process Windows Service Control Manager tests](SERVICE_CONTROL.md), a self-authored service registered by one Wine process was not consistently discoverable by another (`OpenServiceW` returned error 1060). A single retained SCM handle could create, run, stop and remove that service after bounded retries.

The Windows Installer `InstallServices` and `StartServices` deferred actions operate across Windows Installer service and client boundaries. Their behavior could therefore reveal a difference relevant to the observed original Framework failure. Mere correlation does not establish causation.

## Controlled comparison

This experiment builds a new, completely auditable x64 MSI from the original repository WiX 5 XML `probes/msi_service_action_probe.wxs`. Its only payload is our already tested original `probes/win_service_smoke.c` user-mode Windows service compiled with MSVC. No .NET DLL, proprietary media, SOLIDWORKS installer, license data, activation, kernel driver or system credentials are included.

On disposable native Windows Server 2025, CI must show:

1. No preexisting harmless test service or installed fixture binary.
2. The MSI installs and starts `SWCompatOriginalServiceTest` using actual `ServiceInstall` and `ServiceControl` tables, with command-line argument `run`.
3. `Get-Service` observes a RUNNING service, and installed executable bytes match the independently compiled MSVC source-backed fixture.
4. The MSI uninstalls, stops and removes the service and its executable.

CI temporarily transfers the exact MSI, its SHA256, and the original service executable to hosted Apple Silicon. The Wine branch creates a brand-new explicitly marked disposable prefix, switches to the same Windows XP version reported during the original Framework 4.0 trial, and checks service absence before attempting the identical MSI. It records the actual MSI process outcome, exact installed executable bytes and **a separate-process Windows SCM service query** afterward.

The Mac report contains only fixed enums: `msi_process`, `binary_after`, `service_after`, and `msi_service_start_candidate`. A return code of 0 **does not** count as successful service startup unless installed bytes match and the separate-process query observes SERVICE_RUNNING.

## How to use the result

- If native Windows passes but Wine's MSI fails and its service is ABSENT, this establishes a targeted MSI/SCM integration regression, subject to further narrow isolation of `InstallServices` versus `StartServices`.
- If the binary is present but a second Wine process cannot find the registered service, this independently reproduces the suspected **cross-process SCM visibility** issue through a real Windows Installer transaction.
- If Wine installs and starts the service successfully, the original Framework failure is more likely specific to Microsoft's custom services, custom actions, assembly registration, or dependencies rather than basic MSI service actions.
- In all cases, the separate `msidbCustomActionTypeTSAware` warning needs independent reproduction before being called causal. Wine's own `fixme` marker is not proof of a fatal action.

A passing diagnostic workflow means these observations were collected and validated. It does **not** mean the original .NET Framework CLR installed, the SOLIDWORKS installer works or any proprietary license service is compatible.

Sources: [WiX v5 ServiceInstall](https://velopack.github.io/wix5-docs/docs/schema/wxs/serviceinstall/), [WiX v5 ServiceControl](https://velopack.github.io/wix5-docs/docs/schema/wxs/servicecontrol/), and the repository's [previous SCM cross-process observations](SERVICE_CONTROL.md).
