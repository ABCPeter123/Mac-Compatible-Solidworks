# Separate MSI InstallServices from StartServices under Wine

The original signed Microsoft .NET Framework 4.0 installer exited Windows 1603, and the private Wine trace classified an MSI service action failure. The same source-backed MSI containing both `InstallServices` and `StartServices` then passed on disposable native Windows but exited NONZERO on Apple Silicon Wine 11.21, leaving its service executable ABSENT and its service not registered after the failed transaction. [See the combined-action experiment](MSI_SERVICE_ACTION_DIFFERENTIAL.md).

This does **not** prove that the service-start step caused the MSI failure. The binary could also be removed by rollback after an earlier failure.

## Controlled single-variable comparison

This variant preserves the original audited x64 MSVC service executable, `SWCompatOriginalServiceTest`, install directory, MSI content and SHA-256 verification scheme. It removes **only** `ServiceControl Start="install"`. Its original WiX `ServiceInstall` table still registers the service with `Start="demand"`. The `ServiceControl` uninstall Stop/Remove controls remain intact.

The native Windows reference must install the exact executable, register the named service in **STOPPED** state, then uninstall and remove it. The hosted Apple Silicon Wine job uses the identical compiled package in a brand-new explicitly marked disposable XP-profile prefix. It records the original MSI exit status, exact installed binary byte comparison and a subsequent independent Win32 `OpenServiceW` query.

If the install-only MSI succeeds on Wine while the otherwise equivalent start-enabled MSI failed, it narrows the problem to the ServiceControl StartServices action or its service process visibility/SCM interaction. If both fail, the next test should isolate InstallServices itself, file/component registration or the Wine service database lifecycle. If both succeed, the earlier failure may be nondeterministic and needs repeatability checks.

The classifier's `msi_service_start_candidate` is **expected to remain FALSE** for the install-only variant because no service startup is requested. The meaningful install-only signal is the conjunction of MSI exit ZERO, installed binary PRESENT_MATCH, and independently queried service state STOPPED. Missing files or a nonzero installer process cannot count as success. This experiment uses no Microsoft runtime binaries, SOLIDWORKS media or real license services, and claims no native Microsoft CLR or SOLIDWORKS compatibility.
