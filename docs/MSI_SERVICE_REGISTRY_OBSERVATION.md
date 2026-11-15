# InstallServices-only: Windows service registry versus separate-process SCM

In [the original MSI install-only Apple Silicon run](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/actions/runs/43657128472), an x64 MSI built from audited WiX XML with a harmless service and **no StartServices instruction** exited ZERO and installed the original executable with exact bytes. An independent Wine process nevertheless reported that the service was ABSENT. The otherwise matching MSI with StartServices enabled returned NONZERO and rolled back, as seen in [the preceding differential](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/actions/runs/43656810967).

This narrows the suspected issue to MSI service registration/start and cross-process Windows Service Control Manager state. It does not establish precisely which API failed, because the successful MSI process did not guarantee visible service registration.

## Next read-only differential

Immediately after the existing install-only MSI has exited, `scripts/msi_service_registry_observation.py` uses Wine's own original Windows `reg.exe query` on **one hard-coded key**:

`HKLM\SYSTEM\CurrentControlSet\Services\SWCompatOriginalServiceTest`

This is compared to the **already captured separate-process** service query from the same marked disposable Wine prefix, after the original verified MSI binary installation. It never changes registry contents and suppresses all raw `reg.exe` stdout/stderr. Public CI statuses are fixed enums and cannot contain arbitrary user paths, values, original package data or service executable paths.

The result distinguishes:

- `REGISTRY_PRESENT_SCM_ABSENT`: Wine persisted the named service key, but the SCM handle from a separate client cannot see the service. This directly supports a service database synchronization/visibility investigation.
- `REGISTRY_ABSENT`: The service registration was not written or persisted even though the MSI reported success and installed the file. Investigate `InstallServices`, service registry commit and deferred action execution.
- `SCM_AND_REGISTRY_PRESENT`: Both independent interfaces see the registration. The earlier service query failure may be nondeterministic; repeat the test before patching anything.
- `UNKNOWN`: The query could not establish which case applies. No compatibility claim is made.

The original Mac test reports exactly whether the MSI returned ZERO and the original binary matched; those checks remain necessary. Even a service registry and SCM pass would **not** prove a native Microsoft .NET CLR, correct Microsoft Framework servicing, real SOLIDWORKS installation or operation.
