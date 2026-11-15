# Same-connection SCM lookup coherence after a real MSI registration

The fully observed Apple Silicon Wine 11.21 sequence after an original self-authored WiX MSI was:

- Actual MSI exits ZERO, installs the exact original service executable and creates the service registry key.
- A separate Win32 controller reports `OpenServiceW=1060` despite the service key being present.
- A second original Win32 controller calls `CreateServiceW` with the verified MSI-installed executable and receives `ERROR_SERVICE_EXISTS (1073)`.
- Another `OpenServiceW` still cannot find the service, and startup is not attempted. Restarting Wine earlier did not produce verified service visibility.

These results **do not yet establish** whether the two APIs disagree against a single service database. They have run in separate Wine client processes and thus could have resolved different service manager instances.

## This targeted follow-up

The original harmless `service_smoke.exe` adds a `coherence <windows-executable-path>` mode. It acquires **one** `OpenSCManagerW` handle and keeps that exact handle across three operations:

1. `OpenServiceW` with `SERVICE_QUERY_STATUS`, record only `PRESENT`, `ABSENT` or `OTHER`.
2. Only if the first lookup is `ABSENT`, attempt the actual `CreateServiceW` with the original MSI-installed executable and fixed test service name. Record only `CREATED`, `ALREADY_EXISTS`, `DATABASE_LOCKED`, `ACCESS_DENIED` or `OTHER`. This may create the harmless service if it truly does not exist, only inside the marked disposable Wine prefix.
3. Repeat `OpenServiceW` using **the same** SCM handle.

It neither modifies any Microsoft installer, licensed software, persistent Wine prefix nor host macOS services, and does not start the service. The native Windows MSVC-compiled fixture is transferred unchanged to the Apple Silicon runner, with exact binary verification. Windows and macOS Python regression tests require a strict four-marker protocol, finite outcomes and independent native CLR/SOLIDWORKS negative status.

Interpretation:

- `EXISTS_BUT_INVISIBLE`: same manager reports `OpenServiceW ABSENT`, `CreateServiceW ALREADY_EXISTS`, `OpenServiceW ABSENT`. Investigate inconsistent lookup/validation or service database implementation inside Wine, not just process churn.
- `CROSS_PROCESS_DISAGREEMENT`: same-connection first and second lookups both `PRESENT` while preceding separate processes failed. Investigate which service manager instance or RPC endpoint each Wine client contacts.
- `NEW_REGISTRATION_VISIBLE`: first lookup `ABSENT`, new `CreateServiceW` `CREATED`, and second lookup `PRESENT`. This supports stale registration/SCM population as a cause.
- `UNRESOLVED`: no proven root cause; collect more narrowly defined evidence.

Wine source context: `programs/services/rpc.c` checks the `scmdatabase_find_service()` result both in `svcctl_OpenServiceW` and `create_serviceW`; `programs/services/services.c` loads service registry entries into the manager database during startup. The prior discrepancy is not enough to justify a blanket registry or services.exe patch.

Sources: [upstream Wine rpc.c](https://github.com/wine-mirror/wine/blob/master/programs/services/rpc.c), [upstream Wine services.c](https://github.com/wine-mirror/wine/blob/master/programs/services/services.c), [prior independent API experiment](MSI_SERVICE_SCM_API_DIFFERENTIAL.md).

A passing diagnostic workflow alone does not establish working Microsoft .NET or real SOLIDWORKS.

## Nondeterminism documented by first PR run

The first PR #72 Apple Silicon run completed successfully as a CI workflow but produced a new independent SCM behavior: the original direct `CreateServiceW` returned `CREATED`, not `ALREADY_EXISTS`, while the original MSI service registry key was already present. An independently executed `OpenServiceW` returned `UNKNOWN` afterward. This is **not** proof of repair, even though the `CreateServiceW` call succeeded.

The initial eligibility rule incorrectly skipped the single-SCM-handle test for `CREATED`. It now accepts both observed values, `CREATED` and `ALREADY_EXISTS`, when the previous Win32 read-only service status has not been verified as `RUNNING` or `STOPPED`. The Python regression includes this exact sequence. A passing CI workflow still requires `trial=MEASURED` only if the real prior evidence satisfies the strict safety gates.
