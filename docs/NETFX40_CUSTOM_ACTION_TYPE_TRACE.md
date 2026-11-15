# Original Microsoft .NET 4.0 custom-action type evidence on Apple Silicon Wine

## Root question

In source-backed [original Microsoft .NET 4.0 run 43667409044](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/actions/runs/43667409044), the original Authenticode-verified bootstrapper exited with Windows 1603, and x64/x86 native Microsoft CLR binaries remained ABSENT. The first explicit failing Wine MSI action was `OTHER_ACTION` with a `SERVICE_TEXT_ONLY` **name** hint, but there was no proven failure in the standard `InstallServices` or `StartServices` actions.

The next discriminant is the **numeric Windows Installer CustomAction Type** of the actual failed original action. Wine's public source [dlls/msi/custom.c](https://github.com/wine-mirror/wine/blob/master/dlls/msi/custom.c) emits `TRACE("Handling custom action %s (%x %s %s)\n", ...)` with the action identifier, numeric Type and two private fields immediately after it reads the `CustomAction` MSI table. Wine's `dlls/msi/action.c` separately emits the failing `execute_script ... action L"..." returned 1603` record. Those two original diagnostic lines can be compared privately without extracting or distributing any Microsoft package internals.

## Exact isolated test

The experiment runs the same pinned original, signed Microsoft offline installer in a **new marked disposable Wine prefix** on a hosted Apple Silicon GitHub runner, after Wine Mono removal and a verified bounded SCM restart. It adds `--experiment-trace-custom-action-type`, opt-in only for this fixture.

When enabled, `WINEDEBUG=-all,err+msi,fixme+msi,trace+msi` is scoped only to the signed setup's Win32 monitor process. A dedicated pipe-draining thread reads private stderr incrementally and **retains in anonymous process memory only**:

- `err:msi` and `fixme:msi` lines already needed for the existing narrow classification.
- `trace:msi` lines containing the exact `Handling custom action` record.

It neither stores nor uploads raw trace bytes. It retains at most 1,024 selected lines totaling 3 MiB, drops lines longer than 4 KiB, marks overflow explicitly, and uses the existing original installer process timeout. Selected private records are discarded after computing fixed status fields. An unexpected trace volume is **CAPTURE_TRUNCATED**, not an invented action type.

The collector privately strips Wine's deferred prefix `[CustomActionData<=>UserSID<=>ProductCode]` exactly as the upstream `ACTION_CustomAction` code does, and matches the remaining original action identifier **exactly**, not by substring. Multiple conflicting candidate Type values produce `TRACE_AMBIGUOUS`; no trace match produces `TRACE_MISSING`. Raw action names, source or target fields, command lines, paths, GUIDs, user IDs, Microsoft data and license details are never persisted in the public report.

The report adds `custom_action_type` with only allowlisted fields: `status`, `family`, `base_type`, `execution`, `impersonation`, `asynchronous` and `ts_aware`. The Type low six bits classify known DLL, EXE, script, nested-MSI or property actions; higher bits describe deferred execution, impersonation, async and Terminal Services awareness. These are *action metadata*, not observed Windows API calls. The independently verified Microsoft CLR file and managed-execution requirements remain unchanged.

## Decision

A **matching** DLL/EXE or script type identifies the correct kind of harmless Windows MSI custom-action reproduction to build. A Type 19 error action would instead suggest deliberate installer abort. A deferred no-impersonation action requires testing its execution context. `TRACE_MISSING` or `CAPTURE_TRUNCATED` means the evidence is insufficient and must not be treated as a discovered Win32 defect.

**No compatibility bypass, original MSI modification, API hook, fake .NET registry value or product activation bypass is used.** A green CI job means only diagnostic completion, not a working native Microsoft CLR or SOLIDWORKS.
