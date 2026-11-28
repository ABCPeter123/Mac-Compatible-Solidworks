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


## First real trace outcome and bounded refinement

[Apple Silicon run 43670234342](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/actions/runs/43670234342) authenticated and executed the original Microsoft setup, which still ended with Windows MSI 1603 and no native Microsoft CLR. The opt-in trace mode completed as a diagnostic, but its private selected trace exceeded the initial capture policy or did not fully drain before the bounded reader join. It reported `CAPTURE_TRUNCATED`, with no action Type claimed and no private logs exported.

The next controlled iteration preserves the **same** signed setup, Wine Staging 11.21 and 3 MiB / 1,024-line memory ceilings, but now retains Wine `Handling custom action` events **only when the exact action name contains 'service'**. This restriction is justified by repeated original trials whose first nonstandard failing action was previously classified `SERVICE_TEXT_ONLY`. All `err:msi` and `fixme:msi` lines continue to be collected. It does not infer a service API call from that text.

If capture is still incomplete, the report includes a finite `capture_reason`: `LINE_LIMIT`, `BYTE_LIMIT`, `READER_UNFINISHED`, `PROCESS_INCOMPLETE` or `UNKNOWN`. These codes distinguish trace volume from process/pipe lifecycle problems without publishing paths, raw log contents, or secret action names. An incomplete report remains `CAPTURE_TRUNCATED` with no claimed Type. The revised collector must pass original Win32 native-loader and managed-execution non-Mono gates independently.


## Verified second Apple Silicon run: trace present but type not matched

[Run 43670851240](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/actions/runs/43670851240) passed original Microsoft Authenticode, native Windows baseline and cross-platform unit checks. The original Microsoft offline setup still returned Windows `MSI_FATAL_ERROR` (1603), Microsoft native x64 `clr.dll` and `mscorlib.dll` remained ABSENT, and independent native CLR loading was NOT_FOUND. The bounded Wine error trace again identified `first_failed_action=OTHER_ACTION` and `nonstandard_name_hint=SERVICE_TEXT_ONLY` with 3 MSI error lines and zero canonical MSI service actions.

After restricting custom-action type tracing to service-word identifiers, the evidence is now **`TRACE_MISSING`**, `capture_reason=NONE`, not `CAPTURE_TRUNCATED`. The original failed identifier did **not** correlate to a `Handling custom action` metadata line visible to this collector. This is not enough to declare the MSI Type or a missing Win32 API.

The next discriminant is to verify Wine's trace pipeline against a *source-authored harmless MSI* containing a deliberately failing custom action. This checks whether the expected `trace:msi:ACTION_CustomAction Handling custom action ...` line is emitted at all on the pinned Wine build. If the self-authored control works, inspect the original action's execution context and MSI database metadata inside the private runner instead of matching guessed action names. Never disclose original action names or distribute extracted Microsoft MSI bytes.

## Verified original Type 1 failure and runtime API census

Run [46032226784](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/actions/runs/46032226784) reproduced the same 1603 with MSYNC enabled and disabled. Both action traces matched a deferred, synchronous, no-impersonation Type 1 DLL. Original MSI table correlation matched one of six scanned packages (partial discovery), and the private AMD64 Binary import census measured two registry reads, one registry write and two loader-related imports, but zero direct SCM imports. This does not exclude dynamic service API lookup.

The next retry adds a bounded Wine relay return census, using the pinned Wine source's RelayInclude and __wine_msi_call_dll_function export. Only calls inside matching DLL invocation scopes returning 1603 contribute public API result counts. No call arguments or raw output are persisted. The filter is installed only in the marked CI prefix and removed after verified cleanup. Missing scopes, overflow and incomplete output are explicit non-evidence. Even observed API failures can be expected fallback behavior; no compatibility shim is justified from counts alone.
