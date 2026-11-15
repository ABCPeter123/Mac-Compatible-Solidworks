# Read-only Windows Installer CustomAction Type metadata

The original signed Microsoft .NET 4.0 installer fails with MSI 1603 and no native CLR on Apple Silicon Wine. Its first nonstandard failing action has a `SERVICE_TEXT_ONLY` name hint, but no matching action Type trace was observed even after avoiding trace truncation. [PR #84, Apple Silicon run 43671644298](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/actions/runs/43671644298) established that the exact Wine `trace:msi:ACTION_CustomAction` parser works for a source-authored deferred DLL failure: `TRACE_MATCHED`, `DLL_BINARY`, base Type 1, execution DEFERRED.

The next question is whether a specific failed action belongs to an MSI `CustomAction` table, **independent of execution trace availability**.

## Original Win32 metadata probe

`probes/msi_custom_action_table_probe.c` is an entirely source-authored, read-only Windows x64 executable. It uses official Windows Installer functions `MsiOpenDatabaseW`, `MsiDatabaseOpenViewW`, `MsiViewExecute`, `MsiViewFetch` and `MsiRecordGetInteger` to read exactly the `Type` column from a `CustomAction` record. The SQL action identifier is provided through a parameterized Windows Installer query, not interpolated into SQL.

The MSI filename is the only command-line argument. The exact action identifier is supplied via standard input, never the process argument list or environment. The native probe emits only two fixed protocol markers, `SWCOMPAT_CA_TABLE_STATUS` and `SWCOMPAT_CA_TABLE_TYPE`; it never emits an action name, path, MSI table contents or vendor data. A strict Python parser maps the returned numeric Type's low six bits into an allowlisted family and rejects extra, repeated, oversized or invalid markers.

Before touching Microsoft media, validate this *separately* against the self-authored WiX MSI from PR #84. Its deliberately failing `ServiceTypeControlSentinel` is known to be deferred, no impersonation and DLL stream Type 1, so its full numeric CustomAction Type should be `0xC01` (3073). Both native Windows and Apple Silicon Wine must independently return `ACTION_FOUND` and base Type 1. All media transfers remain hash-verified and private to GitHub Actions.

This probe does **not** modify a Windows Installer database, run installer actions or install Microsoft runtime files. The first iteration does not scan or redistribute proprietary Microsoft MSI internals. Once it passes on original source-authored media, a separate bounded original .NET experiment may invoke it against an original MSI **only if that original MSI file is verifiably available inside the existing marked disposable prefix**. If it has already been deleted, that result is `DATABASE_UNAVAILABLE`, not grounds to fabricate a CustomAction Type.

A successful metadata lookup narrows the type of custom action; it does not establish which Win32 API failed. The native Microsoft CLR and actual SOLIDWORKS CAD remain unverified.


## First Apple Silicon execution and stage isolation

[Run 43672021668](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/actions/runs/43672021668) passed the native Windows compilation, original MSI failure/rollback and **native read-only table query**, but its Apple Silicon metadata step stopped at `BAD_EXIT`: the Wine-launched Win32 helper returned a nonzero process code without a parseable final status. The original self-authored MSI custom-action trace itself had passed on this same Wine build in [run 43671644298](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/actions/runs/43671644298).

A `BAD_EXIT` is a helper process execution problem, not evidence that the Windows Installer CustomAction table lacks the action. The controlled follow-up uses static MSVC CRT linking and **fixed flushed stage markers** `ENTRY`, `INPUT_OK`, `DATABASE_OPEN`, `VIEW_OPEN`, `PARAMETER_SET`, `VIEW_EXECUTED` and `ROW_FETCHED` around the exact Win32 MSI APIs. The strict parser retains only the last allowlisted stage, even on a failed process, without publishing Win32 identifiers, paths or vendor data. If no `ENTRY` appears, investigate the helper's loader/execution environment; if a later stage appears, localize the corresponding Windows Installer API boundary.


## Second Apple Silicon measurement: before Win32 entry

[Run 43672372521](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/actions/runs/43672372521) verified the static-CRT probe on native Windows again, but the Apple Silicon probe still exited nonzero with `BAD_EXIT`, `stage=NOT_OBSERVED`. Even a flushed `ENTRY` marker at the beginning of `wmain` was not reached. Therefore the run provides **no evidence that a Windows Installer database query was executed**, and it cannot justify an MSI database compatibility shim.

The next controlled variation removes static `msi.lib` imports entirely. The helper now enters `wmain` before explicitly calling `LoadLibraryW(L"msi.dll")` and `GetProcAddress` for the exact Win32 MSI functions. It reports `MSI_DLL_UNAVAILABLE` or `MSI_EXPORT_UNAVAILABLE` with fixed stage markers, without attempting a database query when APIs are absent. Distinguishing process-loader failure from missing native MSI DLL exports is necessary before attempting any patch. The initial self-authored Windows reference is unchanged.


## Confirmed harness startup cause: relative helper path

[Run 43672620175](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/actions/runs/43672620175), even after removing all static MSI imports and linking the C runtime statically, returned `BAD_EXIT`, `stage=NOT_OBSERVED` on Apple Silicon. Source review then found a concrete **test-harness bug**: `scripts/msi_custom_action_table_type.py` invoked Wine with `str(probe)` set to the repository-relative `build/msi_custom_action_table_probe.exe`, but set `cwd=prefix`. This made Wine look for `build/...exe` **under the disposable prefix**, where the helper was not present. No native Windows Installer API was called. The earlier `BAD_EXIT` results therefore cannot support any claim of a Wine loader/MSI API defect.

The corrected wrapper rejects symlinks and resolves the Wine binary, prefix, probe executable and self-authored MSI to absolute paths **before changing subprocess cwd**. POSIX regression tests intentionally pass a relative executable and assert that the actual Wine child receives an absolute original helper path. The original read-only database query, private standard-input action name and exact MSI hash/expected Type validation remain unchanged. Native Windows reference success is preserved.


## Verified Windows and Apple Silicon result, November 15, 2026

The complete [source-authored Windows/Wine CI run 43675250677](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/actions/runs/43675250677) **passed both jobs**. Windows compiled the original native x64 DLL custom action, read-only MSI metadata query and independent Win32 process monitor. It verified the original harmless MSI intentionally fails with Windows 1603 and rolls back its synthetic file.

On Wine Staging 11.21 under Apple Silicon, all these strictly bounded checks now pass:

- Original helper **self-test**: `SELFTEST_OK`, exact entry and fixed status channel verified.
- Independent `CreateProcessW` smoke: `STARTED`, child exit `ZERO`.
- Direct original MSI `CustomAction` table lookup: `ACTION_FOUND`, last stage `ROW_FETCHED`.
- Same original table lookup through independent `CreateProcessW`: `ACTION_FOUND`, `family=DLL_BINARY`, low-six-bit `base_type=1`, last stage `ROW_FETCHED`.
- Separate actual, intentionally failing deferred DLL action under Wine: `TRACE_MATCHED`, `DLL_BINARY`, `base_type=1`, `DEFERRED`. The actual MSI process returned nonzero, as intended.
- Original .NET compatibility remains **false/unverified** and SOLIDWORKS readiness is **not demonstrated**.

The earlier Apple Silicon `MALFORMED`/ `NOT_OBSERVED` **did not establish a defect in Wine's `MsiOpenDatabaseW` or query APIs**. The decisive diagnostic harness defect was a strict parser allowing only eight stage markers while a fully successful MSI database query emits nine. The full nine-stage path now has a regression test and emits `ACTION_FOUND`; malformed or duplicate stages remain rejected.

The source-authored action is sent to the actual Win32 helper through an exclusively created mode-0600 file inside the marked disposable Wine prefix, and the file is removed after processing. A separate real Win32 `CreateProcessW` path independently validates execution, using fixed private-report status markers. No original proprietary MSI records, vendor paths, action names or installer logs enter CI output.

**Engineering conclusion:** Read-only MSI CustomAction Type inspection is a verified, usable capability on the pinned Wine build. Next inspect the first failed nonstandard action **only if the original Microsoft installer actually retains its signed nested MSI inside the disposable prefix**, and output only the same allowlisted type family/execution mode. Do not invent an original action type, patch Wine SCM without source-backed evidence or claim native Microsoft CLR installation.
