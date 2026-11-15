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
