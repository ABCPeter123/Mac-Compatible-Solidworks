# First precise Microsoft .NET 4.0 MSI service-action failure on Apple Silicon Wine

The authentic signed, checksum-pinned original Microsoft .NET Framework 4.0 offline installer exits Windows 1603 in both Wine Development and Wine Staging 11.21. Independent native Microsoft CLR binaries remain ABSENT. In a separate original self-authored MSI fixture, a bounded Wine restart makes a previously registry-only service visible to a new Windows process; applying the same bounded restart after Wine Mono cleanup did **not** repair authentic .NET Framework setup.

The last original .NET trial ([43665743538](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/actions/runs/43665743538)) produced only three `err:msi` lines, grouped as service action, finalization and other; the warning `msidbCustomActionTypeTSAware not handled` is a `fixme`, not proof of the failure. Four private installer logs contained no recognized first `Return value 3` action. This evidence is too broad to justify patching Wine's SCM or MSI engine.

## Exact scripted action differential

This experiment changes only the privacy-safe classifier over the same private, bounded `WINEDEBUG=-all,err+msi,fixme+msi` diagnostic. It identifies only Wine's specific `err:msi:execute_script ... action L"<name>" returned 1603` marker, using an allowlist of **exact canonical Windows Installer action names**, not substring matches on unknown vendor names.

It exports `first_failed_action` and sorted `service_action_failures` using finite categories: `INSTALL_SERVICES`, `START_SERVICES`, `STOP_SERVICES`, `DELETE_SERVICES`, `SERVICE_CONFIG`, `INSTALL_FILES`, `PATCH_FILES`, `REGISTRY_COM`, `ASSEMBLY_GAC`, `CUSTOM_ACTION`, `OTHER_ACTION`, `FINALIZE_ONLY`, or `NOT_IDENTIFIED`. The latter is mandatory when no explicit failed script action appears. If an earlier custom action failed and finalization later reported rollback, the first non-finalize action is kept. An arbitrary vendor custom-action name containing `StartServices` is **not** treated as the Windows Installer standard action.

No original Microsoft MSI, raw Wine output, action names, expanded MSI properties, Windows paths, GUIDs, credentials or serials leave the ephemeral GitHub runner. All original .NET file, native loader and managed execution checks remain unchanged. Unit tests check each principal service action and reject malformed/invented status categories.

## Next engineering choice

- `INSTALL_SERVICES`: reproduce the exact SCM service creation and database persistence across installer transactions with a source-authored MSI, then compare native Windows and Wine service APIs.
- `START_SERVICES`: reproduce service startup **within the original MSI transaction** with an independent harmless Win32 service. A restart *after* the transaction cannot repair an internal StartServices action.
- `CUSTOM_ACTION`: investigate the specific custom-action loader/pipe/error code, not generic service registration.
- `FINALIZE_ONLY` or `NOT_IDENTIFIED`: do not invent a first cause. Add the next bounded private-log parser or Win32 fixture before changing Wine.

This experiment is not a SOLIDWORKS installation and does not establish functional .NET Framework or CAD readiness.


## Measured result on Wine Staging, November 15, 2026

[Authenticated original Microsoft .NET 4.0 run 43666816258](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/actions/runs/43666816258) passed its evidence gates and still returned Windows `MSI_FATAL_ERROR` (1603). Original native Microsoft `clr.dll`/`mscorlib.dll` are ABSENT, the native loader was NOT_FOUND and `candidate_native40=False`. The same private trace contains three `err:msi` lines; exact script-action classification returned `first_failed_action=OTHER_ACTION` and `service_action_failures=[]`.

The prior aggregate Wine class still contains `MSI_ACTION_SERVICE`. **This is not evidence of a failed standard InstallServices or StartServices action.** The older broad classifier matches `installservice`/ `startservice` *substrings* in arbitrary action names. The exact classifier requires canonical full action names, and found none. Do not target a Wine standard service-action implementation based solely on that broad category.

**Next change:** remove the misleading substring-based service classification; distinguish an original nonstandard action name from a genuine built-in MSI action. For nonstandard actions, allow only finite shape/category hints without emitting its raw expanded identifier. Then reproduce the actual failing behavior in a harmless independently authored MSI before proposing compatibility hooks.


## Correcting an unsafe earlier service classification

The broad Wine error classifier had treated *any* failed script action whose name contained a word such as `installservice` as a standard `MSI_ACTION_SERVICE`. The exact-action trial proved `first_failed_action=OTHER_ACTION` with zero canonical `InstallServices`/`StartServices` failures, revealing that this broad heuristic was unreliable. Matching a word inside a private MSI property expansion or vendor-defined custom-action identifier is **not proof** that Wine's standard service code failed.

The classifier now uses the **same exact allowlisted standard action categories** for both `classes` and `first_failed_action`, preventing this mismatch. When an original failed script action is nonstandard, `nonstandard_name_hint` reports only one name-shape hint from `SERVICE_TEXT_ONLY`, `REGISTRY_TEXT_ONLY`, `ASSEMBLY_TEXT_ONLY`, `MSI_PROPERTY_EXPANSION` or `OTHER_NONSTANDARD_NAME`. The default for a known standard action or missing action is `NOT_APPLICABLE`. A hint is always **NAME_ONLY**, never an API result or root-cause classification. Original action names and log bytes remain local to the disposable runner.

The next native .NET A/B will reveal whether the original action merely contains service-related text, is an expanded MSI property, or another nonstandard action. Even a `SERVICE_TEXT_ONLY` result does not authorize a Wine `StartServiceW` shim. A source-authored reproduction of the actual operation remains necessary.


## Original signed Apple Silicon result after removing false service matches

[PR #82 run 43667409044](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/actions/runs/43667409044) passed the original Microsoft media authentication, strict cross-platform tests and full Apple Silicon original installation evidence gates. The Microsoft installer still returned `MSI_FATAL_ERROR`, both native CLR binaries remained absent and independent native DLL loading reported NOT_FOUND.

The corrected Wine error categories are `MSI_ACTION_FINALIZE`, `MSI_TSAWARE_UNIMPLEMENTED` and `OTHER_MSI_ERROR`, from three errors. The first exact failed action remained `OTHER_ACTION`, `service_action_failures=[]`, and the new name-only hint was `SERVICE_TEXT_ONLY`.

This **confirms a failure in a nonstandard action whose original name includes service-related text**, not that Microsoft's built-in MSI `InstallServices`/`StartServices` actions were called or failed. The precise underlying Windows API or Wine implementation remains unknown; the next test must capture bounded lower-level operation evidence or construct a source-backed reproduction before proposing any Wine patch.
