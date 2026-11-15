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
