# Source-authored MSI deferred custom action vs Wine Type trace

## Why this test exists

The authentic, signed Microsoft .NET Framework 4.0 installation under Wine Staging 11.21 fails with Win32 MSI error 1603 and no independent native Microsoft CLR deployment. Exact diagnostics identified a first nonstandard script action with `SERVICE_TEXT_ONLY` name hint. The opt-in trace in [PR #83](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/pull/83) was initially truncated by large Wine MSI trace volume. After narrowing to service-word custom-action names, the [original Apple Silicon run 43670851240](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/actions/runs/43670851240) completed with `TRACE_MISSING` and `capture_reason=NONE`. No CustomAction Type, DLL/EXE family or missing Wine API was established.

Before adding further expensive original .NET trial permutations, **validate that the exact same Wine diagnostic code can recognize a known action**. This eliminates an instrumentation blind spot as a confounder.

## Independent original reference

`probes/msi_custom_action_type_control.wxs` and `probes/msi_custom_action_fail.c` describe a fully self-authored, harmless Windows Installer MSI built with pinned WiX 5 and native MSVC x64. The MSI includes a single deliberately failing deferred native DLL CustomAction called `ServiceTypeControlSentinel`. Its Type is DLL binary stream + deferred execution + no impersonation, with low six bits `1`. The DLL does nothing except return MSI error 1603. Its action name includes `Service` **solely** to exercise the same bounded filter as the authentic Microsoft trace.

On native Windows, CI demands that the exact original self-authored MSI returns 1603 and rolls back a synthetic marker. The native MSI SHA-256 is transferred privately to Apple Silicon CI for exact-byte verification.

Apple Silicon runs the unchanged MSI under the pinned original Wine Staging 11.21, in a fresh marked disposable Wine prefix. `scripts/msi_custom_action_type_control.py` streams the same `WINEDEBUG=-all,err+msi,fixme+msi,trace+msi` private channel. It retains only selected bounded error, warning and service-word `Handling custom action` records, with identical fixed 3 MiB and 1,024-line ceilings and bounded process timeout. It never saves raw action identifiers, DLL paths or stderr to public files, logs or artifacts.

A successful control must produce `TRACE_MATCHED`, `DLL_BINARY`, `base_type=1`, `execution=DEFERRED` and an actual nonzero installer exit. A failed control is useful evidence of instrumentation, Wine debug emission or custom-action behavior, **not** native .NET incompatibility by itself. No original Microsoft .NET files are included in this workflow.

## Next interpretation

- If the original self-authored control succeeds under Wine, the original Microsoft `TRACE_MISSING` is more likely related to that action's execution path, deferred action identifier, or metadata, rather than an entirely broken trace channel. The next step is a private read-only MSI CustomAction table lookup using native MSI database APIs and the failure name, if the extracted original MSI remains accessible.
- If the original control fails, fix the Wine/debug collector or narrow line parsing using the actual self-authored fixture. Do **not** change CLR setup registry fields or implement a guessed service API shim.
- Neither case establishes Microsoft .NET Framework installation, SOLIDWORKS CAD compatibility or licensing readiness.


## Measured native Windows and Apple Silicon result

[CI run 43671644298](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/actions/runs/43671644298) has **passed both jobs**. The original self-authored native Windows x64 MSI deliberately returned 1603 and rolled back its marker. The identical checksum-verified MSI was then run under Wine Staging 11.21 in a fresh Apple Silicon Wine prefix; Wine's MSI process returned NONZERO, and the private bounded trace correctly correlated the failed action to `TRACE_MATCHED`, `family=DLL_BINARY`, `base_type=1`, `execution=DEFERRED`, `capture_reason=NONE`. Cross-platform compatibility foundation tests also passed.

This establishes that the exact `trace:msi:ACTION_CustomAction` channel, service-word filter, and failed-action correlation **work on Apple Silicon Wine for a real deferred DLL Type 1**. It narrows the authentic Microsoft `TRACE_MISSING` from PR #83: the failure is specific to that original action's identifiers, CustomAction table execution path, or original media context, rather than a universally broken Wine trace channel. It **does not** establish that original Microsoft .NET's action itself is a DLL, nor that the underlying service API is broken.

**Next decisive step:** private, read-only Windows Installer database metadata lookup for the first original failed nonstandard action, with fixed enum output only. It should distinguish (1) an actual `CustomAction` row and Type, (2) a standard `InstallExecuteSequence` action, and (3) no accessible original MSI database. Validate this lookup first on the known self-authored reference. Avoid adding more unactionable Wine restart or registry workarounds.
