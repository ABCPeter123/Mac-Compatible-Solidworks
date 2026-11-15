# Experimental SCM refresh between Wine Mono removal and genuine Microsoft .NET setup

## Evidence motivating this test

[Original Windows service MSI on hosted Apple Silicon Wine 43665377780](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/actions/runs/43665377780) installed an exact-byte original Win64 service executable and registry entry. An independent Win32 process saw its service **ABSENT** immediately after the MSI completed. A bounded `wineboot.exe --restart` then returned COMPLETED and a new independent Windows controller saw the original service **STOPPED**, with its registry entry intact. This was revealed after correcting a false-negative Python marker parser that rejected the legitimate `SWCOMPAT_SERVICE_WIN32_EXIT` diagnostic.

[Original signed Microsoft .NET 4.0 trial on Wine Staging 11.21 run 43665180811](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/actions/runs/43665180811) still failed with Windows 1603 and no native CLR despite uninstalling Wine Mono's registered MSI, clearing fake Release values, using WinXP and scoped fusion configuration. The trace includes MSI_SERVICE and unimplemented TSAware warnings, but **does not** identify the first failed action or prove SCM caused the 1603.

## Narrow A/B

In a **fresh marked disposable Wine prefix only**, the experiment performs the same known-original Microsoft setup flow, but with exactly one opt-in boundary step:

1. Set temporary Wine Windows XP version and clear false Framework Release indicators, as in the previous signed original trial.
2. Uninstall registered Wine Mono MSI packages and verify cleanup, unchanged from baseline.
3. Run one bounded Wine restart using the existing `wineboot_restart` implementation. Record only `COMPLETED`, `TIMED_OUT`, `START_FAILED`, or `EXIT_NONZERO`. Refuse the authentic Microsoft setup if the refresh did not complete.
4. Run the self-authored Win32 launch self-test, the original SHA256-pinned, Authenticode-verified Microsoft offline .NET 4.0 setup, and the identical nested MSI evidence collector.
5. Independently verify the actual Microsoft CLR binary's PE architecture, mscorlib presence, Win32 DLL loading and non-Mono managed execution. No registry/installer exit alone counts as CLR success.

The opt-in CLI flag `--experiment-restart-after-mono` is not enabled for user-managed Wine prefixes or local native SOLIDWORKS installation. The report adds `pre_setup_scm_restart` with `NOT_REQUESTED` as the default in other invocations. Explicit test validation requires a completed restart for the CI A/B, verifies no original Microsoft installer runs on restart failure, and preserves all false-compatibility gates.

**Decision:** if this fixes native CLR deployment, test which services become visible and whether that persists for 4.8.1. If the original installer still fails 1603, the restart only solves the separate service registration symptom, and we need the earliest causative MSI custom action or service transaction failure. No fabricated licensing or .NET registration states are used.


## Actual Apple Silicon evidence

[Authenticated original Microsoft .NET 4.0 run 43665743538](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/actions/runs/43665743538) passed its CI evidence gates. Wine Mono MSI uninstall was verified (`REMOVED`) and the new pre-install service-manager restart completed (the integration gate requires `pre_setup_scm_restart=COMPLETED`). The identical signed Microsoft installer was then launched by the independently verified original Win32 process monitor.

Despite this refresh, Microsoft setup returned `MSI_FATAL_ERROR` (Windows 1603), the observed child exited nonzero, the real x64 and x86 `clr.dll` files were ABSENT, `mscorlib.dll` was ABSENT and the native CLR loader returned NOT_FOUND. The nested MSI report found four logs (one nested MSI) but no first failing `Return value 3` action. Wine trace categories remained `MSI_ACTION_FINALIZE`, `MSI_ACTION_SERVICE`, `MSI_TSAWARE_UNIMPLEMENTED` and `OTHER_MSI_ERROR`, from three Wine MSI error lines. A service action category is a direction, not causality.

**A bounded restart between Wine Mono removal and .NET 4.0 setup is insufficient to install native Microsoft CLR.** The verified SCM restart from a separate harmless MSI cannot be assumed to repair service actions *inside* Microsoft's nested MSI transaction. Next isolate the exact first service action (InstallServices versus StartServices) in the private Wine error trace, using fixed enums only, and build a matching self-authored MSI regression.
