# Authentic .NET Framework 4.8 CLR versus shim activation on Windows and Wine

**Verified 2026-11-16.** Active compatibility blocker: [issue #115](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/issues/115). This document distinguishes native Windows loader capability from CLR hosting, a completed Microsoft framework installation, and SOLIDWORKS functionality.

## Evidence and the corrected mental model

| Gate | Grounded result | Reproducible evidence |
| --- | --- | --- |
| Original Microsoft x64 clr.dll, no dependencies staged | `MISSING_DEPENDENCY` (Win32 126) | [43798619311](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/actions/runs/43798619311) |
| Original x64 CLR with two original Microsoft MZZ imports staged | `LOADED`, process exit 0 | [43798619311](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/actions/runs/43798619311) |
| Host via Wine builtin mscoree.dll | `OTHER_RUNTIME_SELECTED`, no original managed execution | [43800026739](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/actions/runs/43800026739) |
| Original signed x64 mscoreei.dll extracted from MZZ | `STAGED` (1 located, 1 genuine x64 PE staged) | [43803887867](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/actions/runs/43803887867) |
| Direct original mscoreei.dll LoadLibraryExW, Apple Silicon Wine | `ORIGINAL_SHIM_INIT_FAILED` (Win32 1114) | [43804284917](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/actions/runs/43804284917) |
| The **same signed original MZZ mscoreei.dll** loaded in isolated directory on native Windows 2025 | `ORIGINAL_SHIM_INIT_FAILED` (Win32 1114) | [43804807763](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/actions/runs/43804807763) |
| Original signed shim in isolated directory, Apple Silicon Wine, standalone native-only mode | `ORIGINAL_SHIM_INIT_FAILED` (Win32 1114) | [43804807763](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/actions/runs/43804807763) |
| Already-installed Windows Framework64 mscoreei.dll, directly loaded in proper location | `INIT_FAILED` (Win32 1114) | [43805122029](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/actions/runs/43805122029) |
| Exact same installed Windows mscoreei.dll copied to disposable temp, directly loaded | `INIT_FAILED` (Win32 1114) | [43805122029](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/actions/runs/43805122029) |
| **Official installed Windows mscoree.dll shell shim**, `CLRCreateInstance(CLSID_CLRMetaHost)` | **`SHELL_ACTIVATION_OK`** | [43805122029](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/actions/runs/43805122029) |

These are deliberately independent tests. Running `LoadLibraryExW` on `clr.dll` establishes native PE linking and DllMain readiness; it does **not** establish managed CLR initialization. `mscoreei.dll` is the shim implementation behind the public `mscoree.dll` shell. The direct `mscoreei.dll` loading test fails even with a properly installed Microsoft framework on genuine Windows; therefore ERROR_DLL_INIT_FAILED is not, by itself, evidence of a missing direct import, missing file, Wine bug, or a portable fix.

The earlier positive control on Windows proved the **normal public shell hosting path**, `mscoree.dll` plus `CLRCreateInstance`, can obtain ICLRMetaHost. The later [PR #150](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/pull/150) independently strengthened that native Windows positive control: an *installed genuine Microsoft Framework64 CLR* executed the original source-authored C# Tasks/XML/SHA256 library via `ICLRRuntimeHost_ExecuteInDefaultAppDomain` (returned `42`), while a known unrelated Windows DLL was rejected at the selected-runtime identity gate. [Run 43898939889, attempt 2](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/actions/runs/43898939889) passed all jobs including Apple Silicon, and preserved original signed 4.8 x64 CLR native reload `LOADED` with two signed-package imports staged; its isolated CLR host still returned `OTHER_RUNTIME_SELECTED`, `managed_executed=False`, and `runtime_installed=False`. Therefore the validated host fixture does **not** turn an isolated, uninstalled CLR into a registered/usable runtime, and there is no Microsoft .NET 4.8 Wine managed success yet.

Wine's actual [`dlls/mscoree/metahost.c` implementation](https://github.com/wine-mirror/wine/blob/master/dlls/mscoree/metahost.c) shows that `CLRRuntimeInfo_GetRuntimeHost` invokes `get_mono_path` and `load_mono`, or returns `CLR_E_SHIM_RUNTIME` if Wine Mono is absent. Merely calling Wine's **builtin** `mscoree.dll` `CLRCreateInstance` after `LoadLibraryExW` of a genuine Microsoft `clr.dll` does **not** switch the metahost to Microsoft CLR. The **installed-native** comparison has now run. The authenticated original .NET 4.0 prefix's `mscoree=n;clr=n` returned `MANAGED_ORIGINAL_PASS`, while Wine's builtin `mscoree=b;clr=n` returned `MANAGED_EXECUTION_FAILED` through the strict original CLR hosting fixture. See [run 43999786107](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/actions/runs/43999786107). The first run's CI failure was an unrelated final-validator bug, fixed in PR #155. This is real original Microsoft 4.0 managed hosting, not an installed 4.8 or 4.8.1 framework.

See Microsoft CLR team's [description of mscoree vs mscoreei](https://devblogs.microsoft.com/dotnet/is-that-the-right-version-of-mscoreei-dll/) and [CLRCreateInstance](https://learn.microsoft.com/dotnet/framework/unmanaged-api/hosting/clrcreateinstance-function).

## Verified original 4.8 runtime startup failure on installed Microsoft 4.0 Wine

[Run 44011928875](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/actions/runs/44011928875) authenticated original Microsoft .NET 4.8 media on native Windows, independently verified the same SHA256 on Apple Silicon, and staged genuine original 4.8 x64 CLR and two direct imports over a *reversible, disposable* original 4.0 prefix. The public CLR hosting API selected the exact original CLR directory, obtained `ICLRRuntimeInfo` and `ICLRRuntimeHost`, but `ICLRRuntimeHost::Start()` failed for all three variants: CLR plus native imports, plus original 4.8 `mscorlib.dll`, and plus four additional original 4.8 core DLLs. The original Microsoft 4.0 CLR executed the source-authored managed fixture before and after restoring the original files.

[Run 44014665961](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/actions/runs/44014665961) independently reproduced the failure and classified the public `Start()` HRESULT as `HOST_START_E_FAIL` for all three variants. This excludes a simple missing direct PE import and excludes the earlier unrelated `OTHER_RUNTIME_SELECTED` explanation, but **does not establish the cause of the CLR startup failure**. A generic E_FAIL can arise from several runtime initialization paths.

[Run 44016664066](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/actions/runs/44016664066) added an extra genuine x64 runtime component and bounded private Wine loader/SEH tracing. All four original 4.8 startup variants still returned `HOST_START_E_FAIL`; the trace confirmed native `clr/mscoree/mscoreei` and found no missing import, module, unimplemented API or exception in enabled channels.

[Run 44029823245](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/actions/runs/44029823245) then compared the read-only public CLR `IsLoadable` and `IsStarted` metadata and broader Wine COM/registry diagnostic categories on the same disposable prefix. Both genuine installed 4.0 and staged original 4.8 returned `PRECHECK_LOADABLE_NOT_STARTED`. Original 4.0 subsequently executed managed code, while all four 4.8 variants returned `HOST_START_E_FAIL`. Both Wine traces were readable and recorded no error or fixme channels; native CLR, mscoree and mscoreei were observed in both. Original 4.0 was restored and managed execution passed again.

**This is an isolated original 4.8 CLR startup failure, not a completed .NET 4.8 installation.** These checks do not prove the underlying cause of `E_FAIL`. Neither .NET 4.8 nor .NET 4.8.1 has completed installation or executed managed code on Apple Silicon Wine, and SOLIDWORKS CAD has not been demonstrated. Original Microsoft media, runtime DLLs and raw Wine traces stay private to ephemeral runners.

## What not to repeat

- Do not continue staging arbitrary DLLs just to force direct mscoreei.dll LoadLibrary to return LOADED. The native Windows control invalidates that as a compatibility acceptance test.
- Do not register a fake .NET 4.8/4.8.1 `Release` value or claim success from a green CI run. An authentic, installed runtime needs real framework file changes, correct registration, native hosting, managed execution, and a successful installer lifecycle.
- Do not rerun identical Microsoft 4.8/4.8.1 setup attempts that returned prerequisite code 5100, the Winetricks 840s timeout, or Wine DISM tests that returned false success for nonexistent CABs.
- Never export Microsoft or SOLIDWORKS proprietary binaries, MZZ members, paths, registry dumps or license data from CI.

[Run 44031647494](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/actions/runs/44031647494) additionally tested the documented `COMPlus_ZapDisable=1` switch, which disables .NET Framework NGEN native images. Original 4.0 still executed managed code with the switch both before and after restoration. Staged original 4.8 still returned `HOST_START_E_FAIL`. This rules out disabling NGEN as a sufficient workaround. The authenticated 4.8 runtime remains uninstalled and unstartable under this tested Wine configuration.

## Next falsifiable work

1. **Exact .NET 4.8/4.8.1 setup prerequisite.** Microsoft documents setup exit code 5100 as an unmet system requirement. The prior Wine setup logs only identified `UNKNOWN_PREREQUISITE`. Diagnose the original signed installer's specific StopBlock/OS/servicing requirement rather than retrying the same 5100 or creating fake `Release` keys.
2. **Native CLR startup dependencies.** The signed original 4.8 CLR passes `IsLoadable` but returns `E_FAIL` at `Start` even with original core payload and NGEN disabled. Further work must test a specific runtime initialization dependency with positive native-Windows and working native-4.0 controls, not unstructured DLL staging.
3. **Actual framework installation and managed execution.** Require correct original Microsoft framework registration, servicing, installer exit status and source-authored managed execution before claiming native 4.8/4.8.1 support.
4. **SOLIDWORKS acceptance.** Only after native framework hosting and installation work, validate a properly licensed genuine SOLIDWORKS build on an interactive Apple Silicon Mac, including sketch, extrude, save and reopen.

**Current verified milestone:** the genuine Microsoft .NET 4.0 native CLR executes managed code on hosted Apple Silicon Wine. Genuine Microsoft .NET 4.8 x64 CLR and its original imports load and pass `IsLoadable`, but `ICLRRuntimeHost::Start` returns `E_FAIL` even with staged original framework support files. No native .NET 4.8/4.8.1 managed execution or usable SOLIDWORKS has been shown.


## Process-scoped Microsoft CLR activation-log differential (November 17)

The genuine 4.8 payload-host run established that setting `COMPlus_ZapDisable=1`
does **not** resolve `ICLRRuntimeHost::Start -> E_FAIL`. Repeating that NGEN
experiment with the same payload adds no evidence. The next distinct test
is the documented **Microsoft CLR activation log**, which reports runtime
discovery and selection decisions rather than Fusion binding or post-
activation managed-code execution:

https://learn.microsoft.com/dotnet/framework/deployment/how-to-debug-clr-activation-issues

`COMPLUS_CLRLoadLogDir` is supplied **only** to one self-authored native CLR
host subprocess at a time. Three temporary directories are created and
destroyed independently for working original 4.0, reversibly staged signed
original 4.8, and restored original 4.0. Logs remain private inside the
marked disposable Wine prefix. Each run exports only bounded fixed categories:
activation header, installed/selected runtime, runtime-load calls, shim
failure, install-root/component errors, or general reported error, plus
the already allowlisted host status. A native Windows host control records
whether Microsoft emits activation logs under the same variable.

**Interpretation:** `NO_LOG` does not mean CLR startup succeeded. Even an
activation log does not prove managed execution or an installed 4.8 runtime.
If 4.8 reports no unique shim issue while Start still returns `E_FAIL`,
the failure remains in a later initialization stage and requires different
instrumentation. Original 4.8 and 4.8.1 setup error **5100 remains unresolved**.
