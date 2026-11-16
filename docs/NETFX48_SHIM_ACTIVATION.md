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

The positive control on Windows proves the **normal public shell hosting path**, `mscoree.dll` plus `CLRCreateInstance`, can obtain ICLRMetaHost. It does **not** show the isolated original 4.8 runtime works under Wine, and does not prove successful managed execution.

See Microsoft CLR team's [description of mscoree vs mscoreei](https://devblogs.microsoft.com/dotnet/is-that-the-right-version-of-mscoreei-dll/) and [CLRCreateInstance](https://learn.microsoft.com/dotnet/framework/unmanaged-api/hosting/clrcreateinstance-function).

## What not to repeat

- Do not continue staging arbitrary DLLs just to force direct mscoreei.dll LoadLibrary to return LOADED. The native Windows control invalidates that as a compatibility acceptance test.
- Do not register a fake .NET 4.8/4.8.1 `Release` value or claim success from a green CI run. An authentic, installed runtime needs real framework file changes, correct registration, native hosting, managed execution, and a successful installer lifecycle.
- Do not rerun identical Microsoft 4.8/4.8.1 setup attempts that returned prerequisite code 5100, the Winetricks 840s timeout, or Wine DISM tests that returned false success for nonexistent CABs.
- Never export Microsoft or SOLIDWORKS proprietary binaries, MZZ members, paths, registry dumps or license data from CI.

## Focused next run: native .NET 4.0 host provenance only

The [manual .NET 4.0 workflow](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/actions/workflows/netfx40-legacy-ci.yml) now exposes `host_provenance_only` (merged PR #148). To test the already established native-4.0 hosting route without the repeated 4.8/4.8.1 prerequisites, explicitly dispatch from `main` with `host_provenance_only=true`, `try_48_intermediate=false`, and `try_48_direct=false`. This still authenticates and tests original Microsoft .NET 4.0 in marked disposable hosted Apple Silicon Wine and may encounter the known intermittent 4.0 MSI 1603 or timeout. The opt-in change skips the duplicate fresh baseline, original 4.8/4.8.1 media or installer path, Winetricks 4.8, and irrelevant upgrade disk/version gates. It reports the actual loaded mscoree and clr implementation as only `NATIVE_ONLY`, `BUILTIN_ONLY`, `MIXED`, `NOT_OBSERVED`, or `TOO_LARGE`, alongside managed execution class. No raw Wine loader trace leaves the runner. Static code tests are passing; this manual actual-native-4.0 provenance experiment has not yet been re-run with the new option.

## Next falsifiable work

1. **Activation provenance on a working native .NET 4.0 Wine prefix.** Prior original .NET 4.0 probes confirmed native-only managed execution and restart persistence. Determine which `mscoree.dll` (native vs Wine builtin) and which CLR path the genuinely working configuration selects, with fixed enum-only source-authored probes and no change to its installation state. This is a useful positive Wine-side control before considering an authentic 4.8 upgrade.
2. **Native Microsoft 4.8 installer/servicing prerequisites.** Determine the actual failed Microsoft requirement behind code 5100. A Wine-reported OS version does not implement Windows component servicing. Focus on an exact blocked child/action/Windows API, not broad generic MSI or SCM loops.
3. **Full original 4.8+ managed execution.** Verify the real Microsoft x64 CLR, genuine framework libraries, native `mscoree` activation, a source-authored managed probe and real installation registration/exit result. Do not mix bits from different Framework releases and label the resulting prefix installed.
4. **4.8.1 and SOLIDWORKS.** Only after the above, attempt the original, properly licensed Windows application on a display-capable interactive Mac; test actual sketch/extrude/save/reopen functionality.

**Current verified milestone:** authentic Microsoft 4.8 clr.dll native PE loads after staging two genuine signed-package imports; normal shell hosting succeeds on native Windows, but genuine Microsoft .NET 4.8/4.8.1 activation and full installation on Apple Silicon Wine have **not** been demonstrated.
