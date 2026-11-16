# Authenticated original .NET Framework 4.8 CLR dependency graph

**Evidence:** [signed private Windows scan 43795489931](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/actions/runs/43795489931), [PR #138](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/pull/138), continuation of the [full compatibility diagnostic](FULL_COMPATIBILITY_DIAGNOSTIC_2026-11-16.md).

The original Microsoft .NET Framework 4.8 offline setup was downloaded from the official Microsoft endpoint and authenticated with Windows Authenticode before extraction. The original `.mzz` archive and individual selected x64 runtime files were inspected only in private Windows runner storage. Neither the original installers nor any Microsoft files were installed, executed, published or copied into a Wine prefix. The report includes fixed, bounded import-family counts and schema-validated enums, not DLL filename lists, import symbols, paths, hashes or proprietary bytes.

| Original signed MZZ member | PE architecture | Static direct imports | Delay imports | CLI metadata directory |
| --- | --- | --- | --- | --- |
| CLR, x64 | PE_AMD64 | READABLE: **7** | READABLE: **18** | Absent |
| mscorlib, x64 | PE_AMD64 | NONE: **0** | NONE: **0** | Present |
| Selected native WPF x64 pattern | NOT_FOUND | NONE | NONE | Absent |

The x64 CLR core is a **native Windows PE library**, unlike `mscorlib`, which is a CLI/managed assembly. The CLR core's Windows loader dependency set must work **before** hosting, Fusion, managed assembly activation or SOLIDWORKS execution can be evaluated. This is not proof the original CLR loads on macOS.

## Static import families observed

| Direct import family | Count |
| --- | ---: |
| NTDLL | 1 |
| KERNEL32 | 1 |
| ADVAPI32 | 1 |
| USER32 | 1 |
| SHLWAPI | 1 |
| VCRUNTIME | 1 |
| OTHER | 1 |
| **Direct total** | **7** |

| Delay import family | Count |
| --- | ---: |
| API_SET | 4 |
| CRYPTO | 3 |
| MSCOREE | 1 |
| NETWORK | 1 |
| OLE32 | 1 |
| OLEAUT32 | 1 |
| VERSION | 1 |
| OTHER | 6 |
| **Delay total** | **18** |

The parser deduplicates each table's imported DLL names privately. The totals are *table-specific counts*, not necessarily a unique count across direct and delayed tables. `OTHER` includes members whose names were intentionally not emitted; **one direct and six delay DLLs remain unclassified**. They must not be treated as missing in Wine just because their category is `OTHER`.

The original `clr.dll` does **not** advertise a CLI metadata directory; the original `mscorlib.dll` does. This is expected for a native CLR implementation coupled to a managed core library. The `clr.dll` directly imports one Visual C++ runtime DLL family, which must be present and ABI-compatible for native Windows `LoadLibraryW` to succeed. The delay table contains Windows API-set, cryptographic and .NET hosting families, which can fail **later** when those functions are exercised, even if the initial loader succeeds.

## Next falsifiable compatibility experiment

1. Compile a **self-authored Windows x64** independent loader fixture on Windows CI with native Windows controls.
2. Download authentic 4.8 media onto a **disposable Apple Silicon macOS runner** with hash equality to independently Authenticode-checked original media on Windows in the same run. Do not share original Microsoft executable, CLR or proprietary DLLs as artifacts.
3. Privately extract only the authenticated x64 CLR member into a temp directory **outside the Wine prefix**; no fake `.NET Release` registry state or unsupported "installation" shortcut.
4. Execute the self-authored Win32 fixture under the pinned Wine executable and classify `LoadLibraryExW(LOAD_WITH_ALTERED_SEARCH_PATH)` by finite status: `LOADED`, missing dependency (126), missing entry point (127), invalid image (193), DLL initialization failure (1114), other or timeout.
5. Even if the original x64 CLR loads, require a subsequent genuine native-only managed-code test and verified .NET installation state before marking the 4.8 runtime usable.

Do not rerun the same direct installer (5100) or unchanged Winetricks `dotnet48` (840-second timeout). The next result should isolate **loader readiness versus managed-runtime activation**, which the existing package-only evidence cannot establish.
