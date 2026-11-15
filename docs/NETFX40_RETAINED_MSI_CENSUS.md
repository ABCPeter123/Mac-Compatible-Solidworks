# Genuine Microsoft .NET 4.0 retained MSI census on Apple Silicon Wine

## Evidence and objective

The authentic signed Microsoft .NET Framework 4.0 offline bootstrapper fails with Win32 MSI 1603 under Wine Staging 11.21. Original CLR files are absent and native Microsoft managed code is unverified. Its first failed nonstandard Wine MSI script action has a service-word name hint but no matching custom-action Type record in the bounded Wine execution trace.

The project separately verified a **read-only Win32 MSI CustomAction table query** under both native Windows and Apple Silicon Wine in [original source-authored test 43675250677](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/actions/runs/43675250677). The same harmless original Type 3073 deferred DLL was `ACTION_FOUND` through direct Wine and an independent Win32-created child. [PR #85](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/pull/85) was merged. The earlier `MALFORMED` reports came from the diagnostic parser rejecting nine valid stages when its cap was eight. This establishes table lookup as a usable capability, **not a Microsoft CLR installation**.

Before inspecting any original Microsoft MSI metadata, we must determine whether the genuine Microsoft bootstrapper leaves any nested MSI file in its disposable Wine prefix after exit. The original installer may clean up all MSI temporary files. A missing MSI cannot be queried or assumed to exist.

## Opt-in original-media check

`scripts/netfx40_msi_inventory.py` scans **only** short-lived directories under the original marked disposable Wine prefix: users, Windows Temp and drive C Temp. It runs immediately after the unchanged authentic signed .NET 4.0 setup finishes, before a possible Wine restart. It neither changes nor extracts installer files. The scanner:

- Refuses symlinked roots and subdirectories and never follows symlinks.
- Caps the scan to 144 directories, 600 file entries, depth seven, 24 candidate matches, and 200 MiB per candidate.
- Recognizes conservative `.msi` candidate filenames with a bounded ASCII grammar and at least 4 KiB.
- Exposes only finite status enums `ABSENT`, `CANDIDATE_PRESENT`, `PARTIAL_SCAN`, `INVALID_ROOT`, plus strictly bounded candidate/directory/file counts. It never returns filenames, paths, package identifiers, raw MSI content, logs or original action names.
- Separately counts `netfx`, `netframework` or `dotnet`-prefixed candidates without treating those names as proof of Microsoft origin.

The original Apple Silicon Wine Staging workflow opts in with `--experiment-inventory-retained-msi`, retaining original signed media authentication, Wine Mono removal, bounded SCM restart, the real installer process/child observation and independent CLR file/managed-execution readiness gates. Windows and POSIX unit tests reject symlink traversal, oversized or malformed candidates, and invented readiness fields.

## Interpretation

- `ABSENT`: the installer left no matching MSI candidate in these scanned directories. A different **source-backed** original-media extraction strategy is required before querying `CustomAction`; do not invent an original Type.
- `CANDIDATE_PRESENT`: a file exists, but its authenticity and relationship to the failed original action are still **unverified**. A later experiment must establish MSI identity and query privately using the verified Windows Installer API, never publish the source names or MSI tables.
- `PARTIAL_SCAN` or `INVALID_ROOT`: inconclusive. Improve bounded discovery without bypassing safety checks.

No Wine service shim, Microsoft MSI patch, registry-forged CLR, serial bypass or SOLIDWORKS activation bypass is part of this experiment.
