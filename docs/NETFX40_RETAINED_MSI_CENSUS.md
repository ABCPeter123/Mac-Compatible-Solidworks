# Genuine Microsoft .NET 4.0 retained MSI census on Apple Silicon Wine

## Evidence and objective

The authentic signed Microsoft .NET Framework 4.0 offline bootstrapper fails with Win32 MSI 1603 under Wine Staging 11.21. Original CLR files are absent and native Microsoft managed code is unverified. Its first failed nonstandard Wine MSI script action has a service-word name hint but no matching custom-action Type record in the bounded Wine execution trace.

The project separately verified a **read-only Win32 MSI CustomAction table query** under both native Windows and Apple Silicon Wine in [original source-authored test 43675250677](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/actions/runs/43675250677). The same harmless original Type 3073 deferred DLL was `ACTION_FOUND` through direct Wine and an independent Win32-created child. [PR #85](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/pull/85) was merged. The earlier `MALFORMED` reports came from the diagnostic parser rejecting nine valid stages when its cap was eight. This establishes table lookup as a usable capability, **not a Microsoft CLR installation**.

Before inspecting any original Microsoft MSI metadata, we must determine whether the genuine Microsoft bootstrapper leaves any nested MSI file in its disposable Wine prefix after exit. The original installer may clean up all MSI temporary files. A missing MSI cannot be queried or assumed to exist.

## Opt-in original-media check

`scripts/netfx40_msi_inventory.py` scans **only** short-lived directories under the original marked disposable Wine prefix: users, Windows Temp, drive C Temp, and at most 12 immediate C-drive extraction folders whose names consist of 10 to 40 hex digits. It runs immediately after the unchanged authentic signed .NET 4.0 setup finishes, before a possible Wine restart. It neither changes nor extracts installer files. The scanner:

- Refuses symlinked roots and subdirectories and never follows symlinks. Scans only strict hex-named immediate C-drive folders rather than scanning the entire drive root.
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


## First original installer measurement and expanded extraction-root test

[Authentic signed .NET 4.0 run 43675805446](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/actions/runs/43675805446) passed all diagnostic gates, but Microsoft's original setup returned `MSI_FATAL_ERROR` (1603); real x64 `clr.dll` and `mscorlib.dll` were ABSENT and independent native loading returned NOT_FOUND. The initial bounded Temp-only census checked 37 directories and four file entries but found zero candidate MSI files. The original failed action is still `OTHER_ACTION` with the `SERVICE_TEXT_ONLY` name hint, and original action Type remains `TRACE_MISSING`.

An `ABSENT` result from that Temp-only run does not prove that the installer never extracted MSIs elsewhere. Some genuine .NET 4.0 installers use direct C-drive random-named extraction folders. The revised census adds at most 12 immediate folders matching 10 to 40 hex digits under the **same marked disposable Wine drive C**. It does not scan other Wine drive mappings or arbitrary user paths. Windows and POSIX regression tests verify that an MSI inside a strict hex folder is counted, unrelated root folders are ignored, linked folders are never followed, and exceeding the root cap yields `PARTIAL_SCAN`.

Even an `ABSENT` expanded-root result means only that no conservatively named, size-bounded MSI file survived in those enumerated locations **after the original setup exited**. It does not prove that a temporary MSI never existed during execution. If none survives, the next grounded investigation is a bounded during-execution census or a privately verified original-media extraction, not a fabricated action Type.


## Expanded-root original signed Microsoft result

[Apple Silicon original .NET 4.0 run 43676443656](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/actions/runs/43676443656) passed the authenticated-media and diagnostic CI gates. Microsoft's original installer **still exited 1603**, real x64 Microsoft `clr.dll` and `mscorlib.dll` remained ABSENT, and independent native CLR loading returned NOT_FOUND. The first Wine MSI failed action was `OTHER_ACTION` with a service-text-only name hint, and original CustomAction Type remained `TRACE_MISSING`.

The expanded post-setup census (TEMP **and** immediate C-drive strict hex-named extraction folders) reported `ABSENT`, **zero candidates**, **37 directories checked** and **four file entries checked**. The same directories/file-entry counts as the Temp-only trial indicate that no surviving strict hex-named root folder added any inspected directory at that time. This is a post-setup measurement only, so it cannot prove an MSI was never extracted during setup.

The next source-grounded experiment should use Microsoft's documented original `dotNetFx40_Full_x86_x64.exe /x:<EXTRACT>` offline extraction option in a separate temporary directory, without invoking installation, and validate that the unpacked MSI files are legitimate outputs of the original signed hash-pinned media **before** privately querying their `CustomAction` table. Do not export Microsoft binaries or raw action names to public artifacts.
