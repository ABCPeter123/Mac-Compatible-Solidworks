# Full compatibility diagnostic: Apple Silicon Wine and SOLIDWORKS

**Measured November 16, 2026.** Repository: `ABCPeter123/Mac-Compatible-Solidworks`. Primary new run: [full authenticated diagnostic 43794812817](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/actions/runs/43794812817). Historical observations below are each linked to the source experiment. This is a diagnostic, **not** a claim that SOLIDWORKS runs on macOS.

## Scope and trust boundary

- Windows 2025 runner authenticated two **unchanged original Microsoft** offline .NET installers with Authenticode. It inspected archive metadata and selected embedded files **without executing setup**.
- Apple Silicon macOS 15 GitHub Actions used a checksum-pinned Wine Staging 11.21 engine and a newly marked disposable Wine prefix. It ran a negative Windows servicing contract against a deliberately nonexistent CAB. No original Microsoft package was applied.
- Original Microsoft MZZ, CAB and DLL content stayed private on Windows runners. Published outputs were finite enums and counts. No vendor binaries, original filenames/paths, logs, license data or personal information were committed or uploaded.
- There was **no interactive, GPU-capable physical Mac**, no successful authentic .NET 4.8/4.8.1 runtime installation, and no authenticated SOLIDWORKS sketch/extrude/save execution. A green diagnostic workflow means **tests and evidence collection passed**, not that application compatibility passed.

## 1. Runtime and installer gate matrix

| Area | Observed status | Direct evidence | Interpretation |
| --- | --- | --- | --- |
| Apple Silicon executes ordinary x64 Win32 code | **PASS for independent probes** | [Native CLR workstream](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/actions/runs/43788410070) | Useful baseline, does not establish all Win32/COM/graphics APIs |
| Microsoft .NET Framework 4.0 x64 | **PASS intermittently after restart** | [43788410070](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/actions/runs/43788410070), [43790580774](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/actions/runs/43790580774) | Original CLR PE_AMD64 present, native loader LOADED, native-only managed probe PASS; original installer can also fail MSI 1603 or time out |
| Original Microsoft .NET 4.8 direct setup | **FAIL: 5100** | [43788410070](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/actions/runs/43788410070) | Original setup itself reported 5100/prerequisite and Windows 7-family OS; no classified specific KB, servicing or other blocker; CLR hash unchanged, Release NOT_FOUND |
| Winetricks `dotnet48` with pinned Wine binary paths | **FAIL: bounded timeout** | [43790580774](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/actions/runs/43790580774) | Reached `DOTNET48_PACKAGE_MENTIONED`, but timed out at 840s. Native CLR64 unchanged and genuine 4.8 Release NOT_FOUND. Binary selection alone did not fix installation |
| Original Microsoft .NET 4.8.1 setup | **FAIL: 5100** | [43772523756](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/actions/runs/43772523756) | Installer returned system-requirements rejection on supported reported Windows generations, native 4.8.1 runtime not verified |
| DISM/CBS install contract under Wine | **FALSE SUCCESS confirmed** | [full diagnostic 43794406958](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/actions/runs/43794406958) | Wine `dism.exe /Online /Add-Package` returns zero when supplied a nonexistent CAB. Success cannot prove any authentic Microsoft servicing transaction completed |
| Original licensed SOLIDWORKS install/launch/part creation | **NOT DEMONSTRATED** | [milestone #7](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/issues/7) | No supported claim of working SOLIDWORKS on macOS |

**Critical:** Windows 7 SP1 is reported by both independently tested Win32 and NT version APIs under the specific Wine 7 profile ([43784060118](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/actions/runs/43784060118)). That does **not** prove correct servicing, hotfix applicability, MSI custom actions or vendor bootstrapper behavior. The .NET 4.8 versus 4.8.1 version-requirement taxonomy was corrected in [PR #134](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/pull/134). Never interpret an older `BELOW_WINDOWS_10` label as proof Windows 7 SP1 is intrinsically unsupported by **4.8**. The exact original 4.8 error 5100 prerequisite remains unidentified.

## 2. New authenticated Microsoft package forensics

Both original installer publishers were validated as Microsoft Corporation before reading private archives. The following values are from the signed, **read-only** package diagnostic, not a Wine installation.

| Original media | .NET Framework 4.8 | .NET Framework 4.8.1 |
| --- | --- | --- |
| Outer archive status | LISTED | LISTED |
| Outer archive entries | **180** | **131** |
| Outer CAB container count | **12** | **3** |
| CAB containers successfully listed | **8 / 12** | **1 / 3** |
| Nested CAB entries listed | **7,616** | **1,777** |
| Nested CAB result | **PARTIAL** | **PARTIAL** |
| CLR and mscorlib signals in listed CABs | Both present | Both present |
| Authentic MZZ archives successfully listed | **1 / 1** | **0 found** |
| Members of classified MZZ | **1,643** | Not applicable |
| MZZ DLL / EXE / other member groups | **96 / 1 / 1,546** | Not applicable |
| MZZ CLR-like and mscorlib-like names | **Present** | Not applicable |
| MZZ x64 and WPF-like member signals | **Present** | Not applicable |
| Native x64 CLR member PE header | **PE_AMD64** | Not measured through MZZ |
| Native x64 mscorlib member PE header | **PE_AMD64** | Not measured through MZZ |

Source: [signed package run 43794812817](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/actions/runs/43794812817) and the privacy-safe artifacts `authentic-netfx-48-diagnostic-categories-only` and `authentic-netfx-481-diagnostic-categories-only`. A later targeted regex regression recognizes both dotted and underscore-encoded original MZZ member names. No original DLL was executed, copied to Wine or uploaded.

**Consequences:**

1. The original .NET 4.8 installer carries Microsoft-origin, genuine **PE_AMD64** CLR and mscorlib payload candidates. We are no longer blocked on merely locating the native x64 CLR files.
2. The MZZ archive is a **real read-only forensic path** independent of Windows setup 5100. It does **not** establish a valid manual installation procedure. A functional runtime additionally requires a coherent set of dependent binaries, native hosting/Fusion, correct .NET registry and COM installation, Windows Installer state, assemblies and real managed execution.
3. Both CAB scans are **partial**. The scanner found positive CLR/servicing signals, but we cannot infer the contents or applicability of the unlisted containers. Never label the archive census complete.
4. .NET Framework 4.8.1 here is chiefly a servicing/CAB packaging problem. No MZZ source was found by the bounded direct or CAB-contained search. This is **not** proof none exists at deeper layers or in alternative media.
5. The individual extracted PE header indicates architecture only; original package authenticity was established by the signed enclosing installer. Do not equate a header with proof the extracted file is safe or correctly installed.

## 3. Windows compatibility subsystems

| Subsystem | Existing test result | Remaining incompatibility |
| --- | --- | --- |
| Windows Service Control Manager on Apple Silicon | A same-process self-authored service can start, reach a nonzero PID, stop and delete | Newly launched Win32 processes can fail to reopen the registered service with Windows error **1060**; service database locking **1055** also observed. [Issue #16](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/issues/16) |
| Windows MSI custom actions and service transitions | Self-authored tests prove some transactions and installation actions, with native Windows controls | The general cross-process service lifecycle is not established under Wine. The authentic .NET 4.0 MSI sometimes fails **1603**. [Issue #16](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/issues/16), [issue #74](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/issues/74) |
| DISM/CBS Microsoft Windows servicing | This diagnostic confirms **DISM_FALSE_SUCCESS** for a missing package | Wine cannot be trusted to apply .NET 4.8.1 CAB servicing solely on exit 0; must verify actual package applicability, component/registry changes and native CLR execution |
| WebView2 x64 controller and DOM | Official Microsoft Evergreen Runtime installs; environment, controller, navigation, DOM and script tests succeed | Browser image capture and compositor callbacks time out; **no macOS rendered pixels yet proved**. [Issue #26](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/issues/26) |
| Independent OpenGL WGL software rasterizer | Mesa llvmpipe OpenGL 4.5, color/depth rendering proved in earlier synthetic tests | Full hardware-backed interactive SOLIDWORKS viewport untested, hosted WGL pixel-format limitations exist. [Issue #1](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/issues/1), [issue #7](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/issues/7) |
| Vulkan-to-OpenGL via Zink | Apple Silicon Wine can enumerate Vulkan device and load genuine Mesa DLLs | Tested MoltenVK device lacks required `robustness2.nullDescriptor`; Mesa Zink initialization fails. [Issue #3](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/issues/3) |
| Native Metal host graphics | Native Metal diagnostics run in compatibility CI | This alone does not provide Windows OpenGL or a visible CAD interface |
| SOLIDWORKS installer and license path | Private original-media gate exists, not a demonstration of usable CAD | Need an actual licensed installer on a GPU/display-capable physical or interactive Mac, with appropriate confidentiality and no license bypass. [Milestone #7](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/issues/7) |

**There is no single proven fix.** .NET 4.8/4.8.1 installation, Windows servicing, SCM cross-process state, embedded Chromium painting, and accelerated graphics are distinct compatibility problems. Passing synthetic hardware/Win32 tests does not imply the proprietary CAD stack will work.

## 4. Ranked engineering decisions

1. **First: native .NET 4.8 dependency/loader proof from authenticated MZZ.** Continue read-only PE/import/assembly inventory, identify the exact coherent x64 runtime/hosting dependencies, and test a bounded native CLR load in a disposable prefix without presenting a binary copy as a supported installation. Never fake a `Release` registry value. Successful native-only managed execution and genuine runtime registration are essential.
2. **Next: bounded Winetricks child-level hang diagnosis.** The corrected binary-routing recipe reaches the original package stage and still hangs at 840s. Observe its exact child lifecycle and blocked Windows API/service in a narrowly scoped process diagnostic; avoid another unchanged full installer run.
3. **Next: real CBS transaction semantics.** Validate a source-authored servicing operation and compare against real Windows, rejecting false DISM success. Only attempt original 4.8.1 servicing after proving a meaningful package transaction.
4. **In parallel: service, browser and graphics gates.** Resolve cross-process SCM access, verify actual painted WebView2 pixels, and obtain passing WGL rendering with an appropriate GPU/host or a documented software fallback. Native Metal success is insufficient by itself.
5. **Finally: real SOLIDWORKS.** Authenticate only appropriately licensed media, test installer/launch under an interactive Mac, then run create sketch, extrude, rotate/zoom, save/reopen and STEP I/O. No success should be claimed until those actions are observed.

## 5. Test discipline

- Do not repeat Windows 7/10 version changes, direct 5100 setups, or 840-second Winetricks trials unchanged. Each new run needs a different and falsifiable hypothesis.
- Do not mark genuine runtime readiness from a registry marker, CLR filename, installer timeout, Windows API return value, MZZ/CAB inventory or self-authored harness alone.
- Continue to publish **only finite categories and counts**. Vendor media, license information, private installer paths, Microsoft binaries, extracted CLR DLLs and logs stay out of public Git and artifacts.
- GitHub-hosted macOS is not a substitute for verifying an interactive CAD viewport or full local user experience.

**Current verdict: native Windows execution is partially demonstrated, but a functioning macOS SOLIDWORKS implementation is not.** The authenticated MZZ x64 CLR payload is the strongest newly confirmed technical lead.
