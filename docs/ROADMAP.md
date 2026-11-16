# Current priority: .NET Framework 4.8.1 prerequisite 5100

**Authenticated .NET 4.8 CLR loader breakthrough (November 16, 2026):** [Merged PR #141](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/pull/141), [original Apple Silicon run 43798619311](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/actions/runs/43798619311). Independent Microsoft Authenticode and same-run SHA256 authenticated original .NET 4.8 offline media. The original x64 native clr.dll returned MISSING_DEPENDENCY (Win32 error 126) initially. Five of seven direct DLL imports loaded, and the missing VCRUNTIME and OTHER libraries were both found in the same authenticated MZZ; both extracted x64 original libraries passed PE checks and the exact same original clr.dll then returned **LOADED, EXIT_ZERO**. No proprietary runtime files were published or installed, no synthetic Release marker written, and no managed code execution was measured. The next distinct gate is [PR #142](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/pull/142): test ICLRMetaHost/ICLRRuntimeHost discovery and start, reject unrelated runtimes including Wine Mono, and execute independent managed code only if the host is provably bound to the original CLR directory. A compiled fixture or green CI infrastructure alone is not managed execution, .NET installation, .NET 4.8.1 support, or SOLIDWORKS compatibility.

**Native .NET 4.8 dependency milestone (November 16, 2026):** [PR #138](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/pull/138) merged. The original, Microsoft-signed 4.8 MZZ payload has a genuine x64 native CLR PE with **7 statically linked imports and 18 delayed imports**, inspected via actual bounded PE RVA tables; x64 mscorlib has a CLI metadata directory and no static DLL imports. CLR's direct set includes NTDLL, KERNEL32, ADVAPI32, USER32, SHLWAPI, VCRUNTIME plus one `OTHER`; delayed set includes four API-set, three cryptography, one MSCOREE, one network, one OLE32, one OLEAUT32, one VERSION and six `OTHER`. [Signed diagnostic run 43795489931](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/actions/runs/43795489931) passed all four jobs. Results and next experiment in [NETFX48_NATIVE_IMPORT_GRAPH.md](NETFX48_NATIVE_IMPORT_GRAPH.md). **Historical status for PR #138 only:** original runtime was not loaded in that earlier import-graph run. The later authenticated [run 43798619311](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/actions/runs/43798619311) independently established original native CLR **LOADED** after staging its two original DLL dependencies, but no managed execution or genuine runtime registration.

**Full-scale compatibility diagnostic (November 16, 2026):** see [FULL_COMPATIBILITY_DIAGNOSTIC_2026-11-16.md](FULL_COMPATIBILITY_DIAGNOSTIC_2026-11-16.md) and [authenticated diagnostic workflow 43794812817](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/actions/runs/43794812817). The original signed .NET 4.8 offline package contains one readable MZZ archive with 1,643 members; read-only extraction verified genuine **PE_AMD64** CLR and mscorlib member architectures, without claiming a working runtime. Original 4.8/4.8.1 CAB inspections remain **PARTIAL**. Apple Silicon Wine DISM returned **FALSE SUCCESS** for an intentionally missing CAB. Windows servicing is therefore not a trustworthy manual replacement for the failed installer. No new original vendor setup was executed for this diagnostic; no SOLIDWORKS runtime workflow was demonstrated. The next high-value engineering gate is coherent x64 CLR dependency/hosting analysis, not repeating setup 5100 or the 840-second Winetricks timeout.


**Only active runtime blocker:** original Microsoft .NET Framework 4.8.1 installation on Apple Silicon Wine. On two fresh CI experiments ([43743135426](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/actions/runs/43743135426), [43744752248](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/actions/runs/43744752248)), original Microsoft .NET 4.0 x64 CLR was installed, loaded, executed native-only managed code, and survived a Wine restart following the msxml3 sequence. Other runs failed, so the setup lifecycle is not deterministic. A timeout is not a successful setup exit.

Authentic 4.8.1 in-place attempts on the native 4.0 prefix returned **5100**, a Microsoft **system-requirements** code, under Wine-reported Windows 10 and Windows 11 **21H2**. Microsoft supports separate 4.8.1 installation on both corresponding real Windows OS generations. The installer-specific prerequisite condition is **unknown** and Wine's DISM/CBS compatibility is **not proven**. `clr.dll` remained from 4.0, 4.8.1 Release registration was absent, and `framework481_confirmed` remained false.

**November 15 diagnostic update:** [Original signed setup run 43772523756](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/actions/runs/43772523756) confirmed 5100 again despite installer-observed supported Windows 10 and >5 GB available in each tested Windows disk-space API. Original 4.8.1 CLR still did not install. This rules out a simple disk-space shortfall, not all installer disk or servicing conditions. The Winetricks original .NET 4.8 recipe previously timed out after 840 seconds, before any 4.8 CLR could be verified. The default Microsoft setup test remains manual-only.

**November 16 original .NET 4.8 result:** Merged [PR #127](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/pull/127) introduced a separately verified signed original 4.8 direct intermediate. [One-shot run 43782461040](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/actions/runs/43782461040) verified the existing native .NET 4.0 CLR after restart, but authentic Microsoft **4.8** setup on Wine Windows 7 also returned exact **5100**, with a nonzero child and private **PREREQUISITE** log phase. CLR64 did not change; .NET 4.8 Release was NOT_FOUND, and original 4.8.1 was safely skipped. The earlier Winetricks timeout was not the sole problem. The temporary PR #128 was closed unmerged. The normal signed test workflow remains manual-only.

**November 16 Windows 7 SP1 differential:** Merged [PR #129](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/pull/129) and [run 43784060118](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/actions/runs/43784060118) established that **both** Windows GetVersionExW and RtlGetVersion return **SP1_OR_LATER** under Apple Silicon Wine Windows 7 for both bare and manifested self-authored probes. No raw OS strings leave the runner. This rules out a missing *reported* Windows 7 SP1 as the 4.8 cause, but does not prove working Windows servicing/update support. Wine Win10/Win11 still demonstrates a manifest-sensitive GetVersionExW version lie, so never equate a probe's OS string with actual original setup requirements.

**November 16 primary/secondary StopBlock findings:** [PR #130](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/pull/130) added version-scoped original .NET 4.8 fresh secondary log scanning. Signed [run 43786328357](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/actions/runs/43786328357) initially hit intermittent native .NET 4.0 MSI 1603 with no CLR, then a single-job rerun verified native .NET 4.0. Original signed 4.8 failed again before upgrading; 5 secondary log files were scanned, with one newly changed and one 4.8-named source but **no specific KB, servicing, or OS blocker**.

[PR #132](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/pull/132) classified the *original 4.8 primary /log* before securely deleting it. Signed [run 43788410070](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/actions/runs/43788410070) independently verified native .NET 4.0 again, and Microsoft original 4.8 primary /log positively reported **5100 / UNKNOWN_PREREQUISITE**, OS version in the Windows 7 family, **without a specific cause**; CLR64 unchanged, Release NOT_FOUND. Closed temporary one-shot PRs #131 and #133 without merging their automatic signed-installer triggers. The authentic 4.8.1 step remained gated/skipped.

**Taxonomy correction:** Merged [PR #134](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/pull/134), tested on Linux, Windows, Intel and Apple Silicon macOS. Older `BELOW_WINDOWS_10` was a **4.8.1-oriented numeric label**, NOT evidence Windows 7 is unsupported by 4.8. Original 4.8 now has distinct Windows 7 SP1/SP0/unverified service-pack categories based on the installer log itself. This corrected parser has synthetic CI verification only; do **not** attribute its new SP category to an original signed run that predates the change.

**November 16 Winetricks binary-routing experiment:** [PR #135](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/pull/135) corrected the Winetricks host environment by passing actual pinned `WINE_BIN`, `WINESERVER_BIN`, and `WINE_BINDIR` and invoking via Bash. An independent 2026 Wine project reports this fixes certain Wine binary-detection failures and can install .NET 4.8, but warns about native x64 CLR crashes. In our project, Apple Silicon [smoke run 43790224034](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/actions/runs/43790224034) verified Winetricks can use the exact pinned engine with no Microsoft media. The distinct [signed experiment 43790580774](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/actions/runs/43790580774) then confirmed a working Microsoft .NET 4.0 CLR, but corrected `bash winetricks -q dotnet48` again **timed out after 840 seconds**, at private progress category `DOTNET48_PACKAGE_MENTIONED`. The native x64 CLR hash was unchanged, .NET 4.8 Release NOT_FOUND, and native-only managed code still ran only on .NET 4.0. 4.8.1 was correctly skipped. One-shot PR #136 closed UNMERGED. This rules out incorrect binary selection *alone* as a fix for the native 4.8 installation stall.

**Stop repeating unchanged installers:** The original 4.8 and 4.8.1 both fail 5100, and even primary/secondary private logs do not identify the underlying prerequisite. Do not run another costly signed 4.8 or Winetricks test without a newly identified, falsifiable blocking call/requirement. Prefer read-only authentication and archive inventory of official 4.8 payloads, especially nested MZZ/CAB files and genuine native x64 CLR PE provenance, before designing an installation alternative. No vendor payloads or logs belong in Git. No SOLIDWORKS runtime session has succeeded.

## Next actions, in order

1. **Identify a concrete alternative to the failed bootstrapper** by read-only inspection of authentic Microsoft 4.8 offline package structure and nested payloads (including archived CLR libraries), or determine one exact blocking Winetricks child/Windows servicing dependency. Validate archive type, PE architecture and signed-media provenance before proposing any changes to a marked disposable Wine prefix. Current evidence does not establish a manual native CLR installation recipe. Original installer configuration and Windows-versus-Wine API differentials remain other candidates. Existing primary/secondary log classifiers produced only `UNKNOWN_PREREQUISITE`. Do not re-run unchanged installer combinations or equate a Wine OS profile with a working Windows servicing stack.
2. **Test only the missing prerequisite** with a source-authored Windows-versus-Wine differential. If it is CBS, model the exact original update transaction and reject DISM false-success. Do not write an ungrounded registry or service shim.
3. **Make 4.8.1 independently verifiable:** original runtime file change, native CLR load, managed functionality, authentic Release registration and successful installer outcome. No synthetic Release values.
4. **Only then** attempt the licensed SOLIDWORKS installer and actual sketch/extrude/save workflow on an interactive Mac or equivalent test environment.

**Already investigated:** ordinary self-authored deferred MSI transactions, SCM query/create, registry create/read/write/cleanup and original DLL import census. These tests passed, but do not establish Microsoft setup behavior. Preserve their evidence; do not repeat them without a new failing hypothesis. The original deferred DLL statically imports registry and process APIs but no recognized SCM APIs.

**CI policy:** [Compatibility foundation](../.github/workflows/compatibility-ci.yml) runs tests automatically. Expensive authenticated Microsoft install/upgrade runs require explicit manual dispatch. Refer to [CI scoping](CI_SCOPING.md) and [Issue #115](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/issues/115).

---

# Long-term milestones and evidence

## M0: Reproducible foundations
- [x] Dedicated Wine prefix and non-invasive command launcher
- [x] Win32 and WGL diagnostics from source
- [x] Unit tests and no-Mac cloud CI configuration
- [ ] Confirm all hosted jobs pass on both Mac architectures

**Acceptance:** each cloud job produces a clear PASS/FAIL result and reports any unavailable hardware capability honestly.

## M1: Windows API/graphics feasibility on macOS
- [ ] Choose a maintained, redistributable Wine build for Intel and Apple Silicon
- [ ] Execute a Windows x64 console test on each target host
- [ ] Create and render a WGL context on each target host
- [ ] Record runtime versions, renderer strings and reproducible logs

**Acceptance:** real Win32 and WGL probes pass under Wine on macOS. Linux-only success is insufficient.

## M2: SOLIDWORKS installer and dependencies
- [ ] Identify legitimate installer version and target requirements
- [ ] Validate redistributable dependencies and COM services
- [x] Install Microsoft-signed WebView2 Runtime and create a real controller in isolated Apple Silicon Wine; Linux Wine remains unsuccessful
- [ ] Verify HTML/DOM rendering and genuine SOLIDWORKS installer behavior
- [ ] Record crashes, missing exports, registry failures and unsupported APIs
- [ ] Keep activation and software licensing intact

**Acceptance:** a legally licensed installation can complete reproducibly.

## M3: First useful CAD session
- [ ] Launch SOLIDWORKS without patching its proprietary binaries
- [ ] Create sketch, extrude body, save and reopen a part
- [ ] Validate basic 3D viewport performance and stability

**Acceptance:** a reproducible editable-part workflow with documented defects.

## M4: Compatibility improvements
- [ ] Feature history, assembly operations, drawings
- [ ] Regression fixtures and benchmark suite
- [ ] Native launcher packaging and isolation

This is a compatibility research project, not a claim of a complete SOLIDWORKS macOS port. It may uncover blockers that cannot be solved within the available time or licensing constraints.
