# Current priority: .NET Framework 4.8.1 prerequisite 5100

**Only active runtime blocker:** original Microsoft .NET Framework 4.8.1 installation on Apple Silicon Wine. On two fresh CI experiments ([43743135426](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/actions/runs/43743135426), [43744752248](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/actions/runs/43744752248)), original Microsoft .NET 4.0 x64 CLR was installed, loaded, executed native-only managed code, and survived a Wine restart following the msxml3 sequence. Other runs failed, so the setup lifecycle is not deterministic. A timeout is not a successful setup exit.

Authentic 4.8.1 in-place attempts on the native 4.0 prefix returned **5100**, a Microsoft **system-requirements** code, under Wine-reported Windows 10 and Windows 11 **21H2**. Microsoft supports separate 4.8.1 installation on both corresponding real Windows OS generations. The installer-specific prerequisite condition is **unknown** and Wine's DISM/CBS compatibility is **not proven**. `clr.dll` remained from 4.0, 4.8.1 Release registration was absent, and `framework481_confirmed` remained false.

**November 15 diagnostic update:** [Original signed setup run 43772523756](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/actions/runs/43772523756) confirmed 5100 again despite installer-observed supported Windows 10 and >5 GB available in each tested Windows disk-space API. Original 4.8.1 CLR still did not install. This rules out a simple disk-space shortfall, not all installer disk or servicing conditions. The Winetricks original .NET 4.8 recipe previously timed out after 840 seconds, before any 4.8 CLR could be verified. The default Microsoft setup test remains manual-only.

**November 16 original .NET 4.8 result:** Merged [PR #127](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/pull/127) introduced a separately verified signed original 4.8 direct intermediate. [One-shot run 43782461040](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/actions/runs/43782461040) verified the existing native .NET 4.0 CLR after restart, but authentic Microsoft **4.8** setup on Wine Windows 7 also returned exact **5100**, with a nonzero child and private **PREREQUISITE** log phase. CLR64 did not change; .NET 4.8 Release was NOT_FOUND, and original 4.8.1 was safely skipped. The earlier Winetricks timeout was not the sole problem. The temporary PR #128 was closed unmerged. The normal signed test workflow remains manual-only.

**November 16 Windows 7 SP1 differential:** Merged [PR #129](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/pull/129) and [run 43784060118](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/actions/runs/43784060118) established that **both** Windows GetVersionExW and RtlGetVersion return **SP1_OR_LATER** under Apple Silicon Wine Windows 7 for both bare and manifested self-authored probes. No raw OS strings leave the runner. This rules out a missing *reported* Windows 7 SP1 as the 4.8 cause, but does not prove working Windows servicing/update support. Wine Win10/Win11 still demonstrates a manifest-sensitive GetVersionExW version lie, so never equate a probe's OS string with actual original setup requirements.

**November 16 primary/secondary StopBlock findings:** [PR #130](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/pull/130) added version-scoped original .NET 4.8 fresh secondary log scanning. Signed [run 43786328357](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/actions/runs/43786328357) initially hit intermittent native .NET 4.0 MSI 1603 with no CLR, then a single-job rerun verified native .NET 4.0. Original signed 4.8 failed again before upgrading; 5 secondary log files were scanned, with one newly changed and one 4.8-named source but **no specific KB, servicing, or OS blocker**.

[PR #132](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/pull/132) classified the *original 4.8 primary /log* before securely deleting it. Signed [run 43788410070](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/actions/runs/43788410070) independently verified native .NET 4.0 again, and Microsoft original 4.8 primary /log positively reported **5100 / UNKNOWN_PREREQUISITE**, OS version in the Windows 7 family, **without a specific cause**; CLR64 unchanged, Release NOT_FOUND. Closed temporary one-shot PRs #131 and #133 without merging their automatic signed-installer triggers. The authentic 4.8.1 step remained gated/skipped.

**Taxonomy correction:** Merged [PR #134](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/pull/134), tested on Linux, Windows, Intel and Apple Silicon macOS. Older `BELOW_WINDOWS_10` was a **4.8.1-oriented numeric label**, NOT evidence Windows 7 is unsupported by 4.8. Original 4.8 now has distinct Windows 7 SP1/SP0/unverified service-pack categories based on the installer log itself. This corrected parser has synthetic CI verification only; do **not** attribute its new SP category to an original signed run that predates the change.

**Stop repeating unchanged installers:** The original 4.8 and 4.8.1 both fail 5100, and even primary/secondary private logs do not identify the underlying prerequisite. Do not run another costly signed 4.8 test without one new, falsifiable missing-dependency or Windows-servicing hypothesis. No SOLIDWORKS runtime session has succeeded.

## Next actions, in order

1. **Identify one specific original setup prerequisite** through read-only authenticated original 4.8/4.8.1 installer configuration, OS servicing/update checks, or narrow Windows-versus-Wine API differentials. Existing primary/secondary log classifiers produced only `UNKNOWN_PREREQUISITE`. Do not re-run unchanged installer combinations or equate a Wine OS profile with a working Windows servicing stack.
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
