# Current priority: .NET Framework 4.8.1 prerequisite 5100

**Only active runtime blocker:** original Microsoft .NET Framework 4.8.1 installation on Apple Silicon Wine. On two fresh CI experiments ([43743135426](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/actions/runs/43743135426), [43744752248](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/actions/runs/43744752248)), original Microsoft .NET 4.0 x64 CLR was installed, loaded, executed native-only managed code, and survived a Wine restart following the msxml3 sequence. Other runs failed, so the setup lifecycle is not deterministic. A timeout is not a successful setup exit.

Authentic 4.8.1 in-place attempts on the native 4.0 prefix returned **5100**, a Microsoft **system-requirements** code, under Wine-reported Windows 10 and Windows 11 **21H2**. Microsoft supports separate 4.8.1 installation on both corresponding real Windows OS generations. The installer-specific prerequisite condition is **unknown** and Wine's DISM/CBS compatibility is **not proven**. `clr.dll` remained from 4.0, 4.8.1 Release registration was absent, and `framework481_confirmed` remained false.

**November 15 diagnostic update:** [Original signed setup run 43772523756](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/actions/runs/43772523756) confirmed 5100 again despite installer-observed supported Windows 10 and >5 GB available in each tested Windows disk-space API. Original 4.8.1 CLR still did not install. This rules out a simple disk-space shortfall, not all installer disk or servicing conditions. The Winetricks original .NET 4.8 recipe previously timed out after 840 seconds, before any 4.8 CLR could be verified. The default Microsoft setup test remains manual-only.

**One controlled intermediate candidate:** [PR #127](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/pull/127) adds manual-dispatch input `try_48_direct` that fetches the signed original .NET 4.8 offline installer on Windows, runs it after independently verified native 4.0 under isolated Wine Windows 7 profile, restores Windows 10, and gates subsequent original 4.8.1 strictly on an actually changed native CLR, authentic 4.8 Release range, successful setup lifecycle, and native-only managed execution. This is **not** a substitute for 4.8.1. Never select `try_48_direct` and `try_48_intermediate` together. No direct signed 4.8 experiment outcome is yet verified.


## Next actions, in order

1. **Diagnose the authentic 5100 condition** using one short-lived, sanitized prerequisite report from the original installer. Measure which setup condition rejected Wine, rather than changing winver again. A Wine-reported supported version is not proof of the real Windows servicing environment.
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
