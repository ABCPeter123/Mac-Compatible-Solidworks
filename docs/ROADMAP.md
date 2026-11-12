# Milestones and evidence

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
