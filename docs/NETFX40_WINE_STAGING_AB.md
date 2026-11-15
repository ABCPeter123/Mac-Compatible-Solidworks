# Signed Microsoft .NET 4.0 A/B: Wine Development versus Wine Staging

The authentic Microsoft-signed, SHA-256-pinned .NET Framework 4.0 offline installer previously ran on Apple Silicon macOS under Gcenx Wine **Development 11.21**. The original Microsoft setup's complete Win32 result was `0x00000643` (1603), one immediate child exited nonzero, and independent checks found neither native Microsoft CLR binary nor managed Microsoft CLR execution. Basic self-authored MSI file installation succeeds under Wine. See [full evidence](NETFX481_REAL_RUNTIME.md) and [nested MSI error analysis](NETFX40_INNER_MSI.md).

Parallel source-backed MSI service experiments used Gcenx Wine **Staging 11.21**. On some Apple Silicon runs, a harmless original Windows service reached RUNNING and STOPPED with a real nonzero PID when a single SCM connection was retained. On other runs, the same installed service could not be opened from independent client processes. These observations do not prove the service variation caused .NET installer 1603.

## Controlled A/B

The branch changes **only the Wine distribution** used in the existing authentic .NET 4.0 Apple Silicon experiment:

| Variable | Development 11.21 reference | Staging 11.21 experiment |
| --- | --- | --- |
| Microsoft original redistributable | Exact same signed .NET 4.0 media | Identical, verified original |
| Wine package | `wine-devel-11.21-osx64.tar.xz` | `wine-staging-11.21-osx64.tar.xz` |
| Wine SHA-256 | `9909b486657e10ab66c7279371ae1f990345b596b3b1b3a0cf21f28af24fa0ce` | `d7bcd5abf4df27aae397a7898aef074fea4a2e0b51e0a55aa9659517bbf9d452` |
| Win32 monitor, probes and safe diagnostic parser | Unchanged | Unchanged |
| Wine Mono MSI cleanup, disposable prefix, XP profile, `fusion=b`, bounded setup, MSI policy | Existing controls | Unchanged |
| Runtime completion gate | Actual CLR binary and independent load/managed tasks | Unchanged |

Both builds are x86-64 Windows Wine bundles running on the hosted Apple Silicon runner. This is **not** a comparison of Wine package version (both 11.21), an installation of SOLIDWORKS or a framework activation shortcut.

CI must show the same fixed, privacy-safe fields: Microsoft installer full Windows result, MSI inner action classification, independent `clr.dll`/`mscorlib.dll` file presence, native loader and non-Mono managed execution. A green workflow means the experiment completed. The native CLR readiness flag must remain false unless all previously established evidence gates actually pass.

**Decision:** A genuine CLR success on Staging while Development fails would justify tracing which Staging patches affect Wine's MSI, service or WOW64 compatibility. If Staging also fails with 1603 and no CLR, this falsifies the simple distribution-switch hypothesis, and effort should return to the specific first failed nested MSI action and Win32 service/COM/Fusion semantics. Never claim SOLIDWORKS readiness from this test.


## Actual Apple Silicon result: Wine Staging 11.21

[Authenticated Microsoft .NET 4.0 A/B run 43665180811](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/actions/runs/43665180811) completed with success as an **evidence collection job**, not as a framework installation. Signed Microsoft media and the native Windows process monitor were verified on Windows before staging. The original Microsoft setup executed in the disposable Wine Staging prefix and returned **MSI_FATAL_ERROR (1603)**. Its immediate child was observed, all children exited and at least one exited nonzero.

Neither `Framework64\v4.0.30319\clr.dll` nor the 32-bit counterpart was present. The expected native `mscorlib.dll` was absent, and native CLR loader result was `NOT_FOUND`. The independent native candidate remains `False`.

The bounded private nested installer evidence scanned four setup logs including one MSI log but returned `NO_FAILURE_MARKER`, `first_failed_action_class=UNKNOWN` and `causality=NOT_ESTABLISHED`. The Wine error classification included `MSI_ACTION_SERVICE`, `MSI_ACTION_FINALIZE`, `MSI_TSAWARE_UNIMPLEMENTED`, and `OTHER_MSI_ERROR`; only three error lines were observed. Neither a service action nor a Wine `fixme` warning establishes the earliest causal failure.

**Conclusion:** Swapping the Wine distribution alone is insufficient. A native CLR is still not installed, and no SOLIDWORKS capability is established. Further work should focus on reproducing the first non-cascade Microsoft MSI failure, especially its service/custom-action behavior, with original Windows installer evidence and minimal independent regression fixtures. Do not forge framework registry values or suppress MSI errors.
