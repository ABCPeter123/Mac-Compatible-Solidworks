# Independent Windows SCM query while another process holds an SCM connection

The original Apple Silicon Wine 11.21 service MSI exits ZERO, installs the exact benign service executable and writes its service key. Prior studies showed cross-process `OpenServiceW` could return 1060 even though `CreateServiceW` could return 1073 (already exists) or CREATED. The single-connection PR #72 finally measured `OpenServiceW PRESENT` twice while retaining one `OpenSCManagerW` handle, hence `CROSS_PROCESS_DISAGREEMENT`. This is not direct evidence of exactly why Wine differs.

## New experiment

This follow-up uses the same native MSVC service fixture and original source-backed MSI on a clean, marked, disposable Wine prefix on GitHub-hosted Apple Silicon.

- Confirm that the MSI-installed executable bytes match the original fixture and that its hard-coded service registry key persists. Require validated prior same-connection evidence.
- Measure the original service from one separate Win32 controller.
- Start another original Windows process via Wine. Its new `scm-hold` mode retains a real `OpenSCManagerW` connection and attempts to hold `OpenServiceW(SERVICE_QUERY_STATUS)` when present. It prints one fixed readiness marker and sleeps for a maximum 50 seconds.
- Only after that marker is observed, query the service from yet **another** independent Win32 controller while the holder is still running. Always terminate the test holder.
- Query once more after the holder closes. The report contains only finite enum statuses, no process IDs, Win32 paths, registry values or raw Wine output.

Outcomes: `VISIBLE_ONLY_WITH_HOLDER` requires a genuine open *service handle*, earlier absent status, a separately observed running or stopped status during the hold, and absent status again after release. `STILL_ABSENT_WITH_HOLDER` requires continued absence with the actual service handle retained. `UNRESOLVED` covers all other timing and API outcomes. Merely opening the manager is **not** equivalent to holding a service and cannot count as recovery.

A positive result would justify testing a finite SCM-holder compatibility helper. A negative result points toward Wine services.exe / RPC-session routing or service database rehydration. It would still not establish the Microsoft CLR or SOLIDWORKS service/activation compatibility.

Prior source-backed upstream inspection shows Wine `svcctl_OpenServiceW` consults `scmdatabase_find_service()` while `services.exe` loads registry service entries into an in-memory database at startup. The observed mismatches are not yet a proven defect in those lines, so no blind patch is made.

See [Wine RPC service source](https://github.com/wine-mirror/wine/blob/master/programs/services/rpc.c), [Wine service database source](https://github.com/wine-mirror/wine/blob/master/programs/services/services.c), and [original one-connection trial](MSI_SERVICE_SCM_COHERENCE.md).

## Evidence-driven follow-up: distinguish independent lookup failures

The first Apple Silicon holder run completed, confirmed `SERVICE_OPEN`, and measured `UNKNOWN` for the three external service status probes, even while the holder retained an actual service handle. This is **not** evidence that the SCM lookup returned error 1060; the old query helper collapsed start failures, Wine process exit status, timeouts and invalid probe output into the same category.

The follow-up uses the original source-built Windows status controller and checks its process outcome independently. Each query now retains the existing `ABSENT/RUNNING/STOPPED/UNKNOWN` status and adds a **single finite diagnostic class**:

- `PARSED`: strict four-field original Win32 marker protocol passed and yielded a recognized service result.
- `LAUNCH_FAILED`: Wine or the original service probe could not be started.
- `TIMED_OUT`: the Windows controller did not finish within the bounded timeout.
- `BAD_EXIT`: the controller exited outside the defined original zero/one result protocol.
- `NO_PROTOCOL`: no original service-status protocol header appeared.
- `MALFORMED`: the protocol header appeared but strict parsing failed.
- `OVERSIZED`: controller output exceeded 2048 bytes.
- `NOT_EXECUTED`: the holder did not become ready or exited before a legitimate concurrent query.
 
No arbitrary stdout or stderr, Win32 code, user path, or service registry contents enter the result. Only successful actual Windows API status markers may justify service visibility. Once these three categories are measured on Apple Silicon, the next fix can target service RPC/SCM lookup if `PARSED`, or the Wine process/probe boundary if another error occurs. No .NET or SOLIDWORKS compatibility claim changes.


## Reproducible malformed-marker evidence, PR #75

The source-backed Apple Silicon run [43664513342](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/actions/runs/43664513342) measured `SERVICE_OPEN` in the holder and `MALFORMED` for all three independent Win32 status queries (before, during and after retaining the service handle). This rules out classifying those three reports as process launch errors or timeouts. It still cannot determine whether the Win32 status API or our marker protocol produced the malformed response.

The next controlled test takes the **same** bounded stdout buffer already used by the original strict `service_result` parser and reports why validation failed using only fixed categories: `NUL_BYTE`, `INVALID_MARKER`, `DUPLICATE_MARKER`, `MISSING_MARKER`, `WRONG_PHASE`, `UNRECOGNIZED_STATUS`, `OVERSIZED`, `BAD_EXIT`, and `NO_HEADER`. A valid status becomes `VALID`. The actual raw buffer, service names, process IDs and paths are never persisted. Existing strict status semantics remain unchanged. Any candidate fix must respond to the observed category, not invent a missing Wine API.


## Concrete parser defect found in PR #76

The real Apple Silicon job [43665129268](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/actions/runs/43665129268) reported `INVALID_MARKER` for all three independent status queries, although the Wine child process exited within the allowed status-controller protocol. This pointed to a mismatch between our **own** original C probe output and Python parser:

- `probes/win_service_smoke.c` emits `SWCOMPAT_SERVICE_WIN32_EXIT=<bounded number>` whenever a service status query succeeds. This is a legitimate diagnostic marker in addition to four required service status fields.
- `scripts/msi_service_action_trial.py` used `[A-Z_]+` for the marker **name**, which excludes the digits `32` in `WIN32_EXIT`. The entire response was therefore rejected as `UNKNOWN`, even if all required fields were otherwise valid.
- The precise fix is `[A-Z0-9_]+` for the marker name, while preserving the four required fields, unique marker checks, strict enumerated output, and rejection of malformed extra service lines.

This fixes a **test harness false negative**. It does not by itself demonstrate that the Wine service becomes visible through the SCM from a new process or that native Microsoft .NET Framework works. The same original MSI and independent service fixture must be rerun on Apple Silicon to measure the corrected service state.


## Verified independent SCM recovery after Wine restart, corrected parser

The [first parser-corrected Apple Silicon run 43665377780](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/actions/runs/43665377780) installed the original harmless MSI with Windows Installer return ZERO and exact binary bytes `PRESENT_MATCH`. The independent service lookup before restart was **ABSENT**, while the service registry was **PRESENT**. After the same disposable Wine prefix underwent the bounded `wineboot --restart`, the subsequent independent Win32 controller observed **STOPPED** and the original service registry was still **PRESENT**. `service_visibility_recovered=True` was genuinely measured. This is **not** a running service or Microsoft CLR.

That run's last CI gate failed because an old assertion required the `CreateServiceW`-based reconciliation trial to be `MEASURED`. The original script correctly chose `NOT_APPLICABLE` because no repair was needed once the service was visible. The gate is now conditional: when the real restart, original MSI success, exact installed binary, registry persistence and independent `STOPPED/RUNNING` result are all proved, it **requires** the repair, same-connection and holder trials to be `NOT_APPLICABLE`, not fake measured successes. If restart does not restore independent service visibility, it still requires the full API-reconciliation trial and its strict evidence gates.

This result supports testing a controlled, bounded SCM refresh **between distinct prerequisite installers** in a disposable Wine prefix. It does **not** prove that Wine can complete a service's own `InstallServices`+`StartServices` actions within a single MSI transaction, or that Microsoft's .NET Framework or SOLIDWORKS can install.
