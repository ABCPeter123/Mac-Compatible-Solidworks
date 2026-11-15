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
