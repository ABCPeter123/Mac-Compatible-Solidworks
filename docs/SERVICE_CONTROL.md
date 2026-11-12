# Windows Service Control Manager functionality

SOLIDWORKS installations can depend on Windows service infrastructure. This experiment evaluates actual Windows Service Control Manager behavior with a harmless, original Windows x64 program.

## Functional test

The test registers the fixed name `SWCompatOriginalServiceTest` inside a disposable Wine prefix (or on an ephemeral Windows CI runner). The service does no background work. It reports `SERVICE_RUNNING`, handles `SERVICE_CONTROL_STOP`, reports `SERVICE_STOPPED`, and exits.

The harness checks the following sequence using separate Windows processes:

1. Verify the test service does not already exist.
2. Use `CreateServiceW` to register the test executable.
3. Use `StartServiceW` and `QueryServiceStatusEx` to confirm the running state.
4. Stop the service with `ControlService` and confirm the stopped state.
5. Use `DeleteService` and verify absence.

It refuses to overwrite an unexpectedly existing service. The cleanup handler attempts to stop/delete the test service if a later assertion fails.

The [CI workflow](../.github/workflows/windows-service-ci.yml) compares native Windows Server 2025, Linux Wine and Wine 11.21 running on Apple Silicon macOS. Test results are stored as JSON artifacts.

## Service process lifetime and Wine client persistence

The first comparison run exposed two failures under Wine but not native Windows:

- Linux Wine 9.0: `CreateServiceW` and `StartServiceW` reported success; immediately afterward, a different controller process saw `SERVICE_STOPPED` with process ID zero, and `ControlService(STOP)` returned error 1062.
- Apple Silicon macOS Wine 11.21: service registration initially appeared successful, but later controllers intermittently returned error 1060 (`ERROR_SERVICE_DOES_NOT_EXIST`).

The [persistent-client follow-up run](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/actions/runs/43294124739) runs the same test while a separate harmless Windows executable remains alive in the same Wine prefix. Linux Wine now passes the full lifecycle, including a nonzero service process ID, STOP and deletion. The Apple Silicon result must be assessed independently.

The harness exposes `--keepalive`, which starts `service_smoke.exe hold` before the controller sequence and terminates it afterward. This avoids reliance on the `wineserver -p` command, which failed to initialize when called directly on the Ubuntu runner. The hold process performs no Windows registry changes, service operations or background work.

**Interpretation:** The before/after comparison supports Wine client/server lifetime as the cause of the Linux failure. It is not proof that all Windows service types work in a production Wine session. The exact mechanism and macOS behavior require separate confirmation.

## Single-process service diagnostic

Because macOS Wine still returns `ERROR_SERVICE_DOES_NOT_EXIST` from later SCM controller processes even with an unrelated Wine client held open, we added a separate diagnostic mode: `service_smoke.exe single-roundtrip`.

It creates, starts, queries, stops and deletes the same harmless Windows service while retaining **one** Service Control Manager connection and service handle. It runs in another fresh Wine prefix, outside the primary test. The output includes Win32 startup/stop errors, service process ID, and deletion status.

A same-process PASS with a cross-process FAIL would indicate a registry/SCM visibility issue between processes. A same-process FAIL would instead point to service startup or process management itself. Neither result should be treated as evidence about proprietary SOLIDWORKS licensing.

The [same-process diagnostic](../probes/win_service_smoke.c) also queries the SCM database lock status when service startup returns Windows error 1055 and retries the start operation a bounded number of times. The lock query reports only locked state and duration, never the identity of the lock owner.

## Apple Silicon start-lock breakthrough

The [Mac lock-diagnostic run](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/actions/runs/43296397170) established that the original Windows service **can** run on Apple Silicon Wine 11.21. The initial same-process `StartServiceW` call returned error 1055 (service database locked). The `QueryServiceLockStatusW` query also returned error 1055, so it could not report a lock owner. Four more startup attempts returned 1055. The fifth succeeded, producing `SERVICE_RUNNING` with process ID 640. STOP, service removal, and final absence checks passed.

The regular cross-process test still failed with error 1060. A follow-up therefore makes **bounded, narrowly scoped retries** for Win32 errors 1055 and 1060 on service startup, without retrying unrelated failures. Each startup attempt and its result remain visible in the JSON log. No result is reported as passing unless the service is observed running and can stop and deregister successfully.

Microsoft documents `QUERY_SERVICE_LOCK_STATUS.dwLockDuration` in **seconds**. The diagnostic marker reports the correct unit.

## Service access-rights differential

The standard Wine experiment verifies service registration through `SERVICE_QUERY_STATUS` before attempting startup through `SERVICE_QUERY_STATUS | SERVICE_START`. Because macOS has allowed the status lookup but returned error 1060 from the startup controller, the probe now records **six** `OpenServiceW` access masks separately: QUERY, START, STOP, DELETE, QUERY+START and ALL_ACCESS. This operation does not start or modify a service.

The same test also queries access rights while retaining the original SCM handle in the single-process control. Comparing these two sets of signals will distinguish an access-rights problem from service-object visibility between processes. No workaround is considered validated until an actual service can run, stop and be deleted using the intended lifecycle.

## Confirmed Apple Silicon access-rights comparison

In [run 43298673742](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/actions/runs/43298673742) the Mac cross-process lifecycle failed even with a persistent Wine client and bounded 1055/1060 retries.

The detailed `OpenServiceW` probe gave the following comparison:

| Access mask | Separate process after registration | Original controller holding SCM handle |
| --- | --- | --- |
| SERVICE_QUERY_STATUS | ERROR_SERVICE_DOES_NOT_EXIST (1060) | Open succeeds |
| SERVICE_START | ERROR_SERVICE_DOES_NOT_EXIST (1060) | Open succeeds |
| SERVICE_STOP | ERROR_SERVICE_DOES_NOT_EXIST (1060) | Open succeeds |
| DELETE | ERROR_SERVICE_DOES_NOT_EXIST (1060) | Open succeeds |
| SERVICE_QUERY_STATUS plus SERVICE_START | ERROR_SERVICE_DOES_NOT_EXIST (1060) | Open succeeds |
| SERVICE_ALL_ACCESS | ERROR_SERVICE_DOES_NOT_EXIST (1060) | Open succeeds |

In the same-process diagnostic, startup initially returned 1055 (`ERROR_SERVICE_DATABASE_LOCKED`) but succeeded on the fifth retry. The service then ran with process ID 640, stopped and was deleted successfully.

**Conclusion supported by this experiment:** the Wine 11.21 Apple Silicon SCM test service is not consistently discoverable from separate controller processes. All tested masks fail in that context, so adjusting the access mask alone is not a workaround. A same-process service lifecycle is demonstrated, but general cross-process service compatibility is not.

This finding is limited to the GitHub-hosted macOS 15 Apple Silicon runner and the pinned Gcenx Wine 11.21 distribution. It does not establish the behavior of other macOS Wine builds or physical hardware.

## Staging runtime comparison

The Wine development build `wine-devel-11.21-osx64.tar.xz` consistently fails cross-process service discovery on GitHub-hosted Apple Silicon even though the same process can create, start, stop and remove the original Windows service.

Gcenx also publishes `wine-staging-11.21-osx64.tar.xz` (SHA-256: `d7bcd5abf4df27aae397a7898aef074fea4a2e0b51e0a55aa9659517bbf9d452`). The SCM CI now tests this **separate upstream Staging build** in an isolated prefix with the identical service executable and harness. It is an experiment; passing would require further regression tests for MSI, COM, .NET and OpenGL before a project-wide runtime switch.

Source: https://github.com/Gcenx/macOS_Wine_builds/releases/tag/11.21

## Wine Staging comparison

The [Wine Staging 11.21 Apple Silicon run](https://github.com/ABCPeter123/Mac-Compatible-Solidworks/actions/runs/43300033831) reproduced the development build's results. The same original service binary under the checksum-pinned Staging release:

- Failed cross-process `OpenServiceW` for all six tested access masks with error 1060.
- Succeeded at same-process creation, service start after retry 5, running state, stop, and deletion.

Both Wine development 11.21 and Wine Staging 11.21 therefore have the same observable cross-process service-object visibility issue on the tested GitHub-hosted Mac. Changing only the Wine flavor is **not** a confirmed fix. We are retaining both test traces rather than switching the production compatibility baseline.

## Scope

A passing test establishes only these Service Control Manager operations. It does not prove compatibility with kernel drivers, system-level license services, SOLIDWORKS background components, Windows service accounts, or CAD functionality.

No SOLIDWORKS executable, installer, license or proprietary component is used. Native Windows testing is restricted to an ephemeral CI runner; Wine uses isolated, disposable prefixes.

The next application-level milestone remains a legitimately licensed SOLIDWORKS installer and an interactive Mac test environment.
