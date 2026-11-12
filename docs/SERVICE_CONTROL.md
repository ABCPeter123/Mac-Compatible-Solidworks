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

## Scope

A passing test establishes only these Service Control Manager operations. It does not prove compatibility with kernel drivers, system-level license services, SOLIDWORKS background components, Windows service accounts, or CAD functionality.

No SOLIDWORKS executable, installer, license or proprietary component is used. Native Windows testing is restricted to an ephemeral CI runner; Wine uses isolated, disposable prefixes.

The next application-level milestone remains a legitimately licensed SOLIDWORKS installer and an interactive Mac test environment.
