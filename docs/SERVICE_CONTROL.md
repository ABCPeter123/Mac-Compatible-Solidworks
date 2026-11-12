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

## Scope

A passing test establishes only these Service Control Manager operations. It does not prove compatibility with kernel drivers, system-level license services, SOLIDWORKS background components, Windows service accounts, or CAD functionality.

No SOLIDWORKS executable, installer, license or proprietary component is used. Native Windows testing is restricted to an ephemeral CI runner; Wine uses isolated, disposable prefixes.

The next application-level milestone remains a legitimately licensed SOLIDWORKS installer and an interactive Mac test environment.
