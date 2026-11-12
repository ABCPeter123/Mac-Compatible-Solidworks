/* Self-authored Win64 service and SCM controller.
 * No SOLIDWORKS components or real licensing services are involved.
 * CI uses a disposable Wine prefix or an ephemeral Windows runner.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsvc.h>
#include <stdio.h>
#include <wchar.h>

static const wchar_t *SERVICE_NAME = L"SWCompatOriginalServiceTest";
static SERVICE_STATUS_HANDLE service_handle;
static HANDLE stop_event;
static SERVICE_STATUS status;

static void set_state(DWORD state, DWORD controls, DWORD hint) {
    status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    status.dwCurrentState = state;
    status.dwControlsAccepted = controls;
    status.dwWin32ExitCode = NO_ERROR;
    status.dwServiceSpecificExitCode = 0;
    status.dwCheckPoint = state == SERVICE_START_PENDING || state == SERVICE_STOP_PENDING ? 1 : 0;
    status.dwWaitHint = hint;
    SetServiceStatus(service_handle, &status);
}

static VOID WINAPI control_handler(DWORD control) {
    if (control == SERVICE_CONTROL_STOP || control == SERVICE_CONTROL_SHUTDOWN) {
        set_state(SERVICE_STOP_PENDING, 0, 3000);
        if (stop_event) SetEvent(stop_event);
    }
}

static VOID WINAPI service_main(DWORD count, LPWSTR *args) {
    (void)count; (void)args;
    service_handle = RegisterServiceCtrlHandlerW(SERVICE_NAME, control_handler);
    if (!service_handle) return;
    set_state(SERVICE_START_PENDING, 0, 3000);
    stop_event = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!stop_event) {
        set_state(SERVICE_STOPPED, 0, 0);
        return;
    }
    set_state(SERVICE_RUNNING, SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN, 0);
    WaitForSingleObject(stop_event, INFINITE);
    set_state(SERVICE_STOPPED, 0, 0);
    CloseHandle(stop_event);
    stop_event = NULL;
}

static int result(const char *phase, DWORD error, DWORD observed, BOOL success) {
    printf("SWCOMPAT_SERVICE_PHASE=%s\n", phase);
    printf("SWCOMPAT_SERVICE_ERROR=%lu\n", (unsigned long)error);
    printf("SWCOMPAT_SERVICE_STATE=%lu\n", (unsigned long)observed);
    printf("SWCOMPAT_SERVICE_CHECK=%s\n", success ? "PASS" : "FAIL");
    fflush(stdout);
    return success ? 0 : 1;
}

static DWORD await_state(SC_HANDLE handle, DWORD required) {
    for (int i = 0; i < 80; i++) {
        SERVICE_STATUS_PROCESS current = {0};
        DWORD bytes = 0;
        if (!QueryServiceStatusEx(handle, SC_STATUS_PROCESS_INFO,
                                  (BYTE*)&current, sizeof(current), &bytes))
            return 0;
        if (current.dwCurrentState == required) return required;
        if (current.dwCurrentState == SERVICE_STOPPED && required != SERVICE_STOPPED)
            return current.dwCurrentState;
        Sleep(125);
    }
    SERVICE_STATUS_PROCESS current = {0};
    DWORD bytes = 0;
    if (QueryServiceStatusEx(handle, SC_STATUS_PROCESS_INFO,
                             (BYTE*)&current, sizeof(current), &bytes))
        return current.dwCurrentState;
    return 0;
}

static int manage(const wchar_t *action, const wchar_t *exe) {
    const char *phase = "unknown";
    if (!wcscmp(action, L"absent")) phase = "absent";
    else if (!wcscmp(action, L"install")) phase = "install";
    else if (!wcscmp(action, L"status")) phase = "status";
    else if (!wcscmp(action, L"start")) phase = "start";
    else if (!wcscmp(action, L"stop")) phase = "stop";
    else if (!wcscmp(action, L"delete")) phase = "delete";
    else return 2;

    DWORD scm_rights = !wcscmp(action,L"install")
                       ? SC_MANAGER_CREATE_SERVICE | SC_MANAGER_CONNECT : SC_MANAGER_CONNECT;
    SC_HANDLE scm = OpenSCManagerW(NULL, NULL, scm_rights);
    if (!scm) return result(phase, GetLastError(), 0, FALSE);
    DWORD state = 0, error = 0;
    BOOL ok = FALSE;
    SC_HANDLE handle = NULL;

    if (!wcscmp(action, L"install")) {
        if (!exe || !*exe) {
            CloseServiceHandle(scm);
            return result(phase, ERROR_INVALID_PARAMETER, 0, FALSE);
        }
        size_t len = wcslen(exe);
        if (len > 2500) {
            CloseServiceHandle(scm);
            return result(phase, ERROR_INSUFFICIENT_BUFFER, 0, FALSE);
        }
        wchar_t command[2600] = {0};
        swprintf(command, 2600, L"\"%ls\" run", exe);
        handle = CreateServiceW(scm, SERVICE_NAME, L"SWCompat Independent Test Service",
                    SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
                    SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL, command,
                    NULL, NULL, NULL, NULL, NULL);
        ok = handle != NULL;
        if (!ok) error = GetLastError();
    } else if (!wcscmp(action, L"absent")) {
        handle = OpenServiceW(scm, SERVICE_NAME, SERVICE_QUERY_STATUS);
        if (!handle) {
            error = GetLastError();
            ok = error == ERROR_SERVICE_DOES_NOT_EXIST;
        } else {
            error = ERROR_SERVICE_EXISTS;
            ok = FALSE;
        }
    } else {
        DWORD rights = SERVICE_QUERY_STATUS;
        if (!wcscmp(action, L"start")) rights |= SERVICE_START;
        if (!wcscmp(action, L"stop")) rights |= SERVICE_STOP;
        if (!wcscmp(action, L"delete")) rights |= DELETE;
        handle = OpenServiceW(scm, SERVICE_NAME, rights);
        if (!handle) error = GetLastError();
        else if (!wcscmp(action, L"status")) {
            SERVICE_STATUS_PROCESS process = {0};
            DWORD bytes = 0;
            ok = QueryServiceStatusEx(handle, SC_STATUS_PROCESS_INFO,
                                      (BYTE*)&process, sizeof(process), &bytes);
            if (ok) {
                state = process.dwCurrentState;
                printf("SWCOMPAT_SERVICE_PID=%lu\n",
                       (unsigned long)process.dwProcessId);
                printf("SWCOMPAT_SERVICE_WIN32_EXIT=%lu\n",
                       (unsigned long)process.dwWin32ExitCode);
            } else {
                error = GetLastError();
            }
        }
        else if (!wcscmp(action, L"start")) {
            ok = StartServiceW(handle, 0, NULL);
            if (!ok) error = GetLastError();
            if (ok) {
                state = await_state(handle, SERVICE_RUNNING);
                ok = state == SERVICE_RUNNING;
                if (!ok) error = ERROR_SERVICE_REQUEST_TIMEOUT;
            }
        } else if (!wcscmp(action, L"stop")) {
            SERVICE_STATUS current = {0};
            ok = ControlService(handle, SERVICE_CONTROL_STOP, &current);
            if (!ok) error = GetLastError();
            if (ok) {
                state = await_state(handle, SERVICE_STOPPED);
                ok = state == SERVICE_STOPPED;
                if (!ok) error = ERROR_SERVICE_REQUEST_TIMEOUT;
            }
        } else {
            ok = DeleteService(handle);
            if (!ok) error = GetLastError();
        }
    }

    if (handle) CloseServiceHandle(handle);
    CloseServiceHandle(scm);
    return result(phase, error, state, ok);
}

/* Distinguish cross-process SCM registry visibility from service startup.
 * The controller retains its SC_HANDLE throughout every operation.
 * This is a separate fresh-prefix experiment, not a runtime workaround. */
static int single_process_roundtrip(void) {
    wchar_t exe[MAX_PATH] = {0};
    DWORD length = GetModuleFileNameW(NULL, exe, MAX_PATH);
    if (!length || length >= MAX_PATH) {
        return result("single-module-path", GetLastError(), 0, FALSE);
    }
    SC_HANDLE scm = OpenSCManagerW(NULL, NULL,
        SC_MANAGER_CREATE_SERVICE | SC_MANAGER_CONNECT);
    if (!scm) return result("single-open-scm", GetLastError(), 0, FALSE);
    wchar_t cmd[MAX_PATH + 16] = {0};
    swprintf(cmd, MAX_PATH + 16, L"\"%ls\" run", exe);
    SC_HANDLE handle = CreateServiceW(scm, SERVICE_NAME,
        L"SWCompat Independent Single-Process Service",
        SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
        SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
        cmd, NULL, NULL, NULL, NULL, NULL);
    if (!handle) {
        DWORD error = GetLastError();
        CloseServiceHandle(scm);
        return result("single-create", error, 0, FALSE);
    }
    puts("SWCOMPAT_SERVICE_SINGLE_CREATE=PASS");
    fflush(stdout);
    DWORD start_error = 0, stop_error = 0, delete_error = 0;
    DWORD running = 0, stopped = 0, process_id = 0;
    BOOL started = StartServiceW(handle, 0, NULL);
    if (!started) start_error = GetLastError();
    if (started) {
        running = await_state(handle, SERVICE_RUNNING);
        SERVICE_STATUS_PROCESS state = {0};
        DWORD bytes = 0;
        if (QueryServiceStatusEx(handle, SC_STATUS_PROCESS_INFO,
                                 (BYTE*)&state, sizeof(state), &bytes))
            process_id = state.dwProcessId;
    }
    printf("SWCOMPAT_SERVICE_SINGLE_START_ERROR=%lu\n", (unsigned long)start_error);
    printf("SWCOMPAT_SERVICE_SINGLE_RUNNING_STATE=%lu\n", (unsigned long)running);
    printf("SWCOMPAT_SERVICE_SINGLE_RUNNING_PID=%lu\n", (unsigned long)process_id);
    fflush(stdout);

    if (started && running == SERVICE_RUNNING) {
        SERVICE_STATUS current = {0};
        BOOL sent = ControlService(handle, SERVICE_CONTROL_STOP, &current);
        if (!sent) stop_error = GetLastError();
        else stopped = await_state(handle, SERVICE_STOPPED);
    }
    printf("SWCOMPAT_SERVICE_SINGLE_STOP_ERROR=%lu\n", (unsigned long)stop_error);
    printf("SWCOMPAT_SERVICE_SINGLE_STOPPED_STATE=%lu\n", (unsigned long)stopped);
    fflush(stdout);

    BOOL deleted = DeleteService(handle);
    if (!deleted) delete_error = GetLastError();
    CloseServiceHandle(handle);
    int gone = 0;
    if (deleted) {
        for (int i = 0; i < 30; i++) {
            SC_HANDLE lookup = OpenServiceW(scm, SERVICE_NAME, SERVICE_QUERY_STATUS);
            if (!lookup && GetLastError() == ERROR_SERVICE_DOES_NOT_EXIST) {
                gone = 1;
                break;
            }
            if (lookup) CloseServiceHandle(lookup);
            Sleep(100);
        }
    }
    CloseServiceHandle(scm);
    printf("SWCOMPAT_SERVICE_SINGLE_DELETE_ERROR=%lu\n", (unsigned long)delete_error);
    printf("SWCOMPAT_SERVICE_SINGLE_REMOVED=%d\n", gone);
    int pass = started && running == SERVICE_RUNNING && process_id != 0 &&
               stopped == SERVICE_STOPPED && deleted && gone;
    printf("SWCOMPAT_SERVICE_SINGLE_PROCESS=%s\n", pass ? "PASS" : "FAIL");
    fflush(stdout);
    return pass ? 0 : 1;
}

int wmain(int argc, wchar_t **argv) {
    if (argc < 2) {
        fputs("Usage: service_smoke.exe single-roundtrip|run|hold|absent|install <path>|status|start|stop|delete\n",stderr);
        return 2;
    }
    if (!wcscmp(argv[1], L"single-roundtrip"))
        return single_process_roundtrip();
    if (!wcscmp(argv[1], L"hold")) {
        /* Diagnostic only: retain one active client of the same Wine prefix
         * while other Wine controllers register/start/stop the service.
         * A successful lifecycle here would isolate wineserver churn. */
        puts("SWCOMPAT_SERVICE_KEEPALIVE=READY");
        fflush(stdout);
        Sleep(180000);
        return 0;
    }
    if (!wcscmp(argv[1], L"run")) {
        SERVICE_TABLE_ENTRYW dispatch[] = {
            {(LPWSTR)SERVICE_NAME, service_main},
            {NULL, NULL}
        };
        if (!StartServiceCtrlDispatcherW(dispatch))
            return result("run", GetLastError(), 0, FALSE);
        return 0;
    }
    return manage(argv[1], argc > 2 ? argv[2] : NULL);
}
