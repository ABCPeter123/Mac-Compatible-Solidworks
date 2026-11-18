/*
 * Source-authored, read-only Win32 SCM presence and running-state probe.
 * Does not start, configure, register, modify or stop any service.
 * Never prints service paths, registry keys, tokens or GetLastError values.
 * Only emits fixed public-service-name and finite-state categories.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    const wchar_t *wide_name;
    const char *field;
} SERVICE_TARGET;

static const SERVICE_TARGET targets[] = {
    {L"TrustedInstaller", "TRUSTEDINSTALLER"},
    {L"msiserver", "MSISERVER"},
    {L"wuauserv", "WUAUSERV"},
    {L"BITS", "BITS"},
    {L"clr_optimization_v4.0.30319_64", "CLR_OPTIMIZATION_64"},
    {L"clr_optimization_v4.0.30319_32", "CLR_OPTIMIZATION_32"},
    {L"MSDTC", "MSDTC"}
};

/* Report both existence and current Win32 service state.
 * Never configure, start, stop, or impersonate a service.
 * Do not expose process IDs, exit codes or raw Windows error strings. */
typedef struct {
    const char *presence;
    const char *state;
} SERVICE_INFO;

static SERVICE_INFO service_information(SC_HANDLE manager, const wchar_t *name) {
    SERVICE_INFO info = {"UNKNOWN", "NOT_APPLICABLE"};
    SC_HANDLE service = OpenServiceW(manager, name, SERVICE_QUERY_STATUS);
    SERVICE_STATUS_PROCESS current;
    DWORD bytes_needed = 0;
    DWORD err;

    if (service == NULL) {
        err = GetLastError();
        if (err == ERROR_SERVICE_DOES_NOT_EXIST)
            info.presence = "ABSENT";
        else if (err == ERROR_ACCESS_DENIED)
            info.presence = "ACCESS_DENIED";
        return info;
    }
    info.presence = "PRESENT";
    info.state = "QUERY_FAILED";
    memset(&current, 0, sizeof(current));
    if (QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO,
                             (LPBYTE)&current, sizeof(current),
                             &bytes_needed)) {
        switch (current.dwCurrentState) {
            case SERVICE_STOPPED:          info.state = "STOPPED"; break;
            case SERVICE_START_PENDING:    info.state = "START_PENDING"; break;
            case SERVICE_STOP_PENDING:     info.state = "STOP_PENDING"; break;
            case SERVICE_RUNNING:          info.state = "RUNNING"; break;
            case SERVICE_CONTINUE_PENDING: info.state = "CONTINUE_PENDING"; break;
            case SERVICE_PAUSE_PENDING:    info.state = "PAUSE_PENDING"; break;
            case SERVICE_PAUSED:           info.state = "PAUSED"; break;
            default:                       info.state = "OTHER"; break;
        }
    }
    CloseServiceHandle(service);
    return info;
}

int main(int argc, char **argv) {
    size_t i;
    if (argc == 2 && strcmp(argv[1], "--selftest") == 0) {
        /* Does not call SCM. Confirms this self-authored MSVC x64 exe
         * starts and writes through the native Windows CRT under Wine. */
        puts("SWCOMPAT_SCM_FIXTURE_SELFTEST=PASS");
        fflush(stdout);
        return 0;
    }
    if (argc != 1)
        return 2;
    SC_HANDLE manager = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    printf("SWCOMPAT_SCM_API_SCHEMA=2\n");
    printf("SWCOMPAT_SCM_API_STATUS=%s\n",
           manager ? "COMPLETE" : "UNAVAILABLE");
    for (i = 0; i < sizeof(targets) / sizeof(targets[0]); ++i) {
        SERVICE_INFO info = manager
            ? service_information(manager, targets[i].wide_name)
            : (SERVICE_INFO){"UNKNOWN", "NOT_APPLICABLE"};
        printf("SWCOMPAT_SCM_API_%s=%s\\n", targets[i].field, info.presence);
        printf("SWCOMPAT_SCM_STATE_%s=%s\\n", targets[i].field, info.state);
    }
    if (manager)
        CloseServiceHandle(manager);
    fflush(stdout);
    return 0; /* Diagnostic completion never implies a service exists. */
}
