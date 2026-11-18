/*
 * Source-authored, read-only Win32 SCM presence probe.
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

static const char *service_presence(SC_HANDLE manager, const wchar_t *name) {
    SC_HANDLE service = OpenServiceW(manager, name, SERVICE_QUERY_STATUS);
    if (service != NULL) {
        CloseServiceHandle(service);
        return "PRESENT";
    }
    switch (GetLastError()) {
        case ERROR_SERVICE_DOES_NOT_EXIST:
            return "ABSENT";
        case ERROR_ACCESS_DENIED:
            return "ACCESS_DENIED";
        default:
            return "UNKNOWN";
    }
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
    printf("SWCOMPAT_SCM_API_SCHEMA=1\n");
    printf("SWCOMPAT_SCM_API_STATUS=%s\n",
           manager ? "COMPLETE" : "UNAVAILABLE");
    for (i = 0; i < sizeof(targets) / sizeof(targets[0]); ++i) {
        const char *value = manager
            ? service_presence(manager, targets[i].wide_name)
            : "UNKNOWN";
        printf("SWCOMPAT_SCM_API_%s=%s\n", targets[i].field, value);
    }
    if (manager)
        CloseServiceHandle(manager);
    fflush(stdout);
    return 0; /* Diagnostic completion never implies a service exists. */
}
