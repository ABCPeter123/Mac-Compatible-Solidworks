/*
 * Read-only Windows Installer infrastructure probe, compiled with MSVC x64.
 * No installation, start-service, service configuration, registry modification,
 * MSI database contents, paths, process names or private information are output.
 *
 * A loaded msi.dll and its exports do NOT prove a functional install pipeline.
 */
#define UNICODE
#define _UNICODE
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsvc.h>
#include <stdio.h>
#include <wchar.h>

static const char *registry_state(void) {
    HKEY key = NULL;
    LONG code = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Services\\msiserver",
        0, KEY_READ | KEY_WOW64_64KEY, &key);
    if (code == ERROR_SUCCESS) {
        RegCloseKey(key);
        return "PRESENT";
    }
    return (code == ERROR_FILE_NOT_FOUND || code == ERROR_PATH_NOT_FOUND)
        ? "ABSENT" : "UNAVAILABLE";
}

static void service_state(const char **registration, const char **runtime) {
    SC_HANDLE manager = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    SC_HANDLE service;
    DWORD code, needed = 0;
    SERVICE_STATUS_PROCESS status;
    *registration = "UNAVAILABLE";
    *runtime = "NOT_VERIFIED";
    if (!manager) return;
    service = OpenServiceW(manager, L"msiserver", SERVICE_QUERY_STATUS);
    if (!service) {
        code = GetLastError();
        *registration = (code == ERROR_SERVICE_DOES_NOT_EXIST)
            ? "ABSENT" : "UNAVAILABLE";
        CloseServiceHandle(manager);
        return;
    }
    *registration = "PRESENT";
    ZeroMemory(&status, sizeof(status));
    if (QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO,
                            (LPBYTE)&status, sizeof(status), &needed)) {
        switch (status.dwCurrentState) {
            case SERVICE_STOPPED: *runtime = "STOPPED"; break;
            case SERVICE_RUNNING: *runtime = "RUNNING"; break;
            case SERVICE_START_PENDING: *runtime = "START_PENDING"; break;
            default: *runtime = "OTHER"; break;
        }
    } else {
        *runtime = "UNAVAILABLE";
    }
    CloseServiceHandle(service);
    CloseServiceHandle(manager);
}

static const char *msi_api_state(void) {
    HMODULE dll = LoadLibraryW(L"msi.dll");
    FARPROC open_database, install_product;
    if (!dll) return "LOAD_FAILED";
    open_database = GetProcAddress(dll, "MsiOpenDatabaseW");
    install_product = GetProcAddress(dll, "MsiInstallProductW");
    FreeLibrary(dll);
    return (open_database && install_product) ? "BOTH_PRESENT" :
           (open_database || install_product) ? "PARTIAL" : "NO_EXPORTS";
}

static const char *msiexec_state(void) {
    WCHAR system[MAX_PATH], exe[MAX_PATH];
    UINT len = GetSystemDirectoryW(system, MAX_PATH);
    DWORD attrs, code;
    if (!len || len >= MAX_PATH ||
        swprintf_s(exe, MAX_PATH, L"%ls\\msiexec.exe", system) < 0)
        return "UNAVAILABLE";
    attrs = GetFileAttributesW(exe);
    if (attrs == INVALID_FILE_ATTRIBUTES) {
        code = GetLastError();
        return (code == ERROR_FILE_NOT_FOUND || code == ERROR_PATH_NOT_FOUND)
            ? "ABSENT" : "UNAVAILABLE";
    }
    return (attrs & FILE_ATTRIBUTE_DIRECTORY) ? "UNAVAILABLE" : "PRESENT";
}

int main(void) {
    const char *registration, *runtime;
    service_state(&registration, &runtime);
    puts("SWCOMPAT_MSI_SCHEMA=1");
    printf("SWCOMPAT_MSI_REGISTRY=%s\n", registry_state());
    printf("SWCOMPAT_MSI_SERVICE=%s\n", registration);
    printf("SWCOMPAT_MSI_SERVICE_STATE=%s\n", runtime);
    printf("SWCOMPAT_MSI_DLL_API=%s\n", msi_api_state());
    printf("SWCOMPAT_MSI_EXEC=%s\n", msiexec_state());
    return 0;
}
