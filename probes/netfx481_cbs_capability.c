/*
 * Independent Windows x64 component servicing capability inventory.
 * This is a READ-ONLY probe: never install, remove, activate or stage a package.
 * Report ONLY fixed string states. No registry values, paths, service IDs, PID,
 * command lines, error strings, Microsoft data or arbitrary output.
 */
#define UNICODE
#define _UNICODE
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsvc.h>
#include <stdio.h>
#include <wchar.h>

static const char *query_registry(void) {
    HKEY key = NULL;
    LONG rc = RegOpenKeyExW(
        HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing",
        0, KEY_READ | KEY_WOW64_64KEY, &key);
    if (rc == ERROR_SUCCESS) {
        RegCloseKey(key);
        return "PRESENT";
    }
    return rc == ERROR_FILE_NOT_FOUND ? "ABSENT" : "UNAVAILABLE";
}

static const char *query_packages(void) {
    WCHAR windows_dir[MAX_PATH];
    WCHAR full[MAX_PATH];
    DWORD size = GetWindowsDirectoryW(windows_dir, MAX_PATH);
    DWORD attrs;
    if (!size || size >= MAX_PATH ||
        swprintf_s(full, MAX_PATH, L"%ls\\servicing\\Packages", windows_dir) < 0)
        return "UNAVAILABLE";
    attrs = GetFileAttributesW(full);
    if (attrs == INVALID_FILE_ATTRIBUTES)
        return GetLastError() == ERROR_FILE_NOT_FOUND ||
                       GetLastError() == ERROR_PATH_NOT_FOUND
                   ? "ABSENT" : "UNAVAILABLE";
    return (attrs & FILE_ATTRIBUTE_DIRECTORY) ? "PRESENT" : "UNAVAILABLE";
}

static const char *query_trusted_installer(void) {
    SC_HANDLE manager = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    SC_HANDLE service;
    DWORD error;
    if (manager == NULL)
        return "UNAVAILABLE";
    service = OpenServiceW(manager, L"TrustedInstaller", SERVICE_QUERY_STATUS);
    if (service != NULL) {
        CloseServiceHandle(service);
        CloseServiceHandle(manager);
        return "PRESENT";
    }
    error = GetLastError();
    CloseServiceHandle(manager);
    return error == ERROR_SERVICE_DOES_NOT_EXIST ? "ABSENT" : "UNAVAILABLE";
}

static const char *query_dismapi(void) {
    HMODULE dll;
    FARPROC proc;
    DWORD attrs = GetFileAttributesW(L"C:\\Windows\\System32\\dismapi.dll");
    if (attrs == INVALID_FILE_ATTRIBUTES)
        return "ABSENT";
    if (attrs & FILE_ATTRIBUTE_REPARSE_POINT)
        return "UNAVAILABLE";
    dll = LoadLibraryW(L"C:\\Windows\\System32\\dismapi.dll");
    if (!dll)
        return "LOAD_FAILED";
    proc = GetProcAddress(dll, "DismOpenSession");
    FreeLibrary(dll);
    return proc ? "EXPORT_PRESENT" : "EXPORT_MISSING";
}

int main(void) {
    puts("SWCOMPAT_CBS_SCHEMA=1");
    printf("SWCOMPAT_CBS_REGISTRY=%s\n", query_registry());
    printf("SWCOMPAT_CBS_PACKAGES=%s\n", query_packages());
    printf("SWCOMPAT_CBS_TRUSTEDINSTALLER=%s\n", query_trusted_installer());
    printf("SWCOMPAT_CBS_DISMAPI=%s\n", query_dismapi());
    return 0;
}
