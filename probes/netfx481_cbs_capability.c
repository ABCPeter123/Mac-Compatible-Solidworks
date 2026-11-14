/*
 * Read-only Windows x64 component servicing inventory.
 * Dynamic advapi32 resolution deliberately avoids static imports from that
 * DLL, allowing partial results even if Wine cannot load service APIs.
 * No registry mutation, service mutation, DISM execution or raw output.
 */
#define UNICODE
#define _UNICODE
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsvc.h>
#include <stdio.h>
#include <wchar.h>

typedef LSTATUS (WINAPI *PRegOpenKeyExW)(
    HKEY, LPCWSTR, DWORD, REGSAM, PHKEY);
typedef LSTATUS (WINAPI *PRegCloseKey)(HKEY);
typedef SC_HANDLE (WINAPI *POpenSCManagerW)(LPCWSTR, LPCWSTR, DWORD);
typedef SC_HANDLE (WINAPI *POpenServiceW)(SC_HANDLE, LPCWSTR, DWORD);
typedef BOOL (WINAPI *PCloseServiceHandle)(SC_HANDLE);

static HMODULE get_advapi(void) {
    return LoadLibraryW(L"advapi32.dll");
}

static const char *query_registry(void) {
    HMODULE api = get_advapi();
    PRegOpenKeyExW open;
    PRegCloseKey close;
    HKEY key = NULL;
    LSTATUS rc;
    if (!api) return "UNAVAILABLE";
    open = (PRegOpenKeyExW)GetProcAddress(api, "RegOpenKeyExW");
    close = (PRegCloseKey)GetProcAddress(api, "RegCloseKey");
    if (!open || !close) {
        FreeLibrary(api);
        return "UNAVAILABLE";
    }
    rc = open(HKEY_LOCAL_MACHINE,
              L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing",
              0, KEY_READ | KEY_WOW64_64KEY, &key);
    if (rc == ERROR_SUCCESS) close(key);
    FreeLibrary(api);
    return rc == ERROR_SUCCESS ? "PRESENT" :
           rc == ERROR_FILE_NOT_FOUND ? "ABSENT" : "UNAVAILABLE";
}

static const char *query_packages(void) {
    WCHAR windows_dir[MAX_PATH];
    WCHAR full[MAX_PATH];
    DWORD size = GetWindowsDirectoryW(windows_dir, MAX_PATH);
    DWORD attrs, error;
    if (!size || size >= MAX_PATH ||
        swprintf_s(full, MAX_PATH, L"%ls\\servicing\\Packages", windows_dir) < 0)
        return "UNAVAILABLE";
    attrs = GetFileAttributesW(full);
    if (attrs == INVALID_FILE_ATTRIBUTES) {
        error = GetLastError();
        return (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND)
               ? "ABSENT" : "UNAVAILABLE";
    }
    return (attrs & FILE_ATTRIBUTE_DIRECTORY) ? "PRESENT" : "UNAVAILABLE";
}

static const char *query_trusted_installer(void) {
    HMODULE api = get_advapi();
    POpenSCManagerW open_manager;
    POpenServiceW open_service;
    PCloseServiceHandle close;
    SC_HANDLE manager, service;
    DWORD error;
    if (!api) return "UNAVAILABLE";
    open_manager = (POpenSCManagerW)GetProcAddress(api, "OpenSCManagerW");
    open_service = (POpenServiceW)GetProcAddress(api, "OpenServiceW");
    close = (PCloseServiceHandle)GetProcAddress(api, "CloseServiceHandle");
    if (!open_manager || !open_service || !close) {
        FreeLibrary(api);
        return "UNAVAILABLE";
    }
    manager = open_manager(NULL, NULL, SC_MANAGER_CONNECT);
    if (!manager) {
        FreeLibrary(api);
        return "UNAVAILABLE";
    }
    service = open_service(manager, L"TrustedInstaller", SERVICE_QUERY_STATUS);
    if (service) {
        close(service);
        close(manager);
        FreeLibrary(api);
        return "PRESENT";
    }
    error = GetLastError();
    close(manager);
    FreeLibrary(api);
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
