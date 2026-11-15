/* Self-authored x64 deferred MSI DLL custom actions.
 * One action queries SCM. The second creates, configures and deletes a
 * transient fixed-name service, but never starts or executes it.
 * No Microsoft installer binaries or SOLIDWORKS code are embedded.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsvc.h>
#include <msi.h>
#include <wchar.h>
#pragma comment(lib, "Advapi32.lib")

static BOOL report_named(const char *state, const WCHAR *filename)
{
    WCHAR path[MAX_PATH];
    DWORD count = GetWindowsDirectoryW(path, MAX_PATH);
    HANDLE out;
    DWORD wrote = 0;
    SIZE_T len;
    if (!count || count >= MAX_PATH - 48) return FALSE;
    if (wcscat_s(path, MAX_PATH, L"\\Temp\\") || wcscat_s(path, MAX_PATH, filename)) return FALSE;
    out = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if (out == INVALID_HANDLE_VALUE) return FALSE;
    len = lstrlenA(state);
    if (!WriteFile(out, state, (DWORD)len, &wrote, NULL) || wrote != len) {
        CloseHandle(out);
        return FALSE;
    }
    CloseHandle(out);
    return TRUE;
}

__declspec(dllexport) UINT __stdcall SWCompatReadOnlyScmAccess(MSIHANDLE session)
{
    SC_HANDLE manager;
    SC_HANDLE service;
    SERVICE_STATUS_PROCESS state;
    DWORD needed = 0;
    const char *result;
    (void)session;
    manager = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!manager) {
        result = "MANAGER_FAILED";
    } else {
        service = OpenServiceW(manager, L"msiserver", SERVICE_QUERY_STATUS);
        if (!service) {
            result = "SERVICE_FAILED";
        } else {
            result = QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO,
                (LPBYTE)&state, sizeof(state), &needed) ? "PASS" : "QUERY_FAILED";
            CloseServiceHandle(service);
        }
        CloseServiceHandle(manager);
    }
    if (!report_named(result, L"swcompat-deferred-scm.status")) return ERROR_INSTALL_FAILURE;
    return lstrcmpA(result, "PASS") == 0 ? ERROR_SUCCESS : ERROR_INSTALL_FAILURE;
}


/* Targeted service-registry differential. The test never starts a service.
 * The service executable path is the Windows command shell, but is never run.
 * Cleanup is attempted regardless of configuration/query result.
 * All names and status files are source-authored fixed constants.
 */
__declspec(dllexport) UINT __stdcall SWCompatTransientServiceRegistration(MSIHANDLE session)
{
    SC_HANDLE manager;
    SC_HANDLE service;
    WCHAR binary[MAX_PATH];
    DWORD length;
    DWORD needed = 0;
    SERVICE_STATUS_PROCESS state;
    SERVICE_DESCRIPTIONW description = { L"SWCompat read-only-safe lifecycle fixture" };
    const char *result = "CREATE_FAILED";
    BOOL config_ok = FALSE, query_ok = FALSE, delete_ok = FALSE;
    (void)session;
    manager = OpenSCManagerW(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (!manager) {
        result = "CREATE_MANAGER_FAILED";
    } else {
        length = GetSystemDirectoryW(binary, MAX_PATH);
        if (!length || length >= MAX_PATH - 32 ||
            wcscat_s(binary, MAX_PATH, L"\\cmd.exe")) {
            result = "CREATE_PATH_FAILED";
        } else {
            service = CreateServiceW(manager,
                L"SWCompatDeferredScmEphemeral", L"SWCompatDeferredScmEphemeral",
                DELETE | SERVICE_CHANGE_CONFIG | SERVICE_QUERY_STATUS,
                SERVICE_WIN32_OWN_PROCESS, SERVICE_DEMAND_START,
                SERVICE_ERROR_IGNORE, binary, NULL, NULL, NULL, NULL, NULL);
            if (!service) {
                result = "CREATE_FAILED";
            } else {
                config_ok = ChangeServiceConfig2W(
                    service, SERVICE_CONFIG_DESCRIPTION, &description);
                query_ok = QueryServiceStatusEx(
                    service, SC_STATUS_PROCESS_INFO, (LPBYTE)&state,
                    sizeof(state), &needed);
                delete_ok = DeleteService(service);
                result = !config_ok ? "CONFIG_FAILED"
                       : !query_ok ? "QUERY_FAILED"
                       : !delete_ok ? "DELETE_FAILED" : "PASS";
                CloseServiceHandle(service);
            }
        }
        CloseServiceHandle(manager);
    }
    if (!report_named(result, L"swcompat-deferred-scm-create.status"))
        return ERROR_INSTALL_FAILURE;
    return lstrcmpA(result, "PASS") == 0 ? ERROR_SUCCESS : ERROR_INSTALL_FAILURE;
}


/* Third source-authored deferred action: Windows registry API differential.
 * All mutations are confined to one fixed test key under HKLM\Software.
 * The key is never a .NET Framework, MSI or license configuration key.
 */
__declspec(dllexport) UINT __stdcall SWCompatTransientRegistryTransaction(MSIHANDLE session)
{
    static const WCHAR *keyname = L"SOFTWARE\\SWCompatDeferredRegistryProbe";
    static const WCHAR *valuename = L"Sentinel";
    const DWORD expected = 0x53435750;
    DWORD created = 0, type = 0, length = sizeof(DWORD), current = 0;
    HKEY key = NULL, reopened = NULL;
    LONG rc;
    BOOL success = FALSE;
    const char *result = "CREATE_FAILED";
    (void)session;
    rc = RegCreateKeyExW(HKEY_LOCAL_MACHINE, keyname, 0, NULL,
                         REG_OPTION_NON_VOLATILE,
                         KEY_READ | KEY_WRITE, NULL, &key, &created);
    if (rc == ERROR_SUCCESS && key) {
        if (created == REG_CREATED_NEW_KEY) {
            rc = RegSetValueExW(key, valuename, 0, REG_DWORD,
                                (const BYTE *)&expected, sizeof(expected));
            if (rc == ERROR_SUCCESS) {
                RegCloseKey(key); key = NULL;
                rc = RegOpenKeyExW(HKEY_LOCAL_MACHINE, keyname, 0,
                                   KEY_QUERY_VALUE, &reopened);
                if (rc == ERROR_SUCCESS && reopened) {
                    rc = RegQueryValueExW(reopened, valuename, NULL,
                                          &type, (LPBYTE)&current, &length);
                    success = rc == ERROR_SUCCESS && type == REG_DWORD
                              && length == sizeof(DWORD) && current == expected;
                }
                result = rc == ERROR_SUCCESS ?
                         (success ? "PASS" : "VERIFY_FAILED") : "READ_FAILED";
            } else result = "WRITE_FAILED";
        } else result = "KEY_ALREADY_EXISTS";
    }
    if (reopened) RegCloseKey(reopened);
    if (key) RegCloseKey(key);
    if (created == REG_CREATED_NEW_KEY) {
        rc = RegDeleteKeyW(HKEY_LOCAL_MACHINE, keyname);
        if (rc != ERROR_SUCCESS) result = "DELETE_FAILED";
    }
    if (!report_named(result, L"swcompat-deferred-registry.status"))
        return ERROR_INSTALL_FAILURE;
    return lstrcmpA(result, "PASS") == 0 ? ERROR_SUCCESS : ERROR_INSTALL_FAILURE;
}
