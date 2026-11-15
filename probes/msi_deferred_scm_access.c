/* Self-authored x64 deferred MSI DLL custom action. Read-only SCM checks.
 * It never starts, creates, reconfigures or deletes a service.
 * No Microsoft installer binaries or SOLIDWORKS code are embedded.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsvc.h>
#include <msi.h>
#include <wchar.h>
#pragma comment(lib, "Advapi32.lib")

static BOOL report(const char *state)
{
    WCHAR path[MAX_PATH];
    DWORD count = GetWindowsDirectoryW(path, MAX_PATH);
    HANDLE out;
    DWORD wrote = 0;
    SIZE_T len;
    if (!count || count >= MAX_PATH - 48) return FALSE;
    if (wcscat_s(path, MAX_PATH, L"\\Temp\\swcompat-deferred-scm.status")) return FALSE;
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
    if (!report(result)) return ERROR_INSTALL_FAILURE;
    return lstrcmpA(result, "PASS") == 0 ? ERROR_SUCCESS : ERROR_INSTALL_FAILURE;
}
