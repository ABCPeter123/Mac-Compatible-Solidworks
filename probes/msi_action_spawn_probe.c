/* Native x64 CreateProcessW smoke for the exact self-authored metadata probe.
   Only fixed status enums are exposed, never helper paths or user data.
   No MSI API is invoked and no product installer is modified. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <wchar.h>

static HANDLE status_file = INVALID_HANDLE_VALUE;

static void emit(const char *key, const char *value)
{
    char line[128];
    DWORD written = 0;
    sprintf_s(line, sizeof(line), "SWCOMPAT_SPAWN_%s=%s", key, value);
    puts(line);
    fflush(stdout);
    if (status_file != INVALID_HANDLE_VALUE)
    {
        WriteFile(status_file, line, lstrlenA(line), &written, NULL);
        WriteFile(status_file, "\r\n", 2, &written, NULL);
        FlushFileBuffers(status_file);
    }
}

static int done(const char *state, const char *child_exit, const char *error)
{
    emit("STATUS", state);
    emit("CHILD_EXIT", child_exit);
    emit("ERROR", error);
    if (status_file != INVALID_HANDLE_VALUE)
    {
        CloseHandle(status_file);
        status_file = INVALID_HANDLE_VALUE;
    }
    return 0;
}

static int exact_target(const wchar_t *s)
{
    static const wchar_t expected[] = L"msi_custom_action_table_probe.exe";
    size_t n, m, i;
    if (!s) return 0;
    n = wcslen(s); m = wcslen(expected);
    if (n <= m + 3 || n > 2048 || s[1] != L':' || s[2] != L'\\')
        return 0;
    for (i = 0; i < n; ++i)
        if (s[i] == L'"' || s[i] == L'\r' || s[i] == L'\n')
            return 0;
    return s[n - m - 1] == L'\\' && _wcsicmp(s + n - m, expected) == 0;
}

int wmain(int argc, wchar_t **argv)
{
    STARTUPINFOW si = {0};
    PROCESS_INFORMATION pi = {0};
    wchar_t command[2304];
    DWORD state, code = 0, error;
    const char *error_type;
    if (argc == 3)
        status_file = CreateFileW(argv[2], GENERIC_WRITE, FILE_SHARE_READ,
                                  NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (argc != 3 || !exact_target(argv[1]))
        return done("INVALID_ARGUMENT", "NOT_VERIFIED", "NONE");
    if (swprintf_s(command, 2304, L"\"%ls\" --selftest C:\\windows\\temp\\swcompat_ca_table_probe.status", argv[1]) < 0)
        return done("INVALID_ARGUMENT", "NOT_VERIFIED", "NONE");
    si.cb = sizeof(si);
    if (!CreateProcessW(argv[1], command, NULL, NULL, FALSE,
                        CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
    {
        error = GetLastError();
        error_type = (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND)
                     ? "FILE_NOT_FOUND" :
                     (error == ERROR_BAD_EXE_FORMAT) ? "INVALID_IMAGE" :
                     (error == ERROR_MOD_NOT_FOUND || error == ERROR_DLL_NOT_FOUND)
                     ? "DEPENDENCY_MISSING" : "OTHER_WIN32";
        return done("START_FAILED", "NOT_VERIFIED", error_type);
    }
    state = WaitForSingleObject(pi.hProcess, 12000);
    if (state == WAIT_TIMEOUT)
    {
        TerminateProcess(pi.hProcess, 1);
        WaitForSingleObject(pi.hProcess, 5000);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return done("TIMED_OUT", "NOT_VERIFIED", "NONE");
    }
    if (state != WAIT_OBJECT_0 || !GetExitCodeProcess(pi.hProcess, &code))
    {
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return done("WAIT_FAILED", "NOT_VERIFIED", "NONE");
    }
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return done("STARTED", code == 0 ? "ZERO" : "NONZERO", "NONE");
}
