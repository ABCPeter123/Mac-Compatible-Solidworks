/*
 * Independent Win32 test harness for original Microsoft .NET Framework 4.8.1.
 * Build on a clean Windows CI runner with MSVC, then run under Wine.
 * Reports only strict fixed-schema status, original 32-bit Windows exit code,
 * and whether a direct child process was OBSERVED. Never logs executable
 * paths, command lines, process names, environment, or license information.
 *
 * The direct-child observation is best effort. NOT_OBSERVED is never proof
 * the bootstrapper did not start a child or service-side process.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <wchar.h>
#include <stdio.h>

#define WAIT_LIMIT_MS 210000u
#define COMMAND_LIMIT 8192u
#define PREFIX L"SWCOMPAT_WIN32_SETUP"
#define LOG_FILE L"C:\\swcompat-netfx481-private\\framework-setup.txt"

static void report(const char *state, DWORD code, const char *child) {
    printf("SWCOMPAT_WIN32_SETUP_SCHEMA=1\n");
    printf("SWCOMPAT_WIN32_SETUP_STATUS=%s\n", state);
    printf("SWCOMPAT_WIN32_SETUP_EXIT_HEX=%08lX\n", (unsigned long)code);
    printf("SWCOMPAT_WIN32_SETUP_CHILD_SEEN=%s\n", child);
    fflush(stdout);
}

static int permitted_media(const wchar_t *path) {
    const wchar_t *expected = L"NDP481-x86-x64-AllOS-ENU.exe";
    size_t len, need, i;
    if (path == NULL || !(path[0] >= L'A' && path[0] <= L'Z')
        && !(path[0] >= L'a' && path[0] <= L'z'))
        return 0;
    if (path[1] != L':' || path[2] != L'\\')
        return 0;
    len = wcslen(path);
    need = wcslen(expected);
    if (len <= need + 3 || len >= COMMAND_LIMIT - 200)
        return 0;
    for (i = 0; i < len; ++i) {
        if (path[i] == L'"' || path[i] == L'\r' || path[i] == L'\n')
            return 0;
    }
    return _wcsicmp(path + len - need, expected) == 0
        && path[len - need - 1] == L'\\';
}

static int seen_direct_child(DWORD pid) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32W entry;
    int found = 0;
    if (snap == INVALID_HANDLE_VALUE)
        return -1;
    ZeroMemory(&entry, sizeof(entry));
    entry.dwSize = sizeof(entry);
    if (Process32FirstW(snap, &entry)) {
        do {
            if (entry.th32ParentProcessID == pid && entry.th32ProcessID != pid) {
                found = 1;
                break;
            }
        } while (Process32NextW(snap, &entry));
    }
    CloseHandle(snap);
    return found;
}

int wmain(int argc, wchar_t **argv) {
    WCHAR app[COMMAND_LIMIT], command[COMMAND_LIMIT];
    STARTUPINFOW startup;
    PROCESS_INFORMATION pi;
    DWORD result, exit_code = 0xFFFFFFFFu;
    int observed = 0, census_valid = 0, snap;
    int selftest = (argc == 2 && wcscmp(argv[1], L"--selftest-3010") == 0);
    const char *child_status;

    if (!selftest && (argc != 2 || !permitted_media(argv[1]))) {
        report("INVALID_ARGUMENT", 0xFFFFFFFFu, "UNKNOWN");
        return 1;
    }
    if (selftest) {
        UINT len = GetSystemDirectoryW(app, COMMAND_LIMIT - 16u);
        if (!len || len >= COMMAND_LIMIT - 16u ||
            wcscat_s(app, COMMAND_LIMIT, L"\\cmd.exe") != 0) {
            report("START_FAILED", 0xFFFFFFFFu, "UNKNOWN");
            return 1;
        }
        if (swprintf_s(command, COMMAND_LIMIT,
                L"\"%ls\" /d /c exit 3010", app) < 0) {
            report("START_FAILED", 0xFFFFFFFFu, "UNKNOWN");
            return 1;
        }
    } else {
        if (wcscpy_s(app, COMMAND_LIMIT, argv[1]) != 0 ||
            swprintf_s(command, COMMAND_LIMIT,
                L"\"%ls\" /q /norestart /log \"%ls\"",
                app, LOG_FILE) < 0) {
            report("INVALID_ARGUMENT", 0xFFFFFFFFu, "UNKNOWN");
            return 1;
        }
    }
    ZeroMemory(&startup, sizeof(startup));
    ZeroMemory(&pi, sizeof(pi));
    startup.cb = sizeof(startup);
    if (!CreateProcessW(app, command, NULL, NULL, FALSE,
                        CREATE_NO_WINDOW, NULL, NULL, &startup, &pi)) {
        report("START_FAILED", GetLastError(), "UNKNOWN");
        return 1;
    }
    result = WAIT_TIMEOUT;
    /* Best-effort direct-child polling during the bootstrapper lifetime. */
    {
        DWORD elapsed = 0;
        while (elapsed < WAIT_LIMIT_MS) {
            result = WaitForSingleObject(pi.hProcess, 100);
            if (result != WAIT_TIMEOUT)
                break;
            snap = seen_direct_child(pi.dwProcessId);
            if (snap >= 0)
                census_valid = 1;
            if (snap > 0)
                observed = 1;
            elapsed += 100;
        }
    }
    if (result == WAIT_TIMEOUT) {
        TerminateProcess(pi.hProcess, 1);
        WaitForSingleObject(pi.hProcess, 5000);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        report("TIMEOUT", 0xFFFFFFFFu, "UNKNOWN");
        return 2;
    }
    if (result != WAIT_OBJECT_0 ||
        !GetExitCodeProcess(pi.hProcess, &exit_code)) {
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        report("WAIT_FAILED", 0xFFFFFFFFu, "UNKNOWN");
        return 2;
    }
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    child_status = observed ? "OBSERVED" : (census_valid ? "NOT_OBSERVED" : "UNKNOWN");
    report("EXIT", exit_code, child_status);
    /* Harness success means it captured the exit code, NOT installer success. */
    return 0;
}
