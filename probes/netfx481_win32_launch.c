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
#define MAX_CHILDREN 12
#define PREFIX L"SWCOMPAT_WIN32_SETUP"
#ifdef SWCOMPAT_NETFX48
#define LOG_FILE L"C:\\swcompat-netfx48-private\\framework-setup.txt"
#define ORIGINAL_SETUP_FILENAME L"NDP48-x86-x64-AllOS-ENU.exe"
#else
#define LOG_FILE L"C:\\swcompat-netfx481-private\\framework-setup.txt"
#define ORIGINAL_SETUP_FILENAME L"NDP481-x86-x64-AllOS-ENU.exe"
#endif

static void report(const char *state, DWORD code, const char *child,
                   const char *lifecycle, const char *child_exit) {
    printf("SWCOMPAT_WIN32_SETUP_SCHEMA=1\n");
    printf("SWCOMPAT_WIN32_SETUP_STATUS=%s\n", state);
    printf("SWCOMPAT_WIN32_SETUP_EXIT_HEX=%08lX\n", (unsigned long)code);
    printf("SWCOMPAT_WIN32_SETUP_CHILD_SEEN=%s\n", child);
    printf("SWCOMPAT_WIN32_SETUP_CHILD_LIFECYCLE=%s\n", lifecycle);
    printf("SWCOMPAT_WIN32_SETUP_CHILD_EXIT=%s\n", child_exit);
    fflush(stdout);
}

static int permitted_media(const wchar_t *path) {
    const wchar_t *expected = ORIGINAL_SETUP_FILENAME;
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

typedef struct {
    DWORD pid;
    HANDLE handle;
} CHILD_RECORD;

static void census_children(DWORD parent, CHILD_RECORD children[MAX_CHILDREN],
                            int *count, int *observed, int *census_valid,
                            int *overflow) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32W entry;
    int i, known;
    if (snap == INVALID_HANDLE_VALUE)
        return;
    *census_valid = 1;
    ZeroMemory(&entry, sizeof(entry));
    entry.dwSize = sizeof(entry);
    if (Process32FirstW(snap, &entry)) {
        do {
            if (entry.th32ParentProcessID != parent || entry.th32ProcessID == parent)
                continue;
            *observed = 1;
            known = 0;
            for (i = 0; i < *count; ++i) {
                if (children[i].pid == entry.th32ProcessID) {
                    known = 1;
                    break;
                }
            }
            if (known)
                continue;
            if (*count >= MAX_CHILDREN) {
                *overflow = 1;
                continue;
            }
            children[*count].pid = entry.th32ProcessID;
            children[*count].handle = OpenProcess(
                SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,
                FALSE, entry.th32ProcessID);
            (*count)++;
        } while (Process32NextW(snap, &entry));
    }
    CloseHandle(snap);
}

static void finish_children(CHILD_RECORD children[MAX_CHILDREN], int count,
                            int observed, int overflow,
                            const char **lifecycle, const char **exit_summary) {
    int i, unknown = overflow, active = 0, failures = 0, reboot = 0, exits = 0;
    DWORD wait, exit_code;
    if (!observed) {
        *lifecycle = "NOT_OBSERVED";
        *exit_summary = "NOT_VERIFIED";
        return;
    }
    for (i = 0; i < count; ++i) {
        if (children[i].handle == NULL) {
            unknown = 1;
            continue;
        }
        /* Maximum 1.5 seconds per child, 18 seconds total. */
        wait = WaitForSingleObject(children[i].handle, 1500);
        if (wait == WAIT_TIMEOUT) {
            active = 1;
        } else if (wait != WAIT_OBJECT_0 ||
                   !GetExitCodeProcess(children[i].handle, &exit_code)) {
            unknown = 1;
        } else {
            exits++;
            if (exit_code == 3010u)
                reboot++;
            else if (exit_code != 0)
                failures++;
        }
        CloseHandle(children[i].handle);
    }
    if (active) {
        *lifecycle = "STILL_ACTIVE";
        *exit_summary = "NOT_VERIFIED";
    } else if (unknown || exits != count) {
        *lifecycle = "PARTIAL";
        *exit_summary = "NOT_VERIFIED";
    } else {
        *lifecycle = "ALL_EXITED";
        *exit_summary = failures ? "NONZERO" : reboot ? "REBOOT_REQUIRED" : "ALL_ZERO";
    }
}

int wmain(int argc, wchar_t **argv) {
    WCHAR app[COMMAND_LIMIT], command[COMMAND_LIMIT];
    STARTUPINFOW startup;
    PROCESS_INFORMATION pi;
    DWORD result, exit_code = 0xFFFFFFFFu;
    CHILD_RECORD children[MAX_CHILDREN] = {{0, NULL}};
    int child_count = 0, child_overflow = 0;
    int observed = 0, census_valid = 0;
    int selftest = (argc == 2 && wcscmp(argv[1], L"--selftest-3010") == 0);
    const char *child_status;
    const char *child_lifecycle = "UNKNOWN";
    const char *child_exit = "NOT_VERIFIED";

    if (!selftest && (argc != 2 || !permitted_media(argv[1]))) {
        report("INVALID_ARGUMENT", 0xFFFFFFFFu, "UNKNOWN", "UNKNOWN", "NOT_VERIFIED");
        return 1;
    }
    if (selftest) {
        UINT len = GetSystemDirectoryW(app, COMMAND_LIMIT - 16u);
        if (!len || len >= COMMAND_LIMIT - 16u ||
            wcscat_s(app, COMMAND_LIMIT, L"\\cmd.exe") != 0) {
            report("START_FAILED", 0xFFFFFFFFu, "UNKNOWN", "UNKNOWN", "NOT_VERIFIED");
            return 1;
        }
        if (swprintf_s(command, COMMAND_LIMIT,
                L"\"%ls\" /d /c exit 3010", app) < 0) {
            report("START_FAILED", 0xFFFFFFFFu, "UNKNOWN", "UNKNOWN", "NOT_VERIFIED");
            return 1;
        }
    } else {
        if (wcscpy_s(app, COMMAND_LIMIT, argv[1]) != 0 ||
            swprintf_s(command, COMMAND_LIMIT,
                L"\"%ls\" /q /norestart /log \"%ls\"",
                app, LOG_FILE) < 0) {
            report("INVALID_ARGUMENT", 0xFFFFFFFFu, "UNKNOWN", "UNKNOWN", "NOT_VERIFIED");
            return 1;
        }
    }
    ZeroMemory(&startup, sizeof(startup));
    ZeroMemory(&pi, sizeof(pi));
    startup.cb = sizeof(startup);
    if (!CreateProcessW(app, command, NULL, NULL, FALSE,
                        CREATE_NO_WINDOW, NULL, NULL, &startup, &pi)) {
        report("START_FAILED", GetLastError(), "UNKNOWN", "UNKNOWN", "NOT_VERIFIED");
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
            census_children(pi.dwProcessId, children, &child_count,
                            &observed, &census_valid, &child_overflow);
            elapsed += 100;
        }
    }
    if (result == WAIT_TIMEOUT) {
        TerminateProcess(pi.hProcess, 1);
        WaitForSingleObject(pi.hProcess, 5000);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        report("TIMEOUT", 0xFFFFFFFFu, "UNKNOWN", "UNKNOWN", "NOT_VERIFIED");
        return 2;
    }
    if (result != WAIT_OBJECT_0 ||
        !GetExitCodeProcess(pi.hProcess, &exit_code)) {
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        report("WAIT_FAILED", 0xFFFFFFFFu, "UNKNOWN", "UNKNOWN", "NOT_VERIFIED");
        return 2;
    }
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    child_status = observed ? "OBSERVED" : (census_valid ? "NOT_OBSERVED" : "UNKNOWN");
    if (observed)
        finish_children(children, child_count, observed, child_overflow,
                        &child_lifecycle, &child_exit);
    else
        child_lifecycle = census_valid ? "NOT_OBSERVED" : "UNKNOWN";
    report("EXIT", exit_code, child_status, child_lifecycle, child_exit);
    /* Harness success means it captured the exit code, NOT installer success. */
    return 0;
}
