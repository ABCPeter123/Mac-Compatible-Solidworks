/* Exact Win32 process result for Wine's own Windows Update installer.
 * Never change the official update package or report harness exit as success.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <wchar.h>

static void packet(const char *state, DWORD code) {
    printf("SWCOMPAT_WUSA_SCHEMA=1\nSWCOMPAT_WUSA_STATUS=%s\nSWCOMPAT_WUSA_EXIT=%08lX\n",
           state, (unsigned long)code);
    fflush(stdout);
}

int wmain(int argc, wchar_t **argv) {
    WCHAR exe[MAX_PATH], command[2 * MAX_PATH];
    STARTUPINFOW si = {0};
    PROCESS_INFORMATION pi = {0};
    DWORD code = 0xffffffffu, length;
    BOOL selftest = FALSE;
    if (argc != 2) return 2;
    if (wcscmp(argv[1], L"--exit-3010") == 0) return 3010;
    selftest = wcscmp(argv[1], L"--selftest") == 0;
    if (selftest) {
        length = GetModuleFileNameW(NULL, exe, MAX_PATH);
        if (!length || length >= MAX_PATH ||
            swprintf_s(command, 2 * MAX_PATH, L"\"%ls\" --exit-3010", exe) < 0)
            return 2;
    } else {
        if (wcscmp(argv[1], L"--apply-catalog-481") != 0) return 2;
        length = GetSystemDirectoryW(exe, MAX_PATH);
        if (!length || length >= MAX_PATH - 12 ||
            wcscat_s(exe, MAX_PATH, L"\\wusa.exe") != 0 ||
            swprintf_s(command, 2 * MAX_PATH,
              L"\"%ls\" \"C:\\swcompat-netfx481-catalog\\KB5011048.msu\" /quiet /norestart", exe) < 0) {
            packet("START_FAILED", code);
            return 1;
        }
    }
    si.cb = sizeof(si);
    if (!CreateProcessW(exe, command, NULL, NULL, FALSE, CREATE_NO_WINDOW,
                        NULL, NULL, &si, &pi)) {
        packet("START_FAILED", code);
        return 1;
    }
    if (WaitForSingleObject(pi.hProcess, INFINITE) != WAIT_OBJECT_0 ||
        !GetExitCodeProcess(pi.hProcess, &code)) {
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        packet("WAIT_FAILED", 0xffffffffu);
        return 1;
    }
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    packet(selftest ? "SELFTEST" : "EXIT", code);
    return selftest && code != 3010 ? 1 : 0;
}
