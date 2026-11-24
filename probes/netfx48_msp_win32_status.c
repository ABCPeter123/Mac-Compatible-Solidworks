/*
 * Independently built Win32 process monitor for the UNMODIFIED original
 * Microsoft .NET 4.8 x64 MSP. Windows CI compiles and selftests this file;
 * only a marked disposable Wine CI prefix may execute the actual patch.
 *
 * No paths, product identifiers, process names, vendor output, Windows
 * diagnostics or installer logs are ever printed. Only the full DWORD
 * GetExitCodeProcess result and a bounded fixed status leave the runner.
 * This is a process-exit probe, NOT a workaround for Windows Installer.
 */
#define WIN32_LEAN_AND_MEAN
#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#include <windows.h>
#include <stdio.h>
#include <wchar.h>
#include <string.h>

#define PATCH_PATH L"C:\\swcompat-original-netfx48-msi\\netfx_Patch_x64.msp"
#define PRIVATE_LOG L"C:\\swcompat-original-netfx48-msi\\netfx48-msp-patch-private.log"
#define CAPACITY 2048

static void report(const char *status, DWORD code) {
    printf("SWCOMPAT_MSP_WIN32_SCHEMA=1\n");
    printf("SWCOMPAT_MSP_WIN32_STATUS=%s\n", status);
    printf("SWCOMPAT_MSP_WIN32_EXIT_HEX=%08lX\n", (unsigned long)code);
    fflush(stdout);
}

int wmain(int argc, wchar_t **argv) {
    WCHAR executable[CAPACITY] = {0};
    WCHAR command[CAPACITY] = {0};
    STARTUPINFOW startup;
    PROCESS_INFORMATION process;
    DWORD rc, code = 0xFFFFFFFFu;
    UINT length;
    if (argc == 2 && wcscmp(argv[1], L"--selftest-1603") == 0) {
        report("SELFTEST", 1603u);
        return 0;
    }
    if (argc != 2 || wcscmp(argv[1], L"--apply-original-msp") != 0) {
        report("INVALID_ARGUMENT", code);
        return 1;
    }
    length = GetSystemDirectoryW(executable, CAPACITY - 32);
    if (length == 0 || length >= CAPACITY - 32
            || wcscat_s(executable, CAPACITY, L"\\msiexec.exe") != 0) {
        report("START_FAILED", code);
        return 1;
    }
    if (swprintf_s(command, CAPACITY,
            L"\"%ls\" /p \"%ls\" /qn /norestart EXTUI=1 /L*v \"%ls\"",
            executable, PATCH_PATH, PRIVATE_LOG) < 0) {
        report("INVALID_ARGUMENT", code);
        return 1;
    }
    ZeroMemory(&startup, sizeof(startup));
    ZeroMemory(&process, sizeof(process));
    startup.cb = sizeof(startup);
    if (!CreateProcessW(executable, command, NULL, NULL, FALSE,
                        CREATE_NO_WINDOW, NULL, NULL, &startup, &process)) {
        report("START_FAILED", code);
        return 1;
    }
    /* The outer Python runner enforces the original 420s limit and reaps
     * the exact marked Wine prefix, including MSI service descendants.
     * Do not return with a still-active original Windows Installer child. */
    rc = WaitForSingleObject(process.hProcess, INFINITE);
    if (rc != WAIT_OBJECT_0 || !GetExitCodeProcess(process.hProcess, &code)) {
        CloseHandle(process.hThread);
        CloseHandle(process.hProcess);
        report("WAIT_FAILED", 0xFFFFFFFFu);
        return 2;
    }
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    report("EXIT", code);
    /* Harness success means Win32 exit was captured, NOT MSP success. */
    return 0;
}
