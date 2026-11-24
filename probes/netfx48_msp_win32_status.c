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
#include <msi.h>
#include <msiquery.h>
#include <stdio.h>
#include <wchar.h>
#include <string.h>

#define PATCH_PATH L"C:\\swcompat-original-netfx48-msi\\netfx_Patch_x64.msp"
#define ORIGINAL_MSI_PATH L"C:\\swcompat-original-netfx48-msi\\netfx_Full_x64.msi"
#define PRIVATE_LOG L"C:\\swcompat-original-netfx48-msi\\netfx48-msp-patch-private.log"
#define CAPACITY 2048

/* Read-only Windows Installer registration probe. Never print product GUID,
 * package path, vendor text or MSI property values. A successful /i process
 * exit does NOT by itself prove that a patch can find a registered product. */
static void report_registration(FILE *stream, const char *status,
                                const char *product, const char *cache) {
    fprintf(stream, "SWCOMPAT_MSI_REG_SCHEMA=1\n");
    fprintf(stream, "SWCOMPAT_MSI_REG_STATUS=%s\n", status);
    fprintf(stream, "SWCOMPAT_MSI_REG_PRODUCT=%s\n", product);
    fprintf(stream, "SWCOMPAT_MSI_REG_CACHE=%s\n", cache);
    fflush(stream);
}

static int probe_registration(FILE *stream) {
    MSIHANDLE db = 0, view = 0, record = 0;
    WCHAR product[80] = {0};
    WCHAR cache_path[2048] = {0};
    DWORD length = 79, cache_length = 2047;
    UINT rc;
    INSTALLSTATE state;
    const char *product_state = "UNKNOWN";
    const char *cache_state = "UNKNOWN";

    rc = MsiOpenDatabaseW(ORIGINAL_MSI_PATH, MSIDBOPEN_READONLY, &db);
    if (rc != ERROR_SUCCESS) {
        report_registration(stream, "OPEN_FAILED", "UNKNOWN", "UNKNOWN");
        return 0;
    }
    rc = MsiDatabaseOpenViewW(
        db, L"SELECT `Value` FROM `Property` WHERE `Property`='ProductCode'", &view);
    if (rc == ERROR_SUCCESS) rc = MsiViewExecute(view, 0);
    if (rc == ERROR_SUCCESS) rc = MsiViewFetch(view, &record);
    if (rc == ERROR_SUCCESS) rc = MsiRecordGetStringW(record, 1, product, &length);
    if (rc != ERROR_SUCCESS || !product[0]) {
        if (record) MsiCloseHandle(record);
        if (view) MsiCloseHandle(view);
        MsiCloseHandle(db);
        report_registration(stream, "QUERY_FAILED", "UNKNOWN", "UNKNOWN");
        return 0;
    }
    state = MsiQueryProductStateW(product);
    if (state == INSTALLSTATE_DEFAULT) product_state = "INSTALLED";
    else if (state == INSTALLSTATE_ADVERTISED) product_state = "ADVERTISED";
    else if (state == INSTALLSTATE_UNKNOWN || state == INSTALLSTATE_ABSENT)
        product_state = "ABSENT";
    else product_state = "OTHER";

    rc = MsiGetProductInfoW(product, INSTALLPROPERTY_LOCALPACKAGE,
                            cache_path, &cache_length);
    if (rc == ERROR_SUCCESS && cache_length && cache_path[0]) {
        DWORD attributes = GetFileAttributesW(cache_path);
        cache_state = (attributes == INVALID_FILE_ATTRIBUTES ||
                      (attributes & FILE_ATTRIBUTE_DIRECTORY))
                      ? "MISSING" : "PRESENT";
    }
    if (record) MsiCloseHandle(record);
    if (view) MsiCloseHandle(view);
    MsiCloseHandle(db);
    report_registration(stream, "OBSERVED", product_state, cache_state);
    return 0;
}

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
    if (argc == 2 && wcscmp(argv[1], L"--selftest-msi-registration") == 0) {
        report_registration(stdout, "SELFTEST", "INSTALLED", "PRESENT");
        return 0;
    }
    if (argc == 2 && wcscmp(argv[1], L"--probe-original-msi-registration") == 0) {
        return probe_registration(stdout);
    }
    if (argc == 2 && wcscmp(argv[1], L"--selftest-1603") == 0) {
        report("SELFTEST", 1603u);
        return 0;
    }
    if (argc != 2 || wcscmp(argv[1], L"--apply-original-msp") != 0) {
        report("INVALID_ARGUMENT", code);
        return 1;
    }
    /* Probe the registration created by the original signed /i MSI *before*
     * the unchanged /p MSP runs. Send only fixed enums to PRIVATE stderr,
     * preserving the existing strict three-line Win32 stdout exit packet. */
    probe_registration(stderr);
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
