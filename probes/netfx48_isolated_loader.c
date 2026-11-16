/*
 * Minimal, self-authored Windows x64 loader with NO CRT dependency.
 * Compiled /NODEFAULTLIB /ENTRY:isolated_entry /GS-. A vanilla Wine prefix
 * may lack the MSVC startup/runtime libraries required by an ordinary probe.
 *
 * The caller supplies only SWCOMPAT_LOAD_DLL_PATH privately via environment.
 * It never prints paths, imported DLL names, addresses, Windows messages or
 * application data. Genuine Microsoft media authentication happens outside
 * this fixture. Loading a DLL never proves managed CLR execution.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

__declspec(noreturn)
static void report(const char *line, DWORD length) {
    static const char prefix[] = "SWCOMPAT_NETFX48_ISOLATED_SCHEMA=1\n";
    static const char managed[] = "SWCOMPAT_NETFX48_ISOLATED_MANAGED=NOT_TESTED\n";
    DWORD written;
    HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
    if (out != INVALID_HANDLE_VALUE && out != NULL) {
        WriteFile(out, prefix, (DWORD)sizeof(prefix) - 1, &written, NULL);
        WriteFile(out, line, length, &written, NULL);
        WriteFile(out, managed, (DWORD)sizeof(managed) - 1, &written, NULL);
    }
    ExitProcess(0);
}

#define RESULT(STATE) do { \
    static const char line[] = "SWCOMPAT_NETFX48_ISOLATED_LOADER=" STATE "\n"; \
    report(line, (DWORD)sizeof(line) - 1); \
} while (0)

void WINAPI isolated_entry(void) {
    wchar_t path[32768];
    DWORD length;
    DWORD attrs;
    DWORD error;
    HMODULE loaded;

    length = GetEnvironmentVariableW(L"SWCOMPAT_LOAD_DLL_PATH", path,
                                     (DWORD)(sizeof(path) / sizeof(path[0])));
    if (length == 0 || length >= (DWORD)(sizeof(path) / sizeof(path[0]))) {
        RESULT("INVALID_ARGUMENT");
    }
    attrs = GetFileAttributesW(path);
    if (attrs == INVALID_FILE_ATTRIBUTES || (attrs & FILE_ATTRIBUTE_DIRECTORY)) {
        RESULT("NOT_FOUND");
    }
    if (attrs & FILE_ATTRIBUTE_REPARSE_POINT) {
        RESULT("LINKED");
    }
    SetLastError(0);
    loaded = LoadLibraryExW(path, NULL, LOAD_WITH_ALTERED_SEARCH_PATH);
    if (loaded != NULL) {
        FreeLibrary(loaded);
        RESULT("LOADED");
    }
    error = GetLastError();
    switch (error) {
        case ERROR_MOD_NOT_FOUND: RESULT("MISSING_DEPENDENCY");
        case ERROR_PROC_NOT_FOUND: RESULT("MISSING_EXPORT");
        case ERROR_BAD_EXE_FORMAT: RESULT("BAD_IMAGE");
        case ERROR_DLL_INIT_FAILED: RESULT("DLL_INIT_FAILED");
        case ERROR_ACCESS_DENIED: RESULT("ACCESS_DENIED");
        default: RESULT("OTHER_LOAD_FAILURE");
    }
}
