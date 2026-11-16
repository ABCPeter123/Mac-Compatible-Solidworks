/*
 * Self-authored Windows x64 probe for an original Microsoft CLR PE.
 * The parent verifies the Microsoft installer Authenticode + digest.
 * LoadLibraryExW resolves direct imports and runs DLL_PROCESS_ATTACH.
 * This is NOT managed execution, install registration, or a runtime fix.
 * No paths, DLL names, Win32 messages or vendor bytes are printed.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wchar.h>
#include <stdio.h>

static const char *classify(DWORD error) {
    switch (error) {
        case ERROR_MOD_NOT_FOUND: return "MISSING_DEPENDENCY";
        case ERROR_PROC_NOT_FOUND: return "MISSING_EXPORT";
        case ERROR_BAD_EXE_FORMAT: return "BAD_IMAGE";
        case ERROR_DLL_INIT_FAILED: return "DLL_INIT_FAILED";
        case ERROR_ACCESS_DENIED: return "ACCESS_DENIED";
        default: return "OTHER_LOAD_FAILURE";
    }
}
static void result(const char *state) {
    printf("SWCOMPAT_NETFX48_ISOLATED_SCHEMA=1\n");
    printf("SWCOMPAT_NETFX48_ISOLATED_LOADER=%s\n", state);
    printf("SWCOMPAT_NETFX48_ISOLATED_MANAGED=NOT_TESTED\n");
}
int wmain(int argc, wchar_t **argv) {
    DWORD attrs;
    HMODULE module;
    DWORD code;
    if (argc == 2 && wcscmp(argv[1], L"--selftest-missing") == 0) {
        result("NOT_FOUND");
        return 0;
    }
    if (argc == 2 && wcscmp(argv[1], L"--selftest-windows") == 0) {
        wchar_t path[MAX_PATH];
        UINT len = GetSystemDirectoryW(path, MAX_PATH);
        if (len == 0 || len > MAX_PATH - 17) {
            result("OTHER_LOAD_FAILURE");
            return 0;
        }
        wcscat_s(path, MAX_PATH, L"\\kernel32.dll");
        module = LoadLibraryExW(path, NULL, LOAD_WITH_ALTERED_SEARCH_PATH);
        result(module ? "LOADED" : classify(GetLastError()));
        if (module) FreeLibrary(module);
        return 0;
    }
    if (argc != 2 || !argv[1] || wcslen(argv[1]) > 32760) {
        result("INVALID_ARGUMENT");
        return 0;
    }
    attrs = GetFileAttributesW(argv[1]);
    if (attrs == INVALID_FILE_ATTRIBUTES || (attrs & FILE_ATTRIBUTE_DIRECTORY)) {
        result("NOT_FOUND");
        return 0;
    }
    if (attrs & FILE_ATTRIBUTE_REPARSE_POINT) {
        result("LINKED");
        return 0;
    }
    /* Do not use DONT_RESOLVE_DLL_REFERENCES: that would mask dependencies. */
    SetLastError(0);
    module = LoadLibraryExW(argv[1], NULL, LOAD_WITH_ALTERED_SEARCH_PATH);
    if (module == NULL) {
        code = GetLastError();
        result(classify(code));
    } else {
        result("LOADED");
        FreeLibrary(module);
    }
    return 0;
}
