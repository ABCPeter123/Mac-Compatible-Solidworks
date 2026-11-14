/*
 * Self-authored Windows x64 diagnostic, built and checked on Windows CI.
 * Test loading the fixed native .NET Framework CLR DLL by full Windows path.
 * It does NOT prove genuine Microsoft signature or managed execution.
 * Never print paths, module names, loaded version or Win32 error strings.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>

int main(void) {
    const wchar_t path[] = L"C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\clr.dll";
    DWORD attrs = GetFileAttributesW(path);
    HMODULE module;
    const char *state;
    if (attrs == INVALID_FILE_ATTRIBUTES || (attrs & FILE_ATTRIBUTE_DIRECTORY)) {
        state = "NOT_FOUND";
    } else if (attrs & FILE_ATTRIBUTE_REPARSE_POINT) {
        state = "LINKED";
    } else {
        /* Plain LoadLibraryW actually resolves imports and calls DllMain.
         * DONT_RESOLVE_DLL_REFERENCES would NOT test loader readiness.
         */
        module = LoadLibraryW(path);
        if (module == NULL) {
            state = "LOAD_FAILED";
        } else {
            state = "LOADED";
            FreeLibrary(module);
        }
    }
    printf("SWCOMPAT_CLR_LOAD_SCHEMA=1\n");
    printf("SWCOMPAT_CLR_LOAD_STATUS=%s\n", state);
    return 0;
}
