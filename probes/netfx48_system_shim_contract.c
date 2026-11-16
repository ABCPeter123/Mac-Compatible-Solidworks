/*
 * Non-installing Windows x64 original-framework shim contract probe.
 * No CRT; no proprietary bytes, locations, error codes or registry content
 * are written to stdout. Windows-only control for shim initialization.
 */
#define WIN32_LEAN_AND_MEAN
#define COBJMACROS
#include <windows.h>
#include <initguid.h>
#include <metahost.h>

static wchar_t target[4096];

__declspec(noreturn) static void emit(const char *result, DWORD length) {
    static const char schema[] = "SWCOMPAT_SHIM_CONTRACT_SCHEMA=1\n";
    HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD written;
    if (out != INVALID_HANDLE_VALUE && out != NULL) {
        WriteFile(out, schema, sizeof(schema)-1, &written, NULL);
        WriteFile(out, result, length, &written, NULL);
    }
    ExitProcess(0);
}
#define RESULT(v) do { \
    static const char marker[] = "SWCOMPAT_SHIM_CONTRACT_STATUS=" v "\n"; \
    emit(marker, sizeof(marker)-1); \
} while(0)

typedef HRESULT (STDAPICALLTYPE *CreateCLRFn)(REFCLSID, REFIID, LPVOID *);

void WINAPI shim_contract_entry(void) {
    HMODULE shim;
    DWORD len, attrs, err;
    wchar_t mode[3];
    len = GetEnvironmentVariableW(L"SWCOMPAT_SHIM_CONTRACT_SHELL", mode, 3);
    if (len == 1 && mode[0] == L'1') {
        CreateCLRFn create;
        ICLRMetaHost *meta = NULL;
        HRESULT hr;
        shim = LoadLibraryW(L"mscoree.dll");
        if (shim == NULL) RESULT("SHELL_MISSING");
        create = (CreateCLRFn)GetProcAddress(shim, "CLRCreateInstance");
        if (create == NULL) RESULT("SHELL_NO_EXPORT");
        hr = create(&CLSID_CLRMetaHost, &IID_ICLRMetaHost, (void **)&meta);
        if (FAILED(hr) || meta == NULL) RESULT("SHELL_ACTIVATION_FAILED");
        ICLRMetaHost_Release(meta);
        RESULT("SHELL_ACTIVATION_OK");
    }
    len = GetEnvironmentVariableW(L"SWCOMPAT_SHIM_CONTRACT_PATH", target, 4096);
    if (len == 0 || len >= 4096) RESULT("INVALID_INPUT");
    attrs = GetFileAttributesW(target);
    if (attrs == INVALID_FILE_ATTRIBUTES || (attrs & FILE_ATTRIBUTE_DIRECTORY))
        RESULT("SHIM_ABSENT");
    if (attrs & FILE_ATTRIBUTE_REPARSE_POINT)
        RESULT("SHIM_LINKED");
    SetLastError(0);
    shim = LoadLibraryExW(target, NULL, LOAD_WITH_ALTERED_SEARCH_PATH);
    if (shim != NULL) {
        FreeLibrary(shim);
        RESULT("SHIM_LOADED");
    }
    err = GetLastError();
    switch (err) {
        case ERROR_MOD_NOT_FOUND: RESULT("MISSING_DEPENDENCY");
        case ERROR_PROC_NOT_FOUND: RESULT("MISSING_EXPORT");
        case ERROR_BAD_EXE_FORMAT: RESULT("BAD_IMAGE");
        case ERROR_DLL_INIT_FAILED: RESULT("INIT_FAILED");
        case ERROR_ACCESS_DENIED: RESULT("ACCESS_DENIED");
        default: RESULT("OTHER_FAILURE");
    }
}