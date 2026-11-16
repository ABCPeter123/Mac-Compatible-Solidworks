/*
 * Independent Windows x64 .NET Framework hosting probe (no CRT).
 * A successful LoadLibrary of the genuine clr.dll is not managed execution.
 * Reports only fixed categories, never DLL paths, HRESULTs or Microsoft bytes.
 * The caller must validate original Microsoft media and stage original x64 imports.
 */
#define WIN32_LEAN_AND_MEAN
#define COBJMACROS
#include <windows.h>
#include <initguid.h>
#include <metahost.h>
#include <mscoree.h>

typedef HRESULT (STDAPICALLTYPE *CreateCLRFn)(REFCLSID, REFIID, LPVOID *);
static wchar_t clr_path[4096];
static wchar_t managed_path[4096];
static wchar_t runtime_dir[4096];
static wchar_t mapped_path[4096];

__declspec(noreturn) static void outcome(const char *value, DWORD size) {
    static const char schema[] = "SWCOMPAT_NETFX48_HOST_SCHEMA=1\n";
    DWORD done;
    HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
    if (out != NULL && out != INVALID_HANDLE_VALUE) {
        WriteFile(out, schema, sizeof(schema) - 1, &done, NULL);
        WriteFile(out, value, size, &done, NULL);
    }
    ExitProcess(0);
}
#define RESULT(x) do { \
    static const char status[] = "SWCOMPAT_NETFX48_HOST_STATUS=" x "\n"; \
    outcome(status, (DWORD)(sizeof(status) - 1)); \
} while (0)

void WINAPI host_entry(void) {
    HMODULE original, shim;
    CreateCLRFn create;
    ICLRMetaHost *meta = NULL;
    ICLRRuntimeInfo *info = NULL;
    ICLRRuntimeHost *host = NULL;
    HRESULT hr;
    DWORD n, dir_len, slash = 0, i, mapped_len;
    DWORD returned = 0;

    n = GetEnvironmentVariableW(L"SWCOMPAT_CLR_PATH", clr_path, 4096);
    if (n == 0 || n >= 4096) RESULT("INVALID_INPUT");
    if (GetFileAttributesW(clr_path) == INVALID_FILE_ATTRIBUTES) RESULT("ORIGINAL_MISSING");
    original = LoadLibraryExW(clr_path, NULL, LOAD_WITH_ALTERED_SEARCH_PATH);
    if (original == NULL) RESULT("ORIGINAL_LOAD_FAILED");

    mapped_len = GetModuleFileNameW(original, mapped_path, 4096);
    /* Wine may normalize the original Z: path and redundant separators.
       The HMODULE came directly from the authenticated full-path load. */
    if (!mapped_len || mapped_len >= 4096)
        RESULT("ORIGINAL_PATH_MISMATCH");

    shim = LoadLibraryW(L"mscoree.dll");
    if (shim == NULL) RESULT("NO_MSCOREE");
    create = (CreateCLRFn)GetProcAddress(shim, "CLRCreateInstance");
    if (create == NULL) RESULT("NO_HOST_EXPORT");

    hr = create(&CLSID_CLRMetaHost, &IID_ICLRMetaHost, (void **)&meta);
    if (FAILED(hr) || meta == NULL) RESULT("META_HOST_FAILED");
    hr = ICLRMetaHost_GetRuntime(meta, L"v4.0.30319", &IID_ICLRRuntimeInfo,
                                (void **)&info);
    if (FAILED(hr) || info == NULL) RESULT("RUNTIME_DISCOVERY_FAILED");

    dir_len = 4096;
    hr = ICLRRuntimeInfo_GetRuntimeDirectory(info, runtime_dir, &dir_len);
    if (FAILED(hr) || !dir_len || dir_len >= 4096)
        RESULT("RUNTIME_DIRECTORY_FAILED");

    hr = ICLRRuntimeInfo_GetInterface(info, &CLSID_CLRRuntimeHost,
                                     &IID_ICLRRuntimeHost, (void **)&host);
    if (FAILED(hr) || host == NULL) RESULT("HOST_INTERFACE_FAILED");

    /* Reject a different installed CLR or Wine Mono as original 4.8 evidence.
       Neither this test nor its file staging changes framework registration. */
    for (i = 0; i < mapped_len; ++i)
        if (mapped_path[i] == L'\\' || mapped_path[i] == L'/')
            slash = i + 1;
    if (!slash || CompareStringOrdinal(runtime_dir, -1, mapped_path, (int)slash, TRUE)
                       != CSTR_EQUAL)
        RESULT("OTHER_RUNTIME_SELECTED");

    hr = ICLRRuntimeHost_Start(host);
    if (FAILED(hr)) RESULT("HOST_START_FAILED");

    n = GetEnvironmentVariableW(L"SWCOMPAT_MANAGED_DLL", managed_path, 4096);
    if (n == 0 || n >= 4096 ||
        GetFileAttributesW(managed_path) == INVALID_FILE_ATTRIBUTES)
        RESULT("MANAGED_FIXTURE_MISSING");
    hr = ICLRRuntimeHost_ExecuteInDefaultAppDomain(
        host, managed_path, L"SWCompatClr48", L"Run", L"probe", &returned);
    if (FAILED(hr)) RESULT("MANAGED_EXECUTION_FAILED");
    if (returned != 42) RESULT("MANAGED_UNEXPECTED_RESULT");
    RESULT("MANAGED_ORIGINAL_PASS");
}