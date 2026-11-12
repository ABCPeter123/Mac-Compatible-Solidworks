/* Independent cross-process COM registration/activation verifier. */
#define WIN32_LEAN_AND_MEAN
#define COBJMACROS
#include <windows.h>
#include <objbase.h>
#include <stdio.h>
#include <string.h>

typedef HRESULT (WINAPI *registration_fn)(void);

static const CLSID CLSID_SWCompat = {
    0x99fcfda0, 0x3c7a, 0x4909, {0xab, 0x39, 0x67, 0xc4, 0x0c, 0x77, 0x2f, 0x15}
};

static int report(const char *phase, HRESULT hr, int pass) {
    printf("SWCOMPAT_COM_PHASE=%s\n", phase);
    printf("SWCOMPAT_COM_HRESULT=0x%08lX\n", (unsigned long)(DWORD)hr);
    printf("SWCOMPAT_COM_CHECK=%s\n", pass ? "PASS" : "FAIL");
    fflush(stdout);
    return pass ? 0 : 1;
}

static int registration(const char *phase, const wchar_t *path, int uninstall) {
    HMODULE module = LoadLibraryW(path);
    if (!module) return report(phase, HRESULT_FROM_WIN32(GetLastError()), 0);
    registration_fn action = (registration_fn)(void *)GetProcAddress(
        module, uninstall ? "DllUnregisterServer" : "DllRegisterServer");
    HRESULT hr = action ? action() : E_NOTIMPL;
    FreeLibrary(module);
    return report(phase, hr, SUCCEEDED(hr));
}

int wmain(int argc, wchar_t **argv) {
    if (argc != 2 && argc != 3) {
        puts("Usage: com_check.exe register <dll> | activate | unregister <dll> | absent");
        return 2;
    }
    char phase[20] = {0};
    WideCharToMultiByte(CP_UTF8, 0, argv[1], -1, phase, sizeof(phase), NULL, NULL);
    if ((!strcmp(phase, "register") || !strcmp(phase, "unregister")) && argc == 3)
        return registration(phase, argv[2], !strcmp(phase, "unregister"));
    if (argc != 2 || (strcmp(phase, "activate") && strcmp(phase, "absent")))
        return 2;

    HRESULT init = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    if (FAILED(init)) return report(phase, init, 0);

    IUnknown *object = NULL;
    HRESULT hr = CoCreateInstance(&CLSID_SWCompat, NULL, CLSCTX_INPROC_SERVER,
                                   &IID_IUnknown, (void **)&object);
    int expect_present = !strcmp(phase, "activate");
    int pass = expect_present ? SUCCEEDED(hr) && object != NULL
                              : hr == REGDB_E_CLASSNOTREG;
    if (object) {
        IUnknown *queried = NULL;
        HRESULT query = IUnknown_QueryInterface(object, &IID_IUnknown,
                                                 (void **)&queried);
        if (FAILED(query) || !queried) pass = 0;
        if (queried) IUnknown_Release(queried);
        IUnknown_Release(object);
    }
    CoUninitialize();
    return report(phase, hr, pass);
}
