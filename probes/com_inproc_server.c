/* Self-authored in-process COM server for functional Windows compatibility tests.
 * Uses a user-scoped HKCU registration. No system privileges or proprietary files.
 */
#define WIN32_LEAN_AND_MEAN
#define COBJMACROS
#include <windows.h>
#include <objbase.h>
#include <stddef.h>
#include <wchar.h>

static const CLSID CLSID_SWCompat = {
    0x99fcfda0, 0x3c7a, 0x4909, {0xab, 0x39, 0x67, 0xc4, 0x0c, 0x77, 0x2f, 0x15}
};
static const wchar_t *REGKEY =
    L"Software\\Classes\\CLSID\\{99FCFDA0-3C7A-4909-AB39-67C40C772F15}";
static LONG live_objects = 0, server_locks = 0;
static HMODULE module_handle = NULL;

typedef struct ProbeObject {
    IUnknown iface;
    LONG refs;
} ProbeObject;

static HRESULT WINAPI object_query(IUnknown *self, REFIID iid, void **result) {
    if (!result) return E_POINTER;
    *result = NULL;
    if (!IsEqualIID(iid, &IID_IUnknown)) return E_NOINTERFACE;
    *result = self;
    IUnknown_AddRef(self);
    return S_OK;
}

static ULONG WINAPI object_addref(IUnknown *self) {
    ProbeObject *object = (ProbeObject *)self;
    return (ULONG)InterlockedIncrement(&object->refs);
}

static ULONG WINAPI object_release(IUnknown *self) {
    ProbeObject *object = (ProbeObject *)self;
    LONG refs = InterlockedDecrement(&object->refs);
    if (!refs) {
        InterlockedDecrement(&live_objects);
        HeapFree(GetProcessHeap(), 0, object);
    }
    return (ULONG)refs;
}

static const IUnknownVtbl object_vtable = {
    object_query, object_addref, object_release
};

typedef struct ProbeFactory {
    IClassFactory iface;
} ProbeFactory;

static HRESULT WINAPI factory_query(IClassFactory *self, REFIID iid, void **result) {
    if (!result) return E_POINTER;
    *result = NULL;
    if (!IsEqualIID(iid, &IID_IUnknown) && !IsEqualIID(iid, &IID_IClassFactory))
        return E_NOINTERFACE;
    *result = self;
    IClassFactory_AddRef(self);
    return S_OK;
}

static ULONG WINAPI factory_addref(IClassFactory *self) {
    (void)self;
    return 2;
}

static ULONG WINAPI factory_release(IClassFactory *self) {
    (void)self;
    return 1;
}

static HRESULT WINAPI factory_create(IClassFactory *self, IUnknown *outer,
                                     REFIID iid, void **result) {
    (void)self;
    if (!result) return E_POINTER;
    *result = NULL;
    if (outer) return CLASS_E_NOAGGREGATION;
    ProbeObject *object = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*object));
    if (!object) return E_OUTOFMEMORY;
    object->iface.lpVtbl = &object_vtable;
    object->refs = 1;
    InterlockedIncrement(&live_objects);
    HRESULT hr = IUnknown_QueryInterface(&object->iface, iid, result);
    IUnknown_Release(&object->iface);
    return hr;
}

static HRESULT WINAPI factory_lock(IClassFactory *self, BOOL lock) {
    (void)self;
    if (lock) InterlockedIncrement(&server_locks);
    else InterlockedDecrement(&server_locks);
    return S_OK;
}

static const IClassFactoryVtbl factory_vtable = {
    factory_query, factory_addref, factory_release, factory_create, factory_lock
};
static ProbeFactory factory = {{&factory_vtable}};

__declspec(dllexport) HRESULT WINAPI DllGetClassObject(REFCLSID clsid,
                                                        REFIID iid, void **result) {
    if (!IsEqualCLSID(clsid, &CLSID_SWCompat)) return CLASS_E_CLASSNOTAVAILABLE;
    return factory_query(&factory.iface, iid, result);
}

__declspec(dllexport) HRESULT WINAPI DllCanUnloadNow(void) {
    return live_objects == 0 && server_locks == 0 ? S_OK : S_FALSE;
}

static HRESULT put_string(HKEY key, const wchar_t *name, const wchar_t *value) {
    DWORD bytes = (DWORD)((wcslen(value) + 1) * sizeof(wchar_t));
    return HRESULT_FROM_WIN32(RegSetValueExW(key, name, 0, REG_SZ,
                                            (const BYTE *)value, bytes));
}

__declspec(dllexport) HRESULT WINAPI DllRegisterServer(void) {
    wchar_t path[MAX_PATH] = {0};
    DWORD length = GetModuleFileNameW(module_handle, path, MAX_PATH);
    if (!length || length >= MAX_PATH) return HRESULT_FROM_WIN32(GetLastError());

    wchar_t keypath[256] = {0};
    if (swprintf(keypath, 256, L"%ls\\InprocServer32", REGKEY) <= 0)
        return E_FAIL;

    HKEY key = NULL;
    LONG status = RegCreateKeyExW(HKEY_CURRENT_USER, keypath, 0, NULL, 0,
                                  KEY_SET_VALUE, NULL, &key, NULL);
    if (status != ERROR_SUCCESS) return HRESULT_FROM_WIN32(status);

    HRESULT hr = put_string(key, NULL, path);
    if (SUCCEEDED(hr)) hr = put_string(key, L"ThreadingModel", L"Both");
    RegCloseKey(key);
    return hr;
}

__declspec(dllexport) HRESULT WINAPI DllUnregisterServer(void) {
    wchar_t keypath[256] = {0};
    if (swprintf(keypath, 256, L"%ls\\InprocServer32", REGKEY) <= 0)
        return E_FAIL;
    LONG a = RegDeleteKeyW(HKEY_CURRENT_USER, keypath);
    LONG b = RegDeleteKeyW(HKEY_CURRENT_USER, REGKEY);
    if ((a != ERROR_SUCCESS && a != ERROR_FILE_NOT_FOUND) ||
        (b != ERROR_SUCCESS && b != ERROR_FILE_NOT_FOUND))
        return HRESULT_FROM_WIN32(a != ERROR_SUCCESS ? a : b);
    return S_OK;
}

BOOL WINAPI DllMain(HINSTANCE module, DWORD reason, LPVOID reserved) {
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        module_handle = (HMODULE)module;
        DisableThreadLibraryCalls(module);
    }
    return TRUE;
}
