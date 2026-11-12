/* Read-only Windows x64 installer prerequisite reconnaissance.
 * Capability signals only, not proof of functional SOLIDWORKS dependencies.
 * Does not install software, modify registry, or access licensing.
 */
#define WIN32_LEAN_AND_MEAN
#define COBJMACROS
#include <windows.h>
#include <objbase.h>
#include <shlobj.h>
#include <winsvc.h>
#include <stdio.h>

typedef LONG (WINAPI *rtl_get_version_fn)(OSVERSIONINFOW *);

static void state(const char *key, int present) {
    printf("SWCOMPAT_PREREQ_%s=%s\n", key, present ? "PRESENT" : "ABSENT");
}

static DWORD registry_dword(HKEY root, const wchar_t *path, const wchar_t *name) {
    HKEY key = NULL;
    DWORD kind = 0, value = 0, size = sizeof(value);
    if (RegOpenKeyExW(root, path, 0, KEY_QUERY_VALUE, &key) != ERROR_SUCCESS) return 0;
    LONG result = RegQueryValueExW(key, name, NULL, &kind, (LPBYTE)&value, &size);
    RegCloseKey(key);
    return result == ERROR_SUCCESS && kind == REG_DWORD && size == sizeof(value) ? value : 0;
}

static void dll_export(const char *key, const wchar_t *dll, const char *export_name) {
    HMODULE module = LoadLibraryW(dll);
    int found = module && (!export_name || GetProcAddress(module, export_name));
    state(key, found);
    if (module) FreeLibrary(module);
}

int main(void) {
    printf("SWCOMPAT_PREREQ_SCHEMA=1\n");
    SYSTEM_INFO system;
    GetNativeSystemInfo(&system);
    printf("SWCOMPAT_PREREQ_PROCESS_BITS=%u\n", (unsigned)(8 * sizeof(void *)));
    printf("SWCOMPAT_PREREQ_PROCESSOR_ARCH=%u\n", (unsigned)system.wProcessorArchitecture);
    state("AMD64_PROCESS", sizeof(void *) == 8 &&
          system.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64);

    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    rtl_get_version_fn version_fn = ntdll ?
        (rtl_get_version_fn)(void *)GetProcAddress(ntdll, "RtlGetVersion") : NULL;
    OSVERSIONINFOW osver = {0};
    osver.dwOSVersionInfoSize = sizeof(osver);
    if (version_fn && version_fn(&osver) == 0) {
        printf("SWCOMPAT_PREREQ_WINDOWS_MAJOR=%lu\n", (unsigned long)osver.dwMajorVersion);
        printf("SWCOMPAT_PREREQ_WINDOWS_MINOR=%lu\n", (unsigned long)osver.dwMinorVersion);
        printf("SWCOMPAT_PREREQ_WINDOWS_BUILD=%lu\n", (unsigned long)osver.dwBuildNumber);
    } else {
        puts("SWCOMPAT_PREREQ_WINDOWS_VERSION=UNAVAILABLE");
    }

    HMODULE msi = LoadLibraryW(L"msi.dll");
    state("MSI_EXPORTS", msi && GetProcAddress(msi, "MsiGetProductInfoW") &&
          GetProcAddress(msi, "MsiInstallProductW"));
    if (msi) FreeLibrary(msi);

    HRESULT hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    int com_ok = SUCCEEDED(hr);
    state("COM_APARTMENT", com_ok);
    if (com_ok) {
        IShellLinkW *link = NULL;
        hr = CoCreateInstance(&CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER,
                              &IID_IShellLinkW, (void **)&link);
        state("SHELLLINK_COM", SUCCEEDED(hr) && link != NULL);
        if (link) IShellLinkW_Release(link);
        CoUninitialize();
    } else {
        state("SHELLLINK_COM", 0);
    }

    SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    state("SCM_CONNECT", scm != NULL);
    if (scm) CloseServiceHandle(scm);

    DWORD netfx_release = registry_dword(
        HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\NET Framework Setup\\NDP\\v4\\Full", L"Release");
    printf("SWCOMPAT_PREREQ_NETFX_RELEASE=%lu\n", (unsigned long)netfx_release);
    /* Version registry entry does NOT prove Wine can run managed code. */
    state("NETFX481_REGISTRY", netfx_release >= 533320);
    dll_export("CLR_CREATE_EXPORT", L"mscoree.dll", "CLRCreateInstance");

    state("VC_X64_REGISTRY", registry_dword(HKEY_LOCAL_MACHINE,
          L"SOFTWARE\\Microsoft\\VisualStudio\\14.0\\VC\\Runtimes\\x64", L"Installed") == 1);
    state("VC_X86_REGISTRY", registry_dword(HKEY_LOCAL_MACHINE,
          L"SOFTWARE\\Microsoft\\VisualStudio\\14.0\\VC\\Runtimes\\x86", L"Installed") == 1);
    dll_export("VCRUNTIME140_DLL", L"vcruntime140.dll", NULL);
    dll_export("MSVCP140_DLL", L"msvcp140.dll", NULL);
    dll_export("VCRUNTIME140_1_DLL", L"vcruntime140_1.dll", NULL);

    wchar_t temp[MAX_PATH + 1] = {0};
    DWORD length = GetTempPathW(MAX_PATH, temp);
    state("TEMP_PATH", length > 0 && length < MAX_PATH &&
          GetFileAttributesW(temp) != INVALID_FILE_ATTRIBUTES);

    puts("SWCOMPAT_PREREQ_PROBE=PASS");
    fflush(stdout);
    return 0;
}
