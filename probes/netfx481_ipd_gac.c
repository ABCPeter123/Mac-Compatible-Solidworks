/* Private original-payload GAC registration fixture. No CLR or Mono execution.
 * Use the exact installed Microsoft Fusion library and documented cache API.
 * Accept one verified path at a time from the guarded host. */
#define COBJMACROS
#include <windows.h>
#include <fusion.h>
#include <stdio.h>
#include <wchar.h>

typedef HRESULT (WINAPI *create_cache_fn)(IAssemblyCache **, DWORD);

int wmain(int argc, WCHAR **argv)
{
    HMODULE fusion = NULL;
    create_cache_fn create_cache;
    IAssemblyCache *cache = NULL;
    HRESULT hr = E_FAIL;
    unsigned phase = 0;
    int i;
    if (argc < 2 || argc > 33) return 2;
    for (i = 1; i < argc; i++)
        if (_wcsnicmp(argv[i], L"Z:\\", 3)) return 2;
    if (!(fusion = LoadLibraryExW(L"C:\\windows\\Microsoft.NET\\Framework64\\v4.0.30319\\fusion.dll",
                                 NULL, LOAD_WITH_ALTERED_SEARCH_PATH)))
    {
        phase = 1;
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto done;
    }
    if (!(create_cache = (create_cache_fn)GetProcAddress(fusion, "CreateAssemblyCache")))
    {
        phase = 2;
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto done;
    }
    phase = 3;
    hr = create_cache(&cache, 0);
    if (FAILED(hr) || !cache) goto done;
    phase = 4;
    printf("SWCOMPAT_IPD_GAC_SCHEMA=1\n");
    for (i = 1; i < argc; i++)
    {
        hr = cache->lpVtbl->InstallAssembly(cache, IASSEMBLYCACHE_INSTALL_FLAG_FORCE_REFRESH,
                                           argv[i], NULL);
        printf("SWCOMPAT_IPD_GAC_ITEM=%08lX\n", (unsigned long)(DWORD)hr);
    }
done:
    if (cache) cache->lpVtbl->Release(cache);
    if (fusion) FreeLibrary(fusion);
    if (phase != 4)
        printf("SWCOMPAT_IPD_GAC_SCHEMA=1\nSWCOMPAT_IPD_GAC_FAILURE=%u:%08lX\n",
               phase, (unsigned long)(DWORD)hr);
    return 0;
}
