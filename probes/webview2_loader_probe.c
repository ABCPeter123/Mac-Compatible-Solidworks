/* Independent Windows x64 Microsoft WebView2 loader discovery probe.
 * The official Microsoft.Web.WebView2 SDK supplies WebView2Loader.dll at
 * runtime; our executable contains no bundled browser or SOLIDWORKS code.
 *
 * This calls only the documented browser-version query. A detected version
 * does NOT prove WebView2 browser environment/controller creation works.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <objbase.h>
#include <stdio.h>

typedef HRESULT (STDAPICALLTYPE *query_version_fn)(PCWSTR, LPWSTR *);

static int fail(const char *stage) {
    printf("SWCOMPAT_WEBVIEW2_STAGE=%s\n", stage);
    puts("SWCOMPAT_WEBVIEW2_LOADER=FAIL");
    puts("SWCOMPAT_WEBVIEW2_PROBE=FAIL");
    fflush(stdout);
    return 1;
}

int main(void) {
    HMODULE loader = LoadLibraryW(L"WebView2Loader.dll");
    if (!loader) {
        printf("SWCOMPAT_WEBVIEW2_WINERR=%lu\n", (unsigned long)GetLastError());
        return fail("LoadLibraryW");
    }
    query_version_fn query = (query_version_fn)(void *)
        GetProcAddress(loader, "GetAvailableCoreWebView2BrowserVersionString");
    if (!query) {
        printf("SWCOMPAT_WEBVIEW2_WINERR=%lu\n", (unsigned long)GetLastError());
        FreeLibrary(loader);
        return fail("GetProcAddress");
    }

    LPWSTR version = NULL;
    HRESULT hr = query(NULL, &version);
    printf("SWCOMPAT_WEBVIEW2_VERSION_QUERY_HRESULT=0x%08lX\n",
           (unsigned long)(DWORD)hr);

    if (SUCCEEDED(hr) && version && version[0] != 0) {
        puts("SWCOMPAT_WEBVIEW2_RUNTIME=VERSION_FOUND");
    } else if (FAILED(hr)) {
        puts("SWCOMPAT_WEBVIEW2_RUNTIME=NOT_DISCOVERED");
    } else {
        if (version) CoTaskMemFree(version);
        FreeLibrary(loader);
        return fail("InvalidVersionReply");
    }

    if (version) CoTaskMemFree(version);
    if (!FreeLibrary(loader)) return fail("FreeLibrary");
    puts("SWCOMPAT_WEBVIEW2_LOADER=PASS");
    puts("SWCOMPAT_WEBVIEW2_PROBE=COMPLETE");
    fflush(stdout);
    return 0;
}
