/* Self-authored x86 Windows process control, no Microsoft dependencies.
 * Compile with native Windows x86 MSVC and verify there before Apple Silicon.
 * No file, system registry or service modification; stdout is fixed markers.
 */
#include <windows.h>
#include <stdio.h>

int main(void)
{
    HMODULE kernel = GetModuleHandleW(L"kernel32.dll");
    FARPROC sleep_proc = kernel ? GetProcAddress(kernel, "Sleep") : NULL;
    int pass = sizeof(void *) == 4 && kernel != NULL && sleep_proc != NULL;
    printf("SWCOMPAT_WOW64_NATIVE_SCHEMA=1\n");
    printf("SWCOMPAT_WOW64_NATIVE_RESULT=%s\n", pass ? "PASS" : "FAIL");
    return pass ? 0 : 1;
}
