/* Self-authored, read-only Windows version probe. No vendor content or paths. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <wchar.h>
#include <stdlib.h>
typedef LONG (WINAPI *GET_NT_VERSION)(OSVERSIONINFOEXW *);
static const char *cat(DWORD major,DWORD minor,DWORD build) {
    if (major==10 && minor==0 && build>=19042 && build<22000) return "WIN10_SUPPORTED";
    if (major==10 && minor==0 && build>=22000 && build<30000) return "WIN11_SUPPORTED";
    if (major==10 && minor==0) return "WIN10_TOO_OLD";
    return "BELOW_WIN10";
}
static const char *registry_build(void) {
    HKEY key; WCHAR buffer[64]; DWORD size=sizeof(buffer), type=0; long build;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,L"Software\\Microsoft\\Windows NT\\CurrentVersion",0,
                     KEY_QUERY_VALUE|KEY_WOW64_64KEY,&key)!=ERROR_SUCCESS)
        return "NOT_VERIFIED";
    if (RegQueryValueExW(key,L"CurrentBuildNumber",NULL,&type,(BYTE*)buffer,&size)!=ERROR_SUCCESS
        || type!=REG_SZ || size<4 || size>sizeof(buffer)) {
        RegCloseKey(key); return "NOT_VERIFIED";
    }
    buffer[(size/sizeof(WCHAR))-1]=L'\0';
    build=wcstol(buffer,NULL,10); RegCloseKey(key);
    if (build>=19042 && build<22000) return "WIN10_SUPPORTED";
    if (build>=22000 && build<30000) return "WIN11_SUPPORTED";
    if (build>=10000 && build<19042) return "WIN10_TOO_OLD";
    return "NOT_VERIFIED";
}
int main(void) {
    OSVERSIONINFOEXW app={0}, native={0};
    HMODULE ntdll=GetModuleHandleW(L"ntdll.dll");
    GET_NT_VERSION get_nt=ntdll?(GET_NT_VERSION)GetProcAddress(ntdll,"RtlGetVersion"):NULL;
    SYSTEM_INFO system={0};
    const char *api="NOT_VERIFIED", *nt="NOT_VERIFIED", *arch="UNKNOWN";
    app.dwOSVersionInfoSize=sizeof(app); native.dwOSVersionInfoSize=sizeof(native);
    if(GetVersionExW((OSVERSIONINFOW*)&app))
        api=cat(app.dwMajorVersion,app.dwMinorVersion,app.dwBuildNumber);
    if(get_nt && get_nt(&native)==0)
        nt=cat(native.dwMajorVersion,native.dwMinorVersion,native.dwBuildNumber);
    GetNativeSystemInfo(&system);
    if(system.wProcessorArchitecture==PROCESSOR_ARCHITECTURE_AMD64) arch="AMD64";
    else if(system.wProcessorArchitecture==PROCESSOR_ARCHITECTURE_INTEL) arch="X86";
    else if(system.wProcessorArchitecture==PROCESSOR_ARCHITECTURE_ARM64) arch="ARM64";
    printf("SWCOMPAT_OS_SCHEMA=1\nSWCOMPAT_OS_WINAPI=%s\nSWCOMPAT_OS_NTDLL=%s\nSWCOMPAT_OS_REGISTRY=%s\nSWCOMPAT_OS_ARCH=%s\n",
           api,nt,registry_build(),arch);
    return 0;
}
