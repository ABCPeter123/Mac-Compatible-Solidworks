/* Harmless native x64 Windows Installer deferred DLL regression.
 * The exported original test action returns MSI 1603 without side effects.
 * No service modifications, Microsoft payload or product files.
 */
#include <windows.h>
#include <msi.h>

__declspec(dllexport) UINT __stdcall SWCompatIntentionalFailure(MSIHANDLE hinstall)
{
    (void)hinstall;
    return ERROR_INSTALL_FAILURE;
}
