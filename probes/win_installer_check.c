/* Inspect user-level MSI installation of our own harmless test package. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <msi.h>
#include <stdio.h>
#include <string.h>

#define PRODUCT_CODE L"{EB00D74E-5D24-49C6-BFB1-FF694AE23719}"

int main(int argc, char **argv) {
    if (argc != 2 || (strcmp(argv[1], "installed") && strcmp(argv[1], "removed"))) {
        fprintf(stderr, "Usage: installer_check.exe installed|removed\n");
        return 2;
    }
    wchar_t local[MAX_PATH] = {0};
    DWORD len = GetEnvironmentVariableW(L"LOCALAPPDATA", local, MAX_PATH);
    if (!len || len >= MAX_PATH) {
        puts("SWCOMPAT_INSTALLER_CHECK=FAIL");
        puts("SWCOMPAT_INSTALLER_STAGE=LocalAppData");
        return 1;
    }
    wchar_t path[MAX_PATH * 2] = {0};
    if (swprintf(path, MAX_PATH * 2, L"%ls\\SWCompatProbe\\probe-marker.txt", local) <= 0) {
        return 1;
    }
    DWORD attr = GetFileAttributesW(path);
    int file_present = attr != INVALID_FILE_ATTRIBUTES && !(attr & FILE_ATTRIBUTE_DIRECTORY);
    int content_ok = 0;
    if (file_present) {
        HANDLE file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
        if (file != INVALID_HANDLE_VALUE) {
            char buffer[128] = {0};
            DWORD bytes = 0;
            if (ReadFile(file, buffer, sizeof(buffer) - 1, &bytes, NULL))
                content_ok = strstr(buffer, "SWCOMPAT_MSI_PAYLOAD_V1") != NULL;
            CloseHandle(file);
        }
    }
    INSTALLSTATE state = MsiQueryProductStateW(PRODUCT_CODE);
    int registered = state == INSTALLSTATE_DEFAULT;
    int expected_present = !strcmp(argv[1], "installed");
    int passed = expected_present ? (file_present && content_ok && registered)
                                  : (!file_present && !registered);

    printf("SWCOMPAT_MSI_FILE_PRESENT=%d\n", file_present);
    printf("SWCOMPAT_MSI_CONTENT_OK=%d\n", content_ok);
    printf("SWCOMPAT_MSI_INSTALL_STATE=%d\n", (int)state);
    printf("SWCOMPAT_MSI_REGISTERED=%d\n", registered);
    printf("SWCOMPAT_MSI_EXPECTED=%s\n", argv[1]);
    printf("SWCOMPAT_MSI_CHECK=%s\n", passed ? "PASS" : "FAIL");
    fflush(stdout);
    return passed ? 0 : 1;
}
