/* Read-only Windows Installer CustomAction table metadata.
 * Receives the exact action identifier on standard input, never argv.
 * Emits only fixed status and Type, never names, paths or MSI contents.
 * Source-authored for comparing native Windows and Apple Silicon Wine.
 */
#define UNICODE
#define _UNICODE
#include <windows.h>
#include <msi.h>
#include <stdio.h>

static int result(const char *status, unsigned int type)
{
    printf("SWCOMPAT_CA_TABLE_STATUS=%s\n", status);
    printf("SWCOMPAT_CA_TABLE_TYPE=%u\n", type);
    return 0;
}

int wmain(int argc, wchar_t **argv)
{
    unsigned char utf8[1408] = {0};
    wchar_t action[352] = {0};
    DWORD read = 0;
    size_t count = 0;
    MSIHANDLE db = 0, view = 0, param = 0, record = 0;
    UINT rc = 0;
    int type = MSI_NULL_INTEGER;
    if (argc != 2 || !argv[1] || !argv[1][0])
        return result("INVALID_ARGUMENT", 0);
    if (!ReadFile(GetStdHandle(STD_INPUT_HANDLE), utf8,
                  sizeof(utf8) - 1, &read, NULL) || !read)
        return result("INVALID_ARGUMENT", 0);
    for (count = 0; count < read; ++count)
        if (utf8[count] == '\r' || utf8[count] == '\n' || utf8[count] == '\0')
            break;
    if (!count || count >= read && read >= sizeof(utf8) - 1)
        return result("INVALID_ARGUMENT", 0);
    utf8[count] = 0;
    if (!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                             (const char *)utf8, -1, action, 352))
        return result("INVALID_ARGUMENT", 0);
    rc = MsiOpenDatabaseW(argv[1], MSIDBOPEN_READONLY, &db);
    if (rc != ERROR_SUCCESS) return result("DATABASE_UNAVAILABLE", 0);
    rc = MsiDatabaseOpenViewW(db,
            L"SELECT `Type` FROM `CustomAction` WHERE `Action` = ?", &view);
    if (rc != ERROR_SUCCESS)
    {
        MsiCloseHandle(db);
        return result("TABLE_UNAVAILABLE", 0);
    }
    param = MsiCreateRecord(1);
    if (!param || MsiRecordSetStringW(param, 1, action) != ERROR_SUCCESS)
    {
        if (param) MsiCloseHandle(param);
        MsiCloseHandle(view);
        MsiCloseHandle(db);
        return result("QUERY_FAILED", 0);
    }
    rc = MsiViewExecute(view, param);
    if (rc != ERROR_SUCCESS)
    {
        MsiCloseHandle(param);
        MsiCloseHandle(view);
        MsiCloseHandle(db);
        return result("QUERY_FAILED", 0);
    }
    rc = MsiViewFetch(view, &record);
    if (rc == ERROR_NO_MORE_ITEMS)
    {
        MsiViewClose(view);
        MsiCloseHandle(param);
        MsiCloseHandle(view);
        MsiCloseHandle(db);
        return result("ACTION_ABSENT", 0);
    }
    if (rc != ERROR_SUCCESS)
    {
        MsiViewClose(view);
        MsiCloseHandle(param);
        MsiCloseHandle(view);
        MsiCloseHandle(db);
        return result("QUERY_FAILED", 0);
    }
    type = MsiRecordGetInteger(record, 1);
    MsiCloseHandle(record);
    MsiViewClose(view);
    MsiCloseHandle(param);
    MsiCloseHandle(view);
    MsiCloseHandle(db);
    if (type == MSI_NULL_INTEGER || type < 0)
        return result("QUERY_FAILED", 0);
    return result("ACTION_FOUND", (unsigned int)type);
}
