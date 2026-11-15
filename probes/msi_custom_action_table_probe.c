/* Safe original read-only Win32 CustomAction metadata probe.
 * Action name arrives via stdin; never included in argv or printed.
 * Resolve MSI functions dynamically to distinguish Wine loader failure from
 * Windows Installer database errors without adding fake CLR libraries.
 */
#include <windows.h>
#include <msiquery.h>
#include <stdio.h>

typedef UINT (WINAPI *P_OPEN_DATABASE)(LPCWSTR, LPCWSTR, MSIHANDLE *);
typedef UINT (WINAPI *P_OPEN_VIEW)(MSIHANDLE, LPCWSTR, MSIHANDLE *);
typedef MSIHANDLE (WINAPI *P_CREATE_RECORD)(UINT);
typedef UINT (WINAPI *P_SET_STRING)(MSIHANDLE, UINT, LPCWSTR);
typedef UINT (WINAPI *P_EXEC_VIEW)(MSIHANDLE, MSIHANDLE);
typedef UINT (WINAPI *P_FETCH_VIEW)(MSIHANDLE, MSIHANDLE *);
typedef int (WINAPI *P_GET_INTEGER)(MSIHANDLE, UINT);
typedef UINT (WINAPI *P_CLOSE_VIEW)(MSIHANDLE);
typedef UINT (WINAPI *P_CLOSE_HANDLE)(MSIHANDLE);

static HANDLE diagnostic_file = INVALID_HANDLE_VALUE;

static void emit(const char *line)
{
    DWORD written = 0;
    printf("%s\n", line);
    fflush(stdout);
    if (diagnostic_file != INVALID_HANDLE_VALUE)
    {
        WriteFile(diagnostic_file, line, lstrlenA(line), &written, NULL);
        WriteFile(diagnostic_file, "\r\n", 2, &written, NULL);
        FlushFileBuffers(diagnostic_file);
    }
}

static void stage(const char *phase)
{
    char line[128];
    wsprintfA(line, "SWCOMPAT_CA_TABLE_STAGE=%s", phase);
    emit(line);
}

static int result(const char *status, unsigned int type)
{
    char line[128];
    wsprintfA(line, "SWCOMPAT_CA_TABLE_STATUS=%s", status);
    emit(line);
    wsprintfA(line, "SWCOMPAT_CA_TABLE_TYPE=%u", type);
    emit(line);
    if (diagnostic_file != INVALID_HANDLE_VALUE)
    {
        CloseHandle(diagnostic_file);
        diagnostic_file = INVALID_HANDLE_VALUE;
    }
    return 0;
}

int wmain(int argc, wchar_t **argv)
{
    unsigned char utf8[1408] = {0};
    wchar_t action[352] = {0};
    DWORD read = 0;
    size_t count = 0;
    HMODULE library = NULL;
    MSIHANDLE db = 0, view = 0, param = 0, record = 0;
    UINT rc = ERROR_FUNCTION_FAILED;
    int type = MSI_NULL_INTEGER;
    P_OPEN_DATABASE open_database;
    P_OPEN_VIEW open_view;
    P_CREATE_RECORD create_record;
    P_SET_STRING set_string;
    P_EXEC_VIEW execute_view;
    P_FETCH_VIEW fetch_view;
    P_GET_INTEGER get_integer;
    P_CLOSE_VIEW close_view;
    P_CLOSE_HANDLE close_handle;

    if (argc == 3 && argv[2] && argv[2][0])
        diagnostic_file = CreateFileW(argv[2], GENERIC_WRITE,
                FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    stage("ENTRY");
    if ((argc != 2 && argc != 3) || !argv[1] || !argv[1][0])
        return result("INVALID_ARGUMENT", 0);
    if (!ReadFile(GetStdHandle(STD_INPUT_HANDLE), utf8,
                  sizeof(utf8) - 1, &read, NULL) || !read)
        return result("INVALID_ARGUMENT", 0);
    for (count = 0; count < read; ++count)
        if (utf8[count] == '\r' || utf8[count] == '\n' || utf8[count] == '\0')
            break;
    if (!count || (count >= read && read >= sizeof(utf8) - 1))
        return result("INVALID_ARGUMENT", 0);
    utf8[count] = 0;
    if (!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                             (const char *)utf8, -1, action, 352))
        return result("INVALID_ARGUMENT", 0);
    stage("INPUT_OK");
    library = LoadLibraryW(L"msi.dll");
    if (!library) return result("MSI_DLL_UNAVAILABLE", 0);
    stage("MSI_DLL_LOADED");

    open_database = (P_OPEN_DATABASE)GetProcAddress(library, "MsiOpenDatabaseW");
    open_view = (P_OPEN_VIEW)GetProcAddress(library, "MsiDatabaseOpenViewW");
    create_record = (P_CREATE_RECORD)GetProcAddress(library, "MsiCreateRecord");
    set_string = (P_SET_STRING)GetProcAddress(library, "MsiRecordSetStringW");
    execute_view = (P_EXEC_VIEW)GetProcAddress(library, "MsiViewExecute");
    fetch_view = (P_FETCH_VIEW)GetProcAddress(library, "MsiViewFetch");
    get_integer = (P_GET_INTEGER)GetProcAddress(library, "MsiRecordGetInteger");
    close_view = (P_CLOSE_VIEW)GetProcAddress(library, "MsiViewClose");
    close_handle = (P_CLOSE_HANDLE)GetProcAddress(library, "MsiCloseHandle");
    if (!open_database || !open_view || !create_record || !set_string ||
        !execute_view || !fetch_view || !get_integer || !close_view || !close_handle)
    {
        FreeLibrary(library);
        return result("MSI_EXPORT_UNAVAILABLE", 0);
    }
    stage("MSI_EXPORTS_READY");
    rc = open_database(argv[1], MSIDBOPEN_READONLY, &db);
    if (rc != ERROR_SUCCESS)
    {
        FreeLibrary(library);
        return result("DATABASE_UNAVAILABLE", 0);
    }
    stage("DATABASE_OPEN");
    rc = open_view(db,
            L"SELECT `Type` FROM `CustomAction` WHERE `Action` = ?", &view);
    if (rc != ERROR_SUCCESS)
    {
        close_handle(db);
        FreeLibrary(library);
        return result("TABLE_UNAVAILABLE", 0);
    }
    stage("VIEW_OPEN");
    param = create_record(1);
    if (!param || set_string(param, 1, action) != ERROR_SUCCESS)
    {
        if (param) close_handle(param);
        close_handle(view);
        close_handle(db);
        FreeLibrary(library);
        return result("QUERY_FAILED", 0);
    }
    stage("PARAMETER_SET");
    rc = execute_view(view, param);
    if (rc != ERROR_SUCCESS)
    {
        close_handle(param);
        close_handle(view);
        close_handle(db);
        FreeLibrary(library);
        return result("QUERY_FAILED", 0);
    }
    stage("VIEW_EXECUTED");
    rc = fetch_view(view, &record);
    if (rc == ERROR_NO_MORE_ITEMS)
    {
        close_view(view);
        close_handle(param);
        close_handle(view);
        close_handle(db);
        FreeLibrary(library);
        return result("ACTION_ABSENT", 0);
    }
    if (rc != ERROR_SUCCESS)
    {
        close_view(view);
        close_handle(param);
        close_handle(view);
        close_handle(db);
        FreeLibrary(library);
        return result("QUERY_FAILED", 0);
    }
    stage("ROW_FETCHED");
    type = get_integer(record, 1);
    close_handle(record);
    close_view(view);
    close_handle(param);
    close_handle(view);
    close_handle(db);
    FreeLibrary(library);
    if (type == MSI_NULL_INTEGER || type < 0)
        return result("QUERY_FAILED", 0);
    return result("ACTION_FOUND", (unsigned int)type);
}
