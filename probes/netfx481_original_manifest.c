/*
 * Read-only RT_MANIFEST classification for an already Authenticode-verified
 * original Microsoft .NET 4.8.1 redistributable. Never execute, edit or
 * republish Microsoft executable, resource bytes, paths or identifiers.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wchar.h>
#include <stdio.h>
#include <string.h>

#define MAX_MANIFEST_SIZE 65536u
static const char win10_guid[] = "8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a";

static unsigned char fold(unsigned char c) {
    return c >= 'A' && c <= 'Z' ? (unsigned char)(c + 'a' - 'A') : c;
}

static int contains_guid(const BYTE *data, DWORD len, int stride) {
    size_t i, j, count = sizeof(win10_guid) - 1;
    if ((size_t)len < count * (size_t)stride)
        return 0;
    for (i = 0; i + count * (size_t)stride <= (size_t)len; i++) {
        for (j = 0; j < count; j++) {
            if (fold(data[i + j * (size_t)stride]) !=
                    (unsigned char)win10_guid[j])
                break;
            if (stride == 2 && data[i + j * 2 + 1] != 0)
                break;
        }
        if (j == count)
            return 1;
    }
    return 0;
}

static const char *inspect(const wchar_t *filename) {
    HMODULE module;
    HRSRC resource;
    HGLOBAL loaded;
    const BYTE *bytes;
    DWORD len;
    module = LoadLibraryExW(filename, NULL,
                            LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE);
    if (!module)
        return "OPEN_FAILED";
    resource = FindResourceW(module, MAKEINTRESOURCEW(1), MAKEINTRESOURCEW(24));
    if (!resource) {
        FreeLibrary(module);
        return "CREATEPROCESS_MANIFEST_ABSENT";
    }
    len = SizeofResource(module, resource);
    if (!len || len > MAX_MANIFEST_SIZE) {
        FreeLibrary(module);
        return "MANIFEST_UNREADABLE";
    }
    loaded = LoadResource(module, resource);
    bytes = loaded ? (const BYTE *)LockResource(loaded) : NULL;
    if (!bytes) {
        FreeLibrary(module);
        return "MANIFEST_UNREADABLE";
    }
    {
        int found = contains_guid(bytes, len, 1) || contains_guid(bytes, len, 2);
        FreeLibrary(module);
        return found ? "WIN10_SUPPORTED_OS_DECLARED" : "WIN10_SUPPORTED_OS_ABSENT";
    }
}

int wmain(int argc, wchar_t **argv) {
    const char *state = "INVALID_INPUT";
    if (argc == 2 && argv[1] && wcslen(argv[1]) < 4096)
        state = inspect(argv[1]);
    printf("SWCOMPAT_ORIGINAL_MANIFEST_SCHEMA=1\n");
    printf("SWCOMPAT_ORIGINAL_MANIFEST_STATUS=%s\n", state);
    return (argc == 2 && wcscmp(state, "OPEN_FAILED") != 0 &&
            wcscmp(state, "INVALID_INPUT") != 0) ? 0 : 1;
}
