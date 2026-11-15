/* Self-authored, read-only Windows filesystem capacity differential.
 * Never reads, changes, or prints user files, free-byte values, or host paths.
 * The categories are deliberately conservative: Microsoft documents 4.5 GB
 * of minimum .NET Framework disk space, but does not specify GB rounding.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <wchar.h>
#define FLOOR_BYTES 4500000000ULL
#define CLEAR_BYTES 5000000000ULL

static const char *category(ULONGLONG bytes)
{
    if (bytes < FLOOR_BYTES) return "BELOW_4P5GB";
    if (bytes < CLEAR_BYTES) return "BORDERLINE_4P5_5GB";
    return "ABOVE_5GB";
}

static const char *capacity_ex(const WCHAR *path)
{
    ULARGE_INTEGER to_caller, total, total_free;
    if (!GetDiskFreeSpaceExW(path, &to_caller, &total, &total_free))
        return "API_FAILED";
    return category(to_caller.QuadPart);
}

static const char *legacy_c(void)
{
    DWORD sectors = 0, bytes = 0, free_clusters = 0, total_clusters = 0;
    ULONGLONG free_space;
    if (!GetDiskFreeSpaceW(L"C:\\", &sectors, &bytes,
                           &free_clusters, &total_clusters))
        return "API_FAILED";
    free_space = (ULONGLONG)sectors * (ULONGLONG)bytes * (ULONGLONG)free_clusters;
    return category(free_space);
}

int wmain(void)
{
    WCHAR temp[MAX_PATH];
    WCHAR root[MAX_PATH];
    DWORD length = GetTempPathW(MAX_PATH, temp);
    const char *temp_category = "TEMP_PATH_FAILED";
    const char *same_volume = "UNKNOWN";
    if (length && length < MAX_PATH) {
        temp_category = capacity_ex(temp);
        if (GetVolumePathNameW(temp, root, MAX_PATH)) {
            same_volume = (root[0] == L'C' || root[0] == L'c')
                          && root[1] == L':' && root[2] == L'\\'
                          && root[3] == 0 ? "YES" : "NO";
        }
    }
    printf("SWCOMPAT_DISK_SCHEMA=1\n");
    printf("SWCOMPAT_DISK_C=%s\n", capacity_ex(L"C:\\"));
    printf("SWCOMPAT_DISK_TEMP=%s\n", temp_category);
    printf("SWCOMPAT_DISK_LEGACY=%s\n", legacy_c());
    printf("SWCOMPAT_DISK_TEMP_SAME_VOLUME=%s\n", same_volume);
    return 0;
}
