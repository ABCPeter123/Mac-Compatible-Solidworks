/* Read-only Win32 window and process enumeration for installer diagnostics.
 * Never reads or exports window titles, command lines, user paths, screenshots,
 * process environment, registry or serial/license information.
 * Candidate executable names are a heuristic, not UI proof.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <cwchar>
#include <cstdio>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <string>
#include <algorithm>
#include <cwctype>

struct ProcessRow {
    DWORD pid;
    DWORD parent;
    bool candidate;
};
static bool matches_installer_name(const wchar_t *name) {
    std::wstring s(name ? name : L"");
    std::transform(s.begin(), s.end(), s.begin(), [](wchar_t c) { return std::towlower(c); });
    return s == L"solidworkssetup.exe" || s == L"sldim.exe"
        || s == L"setup.exe" || s == L"sldimdownloader.exe"
        || s == L"solidworks installation manager.exe";
}

struct WindowCounts {
    int visible_large = 0;
    int candidate_visible = 0;
    std::unordered_set<DWORD> candidate_ids;
};
static BOOL CALLBACK enumerate(HWND hwnd, LPARAM data) {
    auto *counts = reinterpret_cast<WindowCounts *>(data);
    if (!IsWindowVisible(hwnd) || GetWindow(hwnd, GW_OWNER) != nullptr) return TRUE;
    RECT area = {};
    if (!GetWindowRect(hwnd, &area) || area.right - area.left < 160 ||
        area.bottom - area.top < 100) return TRUE;
    ++counts->visible_large;
    DWORD pid = 0;
    GetWindowThreadProcessId(hwnd, &pid);
    if (counts->candidate_ids.count(pid)) ++counts->candidate_visible;
    return TRUE;
}

int main() {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        puts("SWCOMPAT_SW_UI_PROBE=UNAVAILABLE");
        return 1;
    }
    std::vector<ProcessRow> processes;
    PROCESSENTRY32W entry = {};
    entry.dwSize = sizeof(entry);
    if (Process32FirstW(snap, &entry)) {
        do {
            processes.push_back({entry.th32ProcessID, entry.th32ParentProcessID,
                                 matches_installer_name(entry.szExeFile)});
            entry.dwSize = sizeof(entry);
        } while (Process32NextW(snap, &entry) && processes.size() < 8192);
    }
    CloseHandle(snap);
    WindowCounts counts;
    for (const auto &p : processes) {
        if (p.candidate) counts.candidate_ids.insert(p.pid);
    }
    /* Include children of known installer process names to catch helper windows. */
    bool changed = true;
    for (int i = 0; changed && i < 8; ++i) {
        changed = false;
        for (const auto &p : processes) {
            if (counts.candidate_ids.count(p.parent) && !counts.candidate_ids.count(p.pid)) {
                counts.candidate_ids.insert(p.pid);
                changed = true;
            }
        }
    }
    if (!EnumWindows(enumerate, reinterpret_cast<LPARAM>(&counts))) {
        puts("SWCOMPAT_SW_UI_PROBE=UNAVAILABLE");
        return 1;
    }
    std::printf("SWCOMPAT_SW_UI_CANDIDATE_PROCESSES=%u\n",
                static_cast<unsigned>(counts.candidate_ids.size()));
    std::printf("SWCOMPAT_SW_UI_CANDIDATE_WINDOWS=%d\n", counts.candidate_visible);
    std::printf("SWCOMPAT_SW_UI_VISIBLE_LARGE_WINDOWS=%d\n", counts.visible_large);
    puts("SWCOMPAT_SW_UI_PROBE=COMPLETE");
    return 0;
}
