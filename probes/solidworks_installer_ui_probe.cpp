/* Read-only, privacy-safe installer HWND responsiveness and GDI diagnostics.
 *
 * No window titles, screenshots, pixel colors, process paths, serials,
 * command lines, clipboard contents, or proprietary binaries leave this probe.
 * Counts, responsiveness and GDI variation are only heuristic evidence,
 * never proof of visible macOS pixels or successful SOLIDWORKS installation.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <cstdio>
#include <cwchar>
#include <cwctype>
#include <string>
#include <vector>
#include <unordered_set>
#include <algorithm>
#include <cstdint>

struct ProcessRow {
    DWORD pid;
    DWORD parent;
    bool candidate;
};

static bool installer_name(const wchar_t *name) {
    std::wstring s(name ? name : L"");
    std::transform(s.begin(), s.end(), s.begin(), [](wchar_t ch) {
        return static_cast<wchar_t>(std::towlower(ch));
    });
    return s == L"solidworkssetup.exe" || s == L"sldim.exe"
        || s == L"setup.exe" || s == L"sldimdownloader.exe"
        || s == L"solidworks installation manager.exe";
}

enum class Surface { FAILURE, UNIFORM, NONUNIFORM };

static Surface sample_client_gdi(HWND window) {
    RECT client = {};
    if (!GetClientRect(window, &client)) return Surface::FAILURE;
    const int width = client.right - client.left;
    const int height = client.bottom - client.top;
    if (width < 100 || height < 100) return Surface::FAILURE;
    HDC source = GetDC(window);
    if (!source) return Surface::FAILURE;
    HDC target = CreateCompatibleDC(source);
    if (!target) {
        ReleaseDC(window, source);
        return Surface::FAILURE;
    }
    BITMAPINFO info = {};
    info.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    info.bmiHeader.biWidth = 32;
    info.bmiHeader.biHeight = -32;
    info.bmiHeader.biPlanes = 1;
    info.bmiHeader.biBitCount = 32;
    info.bmiHeader.biCompression = BI_RGB;
    void *pixels = nullptr;
    HBITMAP bitmap = CreateDIBSection(source, &info, DIB_RGB_COLORS, &pixels, nullptr, 0);
    Surface outcome = Surface::FAILURE;
    if (bitmap && pixels) {
        HGDIOBJ prior = SelectObject(target, bitmap);
        if (prior && prior != HGDI_ERROR) {
            SetStretchBltMode(target, COLORONCOLOR);
            /* Read center 60% of client area, excluding most window chrome.
             * Never serialize or emit individual pixels or image data.
             */
            const BOOL copied = StretchBlt(target, 0, 0, 32, 32,
                source, width / 5, height / 5, width * 3 / 5, height * 3 / 5, SRCCOPY);
            if (copied) {
                const auto *rgb = static_cast<const uint32_t *>(pixels);
                std::unordered_set<uint32_t> colors;
                for (size_t i = 0; i < 32 * 32 && colors.size() < 2; ++i)
                    colors.insert(rgb[i] & 0x00FFFFFFu);
                outcome = colors.size() >= 2 ? Surface::NONUNIFORM : Surface::UNIFORM;
            }
            SelectObject(target, prior);
        }
    }
    if (bitmap) DeleteObject(bitmap);
    DeleteDC(target);
    ReleaseDC(window, source);
    return outcome;
}

static bool responds_to_null(HWND hwnd) {
    DWORD_PTR ignored = 0;
    return SendMessageTimeoutW(hwnd, WM_NULL, 0, 0,
        SMTO_ABORTIFHUNG | SMTO_BLOCK, 1000, &ignored) != 0;
}

struct WindowCounts {
    int visible_large = 0;
    int candidate_visible = 0;
    int responsive = 0;
    int unresponsive = 0;
    int nonuniform = 0;
    int uniform = 0;
    int failed_readback = 0;
    std::unordered_set<DWORD> candidate_ids;
};

static BOOL CALLBACK enumerate(HWND hwnd, LPARAM userdata) {
    auto *counts = reinterpret_cast<WindowCounts *>(userdata);
    if (!IsWindowVisible(hwnd) || GetWindow(hwnd, GW_OWNER) != nullptr) return TRUE;
    RECT bounds = {};
    if (!GetWindowRect(hwnd, &bounds) || bounds.right - bounds.left < 160 ||
        bounds.bottom - bounds.top < 100) return TRUE;
    ++counts->visible_large;
    DWORD pid = 0;
    GetWindowThreadProcessId(hwnd, &pid);
    if (!counts->candidate_ids.count(pid)) return TRUE;
    ++counts->candidate_visible;
    if (responds_to_null(hwnd)) ++counts->responsive;
    else ++counts->unresponsive;
    switch (sample_client_gdi(hwnd)) {
        case Surface::NONUNIFORM: ++counts->nonuniform; break;
        case Surface::UNIFORM: ++counts->uniform; break;
        case Surface::FAILURE: ++counts->failed_readback; break;
    }
    return TRUE;
}

static LRESULT CALLBACK test_wndproc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam) {
    if (msg == WM_PAINT) {
        PAINTSTRUCT paint = {};
        HDC hdc = BeginPaint(hwnd, &paint);
        RECT r = {};
        GetClientRect(hwnd, &r);
        RECT top = {0, 0, r.right, r.bottom / 2};
        RECT bottom = {0, r.bottom / 2, r.right, r.bottom};
        HBRUSH blue = CreateSolidBrush(RGB(19, 83, 147));
        HBRUSH green = CreateSolidBrush(RGB(29, 205, 91));
        FillRect(hdc, &top, blue);
        FillRect(hdc, &bottom, green);
        DeleteObject(blue);
        DeleteObject(green);
        EndPaint(hwnd, &paint);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wparam, lparam);
}

static int self_test() {
    WNDCLASSW wc = {};
    wc.lpfnWndProc = test_wndproc;
    wc.hInstance = GetModuleHandleW(nullptr);
    wc.lpszClassName = L"SWCompatSyntheticWindowProbe";
    if (!RegisterClassW(&wc)) return 1;
    HWND hwnd = CreateWindowW(wc.lpszClassName, L"synthetic no-license control",
        WS_OVERLAPPEDWINDOW, 100, 100, 360, 280,
        nullptr, nullptr, wc.hInstance, nullptr);
    if (!hwnd) return 1;
    ShowWindow(hwnd, SW_SHOWNORMAL);
    UpdateWindow(hwnd);
    const bool responsive = responds_to_null(hwnd);
    const Surface variation = sample_client_gdi(hwnd);
    DestroyWindow(hwnd);
    if (!responsive || variation != Surface::NONUNIFORM) {
        puts("SWCOMPAT_SW_UI_SELF_TEST=FAIL");
        return 1;
    }
    puts("SWCOMPAT_SW_UI_SELF_TEST=PASS");
    return 0;
}

int wmain(int argc, wchar_t **argv) {
    if (argc == 2 && std::wcscmp(argv[1], L"--self-test") == 0) return self_test();
    if (argc != 1) return 2;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        puts("SWCOMPAT_SW_UI_PROBE=UNAVAILABLE");
        return 1;
    }
    std::vector<ProcessRow> processes;
    PROCESSENTRY32W row = {};
    row.dwSize = sizeof(row);
    if (Process32FirstW(snapshot, &row)) {
        do {
            processes.push_back({
                row.th32ProcessID, row.th32ParentProcessID,
                installer_name(row.szExeFile)
            });
            row.dwSize = sizeof(row);
        } while (Process32NextW(snapshot, &row) && processes.size() < 8192);
    }
    CloseHandle(snapshot);
    WindowCounts counts;
    for (const auto &p : processes)
        if (p.candidate) counts.candidate_ids.insert(p.pid);
    bool updated = true;
    for (int i = 0; updated && i < 8; ++i) {
        updated = false;
        for (const auto &p : processes) {
            if (counts.candidate_ids.count(p.parent) &&
                !counts.candidate_ids.count(p.pid)) {
                counts.candidate_ids.insert(p.pid);
                updated = true;
            }
        }
    }
    if (!EnumWindows(enumerate, reinterpret_cast<LPARAM>(&counts))) {
        puts("SWCOMPAT_SW_UI_PROBE=UNAVAILABLE");
        return 1;
    }
    const char *response = counts.candidate_visible == 0 ? "NO_CANDIDATE"
        : counts.responsive > 0 ? "RESPONSIVE" : "UNRESPONSIVE";
    const char *surface = counts.candidate_visible == 0 ? "NO_CANDIDATE"
        : counts.nonuniform > 0 ? "NONUNIFORM"
        : counts.uniform > 0 ? "UNIFORM" : "READBACK_FAILED";
    std::printf("SWCOMPAT_SW_UI_CANDIDATE_PROCESSES=%u\n",
        static_cast<unsigned>(counts.candidate_ids.size()));
    std::printf("SWCOMPAT_SW_UI_CANDIDATE_WINDOWS=%d\n", counts.candidate_visible);
    std::printf("SWCOMPAT_SW_UI_VISIBLE_LARGE_WINDOWS=%d\n", counts.visible_large);
    std::printf("SWCOMPAT_SW_UI_RESPONSIVENESS=%s\n", response);
    std::printf("SWCOMPAT_SW_UI_GDI_CLIENT=%s\n", surface);
    puts("SWCOMPAT_SW_UI_PROBE=COMPLETE");
    return 0;
}
