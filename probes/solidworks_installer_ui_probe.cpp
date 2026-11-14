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
enum class FailureStage {
    NONE, CLIENT_RECT, CLIENT_TOO_SMALL, SOURCE_DC,
    MEMORY_DC, DIB_CREATE, BITMAP_SELECT, STRETCH_BLT
};

struct GdiSample {
    Surface surface = Surface::FAILURE;
    Surface direct_pixel = Surface::FAILURE;
    FailureStage failure = FailureStage::CLIENT_RECT;
};

static Surface sample_direct_getpixel(HDC source, int width, int height) {
    std::unordered_set<COLORREF> colors;
    /* Always sample bounded coordinates within the client rect.
     * RGB values are used only for process-local aggregate variation.
     */
    for (int y = 1; y <= 4; ++y) {
        for (int x = 1; x <= 4; ++x) {
            const COLORREF pixel = GetPixel(source, width * x / 5, height * y / 5);
            if (pixel == CLR_INVALID) return Surface::FAILURE;
            colors.insert(pixel);
            if (colors.size() >= 2) return Surface::NONUNIFORM;
        }
    }
    return Surface::UNIFORM;
}

static GdiSample sample_client_gdi(HWND window) {
    GdiSample result;
    RECT client = {};
    if (!GetClientRect(window, &client)) return result;
    const int width = client.right - client.left;
    const int height = client.bottom - client.top;
    if (width < 100 || height < 100) {
        result.failure = FailureStage::CLIENT_TOO_SMALL;
        return result;
    }
    HDC source = GetDC(window);
    if (!source) {
        result.failure = FailureStage::SOURCE_DC;
        return result;
    }
    result.direct_pixel = sample_direct_getpixel(source, width, height);
    HDC target = CreateCompatibleDC(source);
    if (!target) {
        result.failure = FailureStage::MEMORY_DC;
        ReleaseDC(window, source);
        return result;
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
    if (!bitmap || !pixels) {
        result.failure = FailureStage::DIB_CREATE;
    } else {
        HGDIOBJ prior = SelectObject(target, bitmap);
        if (!prior || prior == HGDI_ERROR) {
            result.failure = FailureStage::BITMAP_SELECT;
        } else {
            SetStretchBltMode(target, COLORONCOLOR);
            const BOOL copied = StretchBlt(target, 0, 0, 32, 32,
                source, width / 5, height / 5, width * 3 / 5, height * 3 / 5, SRCCOPY);
            if (!copied) {
                result.failure = FailureStage::STRETCH_BLT;
            } else {
                const auto *rgb = static_cast<const uint32_t *>(pixels);
                std::unordered_set<uint32_t> colors;
                for (size_t i = 0; i < 32 * 32 && colors.size() < 2; ++i)
                    colors.insert(rgb[i] & 0x00FFFFFFu);
                result.surface = colors.size() >= 2 ? Surface::NONUNIFORM : Surface::UNIFORM;
                result.failure = FailureStage::NONE;
            }
            SelectObject(target, prior);
        }
    }
    if (bitmap) DeleteObject(bitmap);
    DeleteDC(target);
    ReleaseDC(window, source);
    return result;
}

static const char *failure_name(FailureStage stage) {
    switch (stage) {
        case FailureStage::NONE: return "NONE";
        case FailureStage::CLIENT_RECT: return "CLIENT_RECT_FAILED";
        case FailureStage::CLIENT_TOO_SMALL: return "CLIENT_TOO_SMALL";
        case FailureStage::SOURCE_DC: return "SOURCE_DC_FAILED";
        case FailureStage::MEMORY_DC: return "MEMORY_DC_FAILED";
        case FailureStage::DIB_CREATE: return "DIB_CREATE_FAILED";
        case FailureStage::BITMAP_SELECT: return "BITMAP_SELECT_FAILED";
        case FailureStage::STRETCH_BLT: return "STRETCH_BLT_FAILED";
    }
    return "UNKNOWN";
}

static bool responds_to_null(HWND hwnd) {
    DWORD_PTR ignored = 0;
    return SendMessageTimeoutW(hwnd, WM_NULL, 0, 0,
        SMTO_ABORTIFHUNG | SMTO_BLOCK, 1000, &ignored) != 0;
}

struct WindowCounts {
    int parent_layered = 0;
    int parent_no_redirection = 0;
    int child_visible = 0;
    int child_layered = 0;
    int child_no_redirection = 0;
    int child_sampled = 0;
    int child_gdi_nonuniform = 0;
    int child_gdi_uniform = 0;
    int child_gdi_failed = 0;
    int visible_large = 0;
    int candidate_visible = 0;
    int owned_visible = 0;
    int responsive = 0;
    int unresponsive = 0;
    int nonuniform = 0;
    int uniform = 0;
    int failed_readback = 0;
    int direct_nonuniform = 0;
    int direct_uniform = 0;
    FailureStage first_failure = FailureStage::NONE;
    std::unordered_set<DWORD> candidate_ids;
};

/* Only aggregate window flags and bounded GDI variation, never handles,
 * class names, text, pixels, URLs or external process information.
 * Child HWNDs may belong to an embedded browser or separate UI process.
 */
#ifndef WS_EX_NOREDIRECTIONBITMAP
#define WS_EX_NOREDIRECTIONBITMAP 0x00200000L
#endif
struct ChildWalk {
    WindowCounts *counts;
    int visited = 0;
};
static BOOL CALLBACK enumerate_child(HWND hwnd, LPARAM userdata) {
    auto *walk = reinterpret_cast<ChildWalk *>(userdata);
    if (++walk->visited > 128) return FALSE;
    RECT area = {};
    if (!IsWindowVisible(hwnd) || !GetWindowRect(hwnd, &area)
        || area.right - area.left < 100 || area.bottom - area.top < 100)
        return TRUE;
    WindowCounts *counts = walk->counts;
    ++counts->child_visible;
    const LONG_PTR ex = GetWindowLongPtrW(hwnd, GWL_EXSTYLE);
    if (ex & WS_EX_LAYERED) ++counts->child_layered;
    if (ex & WS_EX_NOREDIRECTIONBITMAP) ++counts->child_no_redirection;
    if (counts->child_sampled >= 8) return TRUE;
    ++counts->child_sampled;
    const GdiSample child = sample_client_gdi(hwnd);
    if (child.surface == Surface::NONUNIFORM) ++counts->child_gdi_nonuniform;
    else if (child.surface == Surface::UNIFORM) ++counts->child_gdi_uniform;
    else ++counts->child_gdi_failed;
    return TRUE;
}

static BOOL CALLBACK enumerate(HWND hwnd, LPARAM userdata) {
    auto *counts = reinterpret_cast<WindowCounts *>(userdata);
    if (!IsWindowVisible(hwnd)) return TRUE;
    const bool owned_popup = GetWindow(hwnd, GW_OWNER) != nullptr;
    /* Owned, visible top-level dialogs may contain the actual installer UI.
     * Include them without collecting window titles or owner HWND values. */
    RECT bounds = {};
    if (!GetWindowRect(hwnd, &bounds) || bounds.right - bounds.left < 160 ||
        bounds.bottom - bounds.top < 100) return TRUE;
    ++counts->visible_large;
    DWORD pid = 0;
    GetWindowThreadProcessId(hwnd, &pid);
    if (!counts->candidate_ids.count(pid)) return TRUE;
    ++counts->candidate_visible;
    if (owned_popup) ++counts->owned_visible;
    const LONG_PTR ex = GetWindowLongPtrW(hwnd, GWL_EXSTYLE);
    if (ex & WS_EX_LAYERED) ++counts->parent_layered;
    if (ex & WS_EX_NOREDIRECTIONBITMAP) ++counts->parent_no_redirection;
    ChildWalk walk = {counts};
    EnumChildWindows(hwnd, enumerate_child, reinterpret_cast<LPARAM>(&walk));
    if (responds_to_null(hwnd)) ++counts->responsive;
    else ++counts->unresponsive;
    const GdiSample sample = sample_client_gdi(hwnd);
    switch (sample.surface) {
        case Surface::NONUNIFORM: ++counts->nonuniform; break;
        case Surface::UNIFORM: ++counts->uniform; break;
        case Surface::FAILURE:
            ++counts->failed_readback;
            if (counts->first_failure == FailureStage::NONE)
                counts->first_failure = sample.failure;
            break;
    }
    if (sample.direct_pixel == Surface::NONUNIFORM) ++counts->direct_nonuniform;
    if (sample.direct_pixel == Surface::UNIFORM) ++counts->direct_uniform;
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
    const GdiSample variation = sample_client_gdi(hwnd);
    DestroyWindow(hwnd);
    if (!responsive || variation.surface != Surface::NONUNIFORM ||
        variation.direct_pixel != Surface::NONUNIFORM ||
        variation.failure != FailureStage::NONE) {
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
    std::printf("SWCOMPAT_SW_UI_OWNED_WINDOWS=%d\n", counts.owned_visible);
    std::printf("SWCOMPAT_SW_UI_VISIBLE_LARGE_WINDOWS=%d\n", counts.visible_large);
    std::printf("SWCOMPAT_SW_UI_RESPONSIVENESS=%s\n", response);
    const char *direct = counts.candidate_visible == 0 ? "NO_CANDIDATE"
        : counts.direct_nonuniform > 0 ? "NONUNIFORM"
        : counts.direct_uniform > 0 ? "UNIFORM" : "READBACK_FAILED";
    const char *stage = counts.candidate_visible == 0 ? "NO_CANDIDATE"
        : counts.failed_readback > 0 ? failure_name(counts.first_failure) : "NONE";
    std::printf("SWCOMPAT_SW_UI_GDI_CLIENT=%s\n", surface);
    std::printf("SWCOMPAT_SW_UI_GDI_FAILURE_STAGE=%s\n", stage);
    std::printf("SWCOMPAT_SW_UI_DIRECT_GETPIXEL=%s\n", direct);
    const char *child_surface = counts.child_visible == 0 ? "NO_CHILD"
        : counts.child_gdi_nonuniform > 0 ? "NONUNIFORM"
        : counts.child_gdi_uniform > 0 ? "UNIFORM" : "READBACK_FAILED";
    std::printf("SWCOMPAT_SW_UI_PARENT_LAYERED=%d\n", counts.parent_layered);
    std::printf("SWCOMPAT_SW_UI_PARENT_NO_REDIRECTION=%d\n", counts.parent_no_redirection);
    std::printf("SWCOMPAT_SW_UI_CHILD_VISIBLE=%d\n", counts.child_visible);
    std::printf("SWCOMPAT_SW_UI_CHILD_LAYERED=%d\n", counts.child_layered);
    std::printf("SWCOMPAT_SW_UI_CHILD_NO_REDIRECTION=%d\n", counts.child_no_redirection);
    std::printf("SWCOMPAT_SW_UI_CHILD_GDI=%s\n", child_surface);
    puts("SWCOMPAT_SW_UI_PROBE=COMPLETE");
    return 0;
}
