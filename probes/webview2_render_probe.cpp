/* Independent WebView2 rendering probe built with Microsoft's public Win32 SDK.
 *
 * Tests local, inline HTML and JavaScript with no external network navigation.
 * Captures the visible WebView into a PNG in the current working directory.
 * A separate, strict Python validator verifies PNG pixels, not merely file
 * existence. Never use this screenshot to capture user/application content.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <objbase.h>
#include <wrl.h>
#include <wincrypt.h>
#include <WebView2.h>
#include <cstdio>
#include <cwchar>
#include <string>
#include <vector>

using Microsoft::WRL::Callback;
using Microsoft::WRL::ComPtr;

using CreateEnvironment = HRESULT(STDAPICALLTYPE *)(
    PCWSTR, PCWSTR, ICoreWebView2EnvironmentOptions *,
    ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler *);

struct Result {
    bool environment_done = false;
    bool controller_done = false;
    bool navigation_done = false;
    bool script_done = false;
    bool preview_done = false;
    bool cdp_done = false;
    HRESULT environment_hr = E_UNEXPECTED;
    HRESULT controller_hr = E_UNEXPECTED;
    HRESULT navigation_hr = E_UNEXPECTED;
    HRESULT script_hr = E_UNEXPECTED;
    HRESULT preview_hr = E_UNEXPECTED;
    HRESULT cdp_hr = E_UNEXPECTED;
    std::wstring cdp_reply;
    bool dom_ok = false;
    ComPtr<ICoreWebView2Environment> environment;
    ComPtr<ICoreWebView2Controller> controller;
    ComPtr<ICoreWebView2> webview;
};

static LRESULT CALLBACK wndproc(HWND w, UINT msg, WPARAM wp, LPARAM lp) {
    if (msg == WM_CLOSE) { DestroyWindow(w); return 0; }
    if (msg == WM_DESTROY) { PostQuitMessage(0); return 0; }
    return DefWindowProcW(w, msg, wp, lp);
}

static void pump_once() {
    MSG msg = {};
    while (PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE)) {
        if (msg.message != WM_QUIT) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
}

static bool wait_for(const bool &done, DWORD timeout_ms) {
    DWORD started = GetTickCount();
    while (!done && GetTickCount() - started < timeout_ms) {
        pump_once();
        Sleep(10);
    }
    return done;
}

static void pump_for(DWORD duration_ms) {
    DWORD started = GetTickCount();
    while (GetTickCount() - started < duration_ms) {
        pump_once();
        Sleep(10);
    }
}

static int fail(const char *stage, HRESULT code) {
    std::printf("SWCOMPAT_WV2_RENDER_STAGE=%s\n", stage);
    std::printf("SWCOMPAT_WV2_RENDER_HRESULT=0x%08lX\n",
                static_cast<unsigned long>(static_cast<DWORD>(code)));
    puts("SWCOMPAT_WV2_RENDER_PROBE=FAIL");
    std::fflush(stdout);
    return 1;
}

static bool save_preview(IStream *stream) {
    STATSTG stat = {};
    if (FAILED(stream->Stat(&stat, STATFLAG_NONAME)) ||
        stat.cbSize.QuadPart < 64 || stat.cbSize.QuadPart > 16 * 1024 * 1024) {
        return false;
    }
    LARGE_INTEGER zero = {};
    if (FAILED(stream->Seek(zero, STREAM_SEEK_SET, nullptr))) return false;
    HANDLE file = CreateFileW(L"swcompat-webview2-preview.png", GENERIC_WRITE, 0,
                               nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;
    unsigned char buffer[65536];
    ULONGLONG remaining = static_cast<ULONGLONG>(stat.cbSize.QuadPart);
    bool good = true;
    while (remaining != 0) {
        ULONG request = remaining > sizeof(buffer) ? sizeof(buffer) :
                        static_cast<ULONG>(remaining);
        ULONG read = 0;
        if (FAILED(stream->Read(buffer, request, &read)) || read != request) {
            good = false;
            break;
        }
        DWORD written = 0;
        if (!WriteFile(file, buffer, read, &written, nullptr) || written != read) {
            good = false;
            break;
        }
        remaining -= read;
    }
    if (!CloseHandle(file)) good = false;
    if (!good) DeleteFileW(L"swcompat-webview2-preview.png");
    return good;
}

/* The Chromium DevTools protocol returns a JSON object containing base64 PNG.
 * Parse only its fixed "data" string, reject unexpectedly sized responses,
 * and decode using Windows Crypt32. This is not an external-browser download.
 */
static bool save_cdp_preview(const std::wstring &reply) {
    if (reply.size() > 24 * 1024 * 1024) return false;
    size_t at = reply.find(L"\"data\"");
    if (at == std::wstring::npos) return false;
    at = reply.find(L':', at + 6);
    if (at == std::wstring::npos) return false;
    ++at;
    while (at < reply.size() && (reply[at] == L' ' || reply[at] == L'\t')) ++at;
    if (at >= reply.size() || reply[at] != L'"') return false;
    size_t begin = ++at;
    while (at < reply.size() &&
           ((reply[at] >= L'A' && reply[at] <= L'Z') ||
            (reply[at] >= L'a' && reply[at] <= L'z') ||
            (reply[at] >= L'0' && reply[at] <= L'9') ||
            reply[at] == L'+' || reply[at] == L'/' || reply[at] == L'=')) {
        ++at;
    }
    if (at >= reply.size() || reply[at] != L'"' || at - begin < 64) return false;
    std::wstring encoded = reply.substr(begin, at - begin);
    DWORD size = 0;
    if (!CryptStringToBinaryW(encoded.c_str(), static_cast<DWORD>(encoded.size()),
                              CRYPT_STRING_BASE64, nullptr, &size, nullptr, nullptr) ||
        size < 64 || size > 16 * 1024 * 1024) return false;
    std::vector<BYTE> bytes(size);
    if (!CryptStringToBinaryW(encoded.c_str(), static_cast<DWORD>(encoded.size()),
                              CRYPT_STRING_BASE64, bytes.data(), &size, nullptr, nullptr)) return false;
    const unsigned char signature[] = {137, 80, 78, 71, 13, 10, 26, 10};
    if (size < sizeof(signature) ||
        memcmp(bytes.data(), signature, sizeof(signature)) != 0) return false;
    HANDLE out = CreateFileW(L"swcompat-webview2-preview.png", GENERIC_WRITE, 0,
                              nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (out == INVALID_HANDLE_VALUE) return false;
    DWORD written = 0;
    bool ok = WriteFile(out, bytes.data(), size, &written, nullptr) && written == size;
    if (!CloseHandle(out)) ok = false;
    if (!ok) DeleteFileW(L"swcompat-webview2-preview.png");
    return ok;
}

int main() {
    HMODULE dll = LoadLibraryW(L"WebView2Loader.dll");
    if (!dll) return fail("LOADER", HRESULT_FROM_WIN32(GetLastError()));
    auto create = reinterpret_cast<CreateEnvironment>(
        GetProcAddress(dll, "CreateCoreWebView2EnvironmentWithOptions"));
    if (!create) return fail("LOADER_EXPORT", HRESULT_FROM_WIN32(GetLastError()));
    HRESULT com = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    if (FAILED(com)) return fail("COM", com);

    WNDCLASSW klass = {};
    klass.lpfnWndProc = wndproc;
    klass.hInstance = GetModuleHandleW(nullptr);
    klass.lpszClassName = L"SWCompatWebView2InlineRender";
    if (!RegisterClassW(&klass)) return fail("WINDOW_CLASS", HRESULT_FROM_WIN32(GetLastError()));
    HWND window = CreateWindowExW(0, klass.lpszClassName, L"WebView2 local synthetic render",
                                  WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT,
                                  640, 480, nullptr, nullptr, klass.hInstance, nullptr);
    if (!window) return fail("WINDOW_CREATE", HRESULT_FROM_WIN32(GetLastError()));
    ShowWindow(window, SW_SHOWNORMAL);
    UpdateWindow(window);

    WCHAR temporary[MAX_PATH + 1] = {};
    DWORD count = GetTempPathW(MAX_PATH, temporary);
    if (count == 0 || count >= MAX_PATH) return fail("TEMP_DIRECTORY", E_FAIL);
    std::wstring profile(temporary);
    profile += L"swcompat-webview2-html-";
    profile += std::to_wstring(GetCurrentProcessId());

    Result result;
    auto environment_cb = Callback<ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler>(
        [&result](HRESULT code, ICoreWebView2Environment *env) -> HRESULT {
            result.environment_done = true;
            result.environment_hr = code;
            if (SUCCEEDED(code) && env) result.environment = env;
            else if (SUCCEEDED(code)) result.environment_hr = E_POINTER;
            return S_OK;
        });
    HRESULT request = create(nullptr, profile.c_str(), nullptr, environment_cb.Get());
    if (FAILED(request)) return fail("ENVIRONMENT_REQUEST", request);
    if (!wait_for(result.environment_done, 30000)) return fail("ENVIRONMENT_TIMEOUT", HRESULT_FROM_WIN32(ERROR_TIMEOUT));
    if (FAILED(result.environment_hr) || !result.environment)
        return fail("ENVIRONMENT_CALLBACK", result.environment_hr);

    auto controller_cb = Callback<ICoreWebView2CreateCoreWebView2ControllerCompletedHandler>(
        [&result](HRESULT code, ICoreWebView2Controller *controller) -> HRESULT {
            result.controller_done = true;
            result.controller_hr = code;
            if (SUCCEEDED(code) && controller) result.controller = controller;
            else if (SUCCEEDED(code)) result.controller_hr = E_POINTER;
            return S_OK;
        });
    request = result.environment->CreateCoreWebView2Controller(window, controller_cb.Get());
    if (FAILED(request)) return fail("CONTROLLER_REQUEST", request);
    if (!wait_for(result.controller_done, 30000)) return fail("CONTROLLER_TIMEOUT", HRESULT_FROM_WIN32(ERROR_TIMEOUT));
    if (FAILED(result.controller_hr) || !result.controller)
        return fail("CONTROLLER_CALLBACK", result.controller_hr);

    HRESULT hr = result.controller->get_CoreWebView2(&result.webview);
    if (FAILED(hr) || !result.webview) return fail("WEBVIEW_INTERFACE", FAILED(hr) ? hr : E_POINTER);
    RECT bounds = {0, 0, 480, 320};
    hr = result.controller->put_Bounds(bounds);
    if (FAILED(hr)) return fail("CONTROLLER_BOUNDS", hr);
    hr = result.controller->put_IsVisible(TRUE);
    if (FAILED(hr)) return fail("CONTROLLER_VISIBLE", hr);

    auto navigation_cb = Callback<ICoreWebView2NavigationCompletedEventHandler>(
        [&result](ICoreWebView2 *, ICoreWebView2NavigationCompletedEventArgs *args) -> HRESULT {
            BOOL success = FALSE;
            HRESULT code = args ? args->get_IsSuccess(&success) : E_POINTER;
            result.navigation_hr = FAILED(code) ? code : (success ? S_OK : E_FAIL);
            result.navigation_done = true;
            return S_OK;
        });
    EventRegistrationToken navigation_token = {};
    hr = result.webview->add_NavigationCompleted(navigation_cb.Get(), &navigation_token);
    if (FAILED(hr)) return fail("NAVIGATION_HANDLER", hr);
    const wchar_t *html =
        L"<!doctype html><html data-swcompat='ready'><head><meta charset='utf-8'>"
        L"<meta name='viewport' content='width=device-width, initial-scale=1'>"
        L"<style>html,body{margin:0;width:100%;height:100%;"
        L"background:rgb(19,83,147)}"
        L"#swcompat-marker{position:absolute;left:25%;top:25%;width:50%;height:50%;"
        L"background:rgb(29,205,91)}</style></head>"
        L"<body><div id='swcompat-marker'>render-test</div></body></html>";
    hr = result.webview->NavigateToString(html);
    if (FAILED(hr)) return fail("NAVIGATION_REQUEST", hr);
    if (!wait_for(result.navigation_done, 30000))
        return fail("NAVIGATION_TIMEOUT", HRESULT_FROM_WIN32(ERROR_TIMEOUT));
    if (FAILED(result.navigation_hr)) return fail("NAVIGATION_CALLBACK", result.navigation_hr);
    result.webview->remove_NavigationCompleted(navigation_token);

    auto script_cb = Callback<ICoreWebView2ExecuteScriptCompletedHandler>(
        [&result](HRESULT code, LPCWSTR json) -> HRESULT {
            result.script_hr = code;
            result.dom_ok = SUCCEEDED(code) && json &&
                            wcscmp(json, L"\"SWCOMPAT_DOM_OK\"") == 0;
            result.script_done = true;
            return S_OK;
        });
    const wchar_t *javascript =
        L"(() => { const e = document.getElementById('swcompat-marker');"
        L"return e && e.textContent === 'render-test' &&"
        L"document.documentElement.dataset.swcompat === 'ready' &&"
        L"getComputedStyle(e).backgroundColor === 'rgb(29, 205, 91)'"
        L" ? 'SWCOMPAT_DOM_OK' : 'SWCOMPAT_DOM_BAD'; })()";
    hr = result.webview->ExecuteScript(javascript, script_cb.Get());
    if (FAILED(hr)) return fail("SCRIPT_REQUEST", hr);
    if (!wait_for(result.script_done, 30000))
        return fail("SCRIPT_TIMEOUT", HRESULT_FROM_WIN32(ERROR_TIMEOUT));
    if (FAILED(result.script_hr) || !result.dom_ok)
        return fail("SCRIPT_DOM", FAILED(result.script_hr) ? result.script_hr : E_FAIL);

    // Allow the compositor and host event loop to paint the static synthetic page.
    pump_for(700);
    ComPtr<IStream> png;
    hr = CreateStreamOnHGlobal(nullptr, TRUE, &png);
    if (FAILED(hr) || !png) return fail("PREVIEW_STREAM", FAILED(hr) ? hr : E_POINTER);
    auto preview_cb = Callback<ICoreWebView2CapturePreviewCompletedHandler>(
        [&result](HRESULT code) -> HRESULT {
            result.preview_hr = code;
            result.preview_done = true;
            return S_OK;
        });
    const char *capture_status = "PASS";
    const char *method = "CAPTURE_PREVIEW";
    hr = result.webview->CapturePreview(
        COREWEBVIEW2_CAPTURE_PREVIEW_IMAGE_FORMAT_PNG, png.Get(), preview_cb.Get());
    bool native_capture_ok = false;
    if (FAILED(hr)) {
        capture_status = "REQUEST_FAILED";
    } else if (!wait_for(result.preview_done, 15000)) {
        capture_status = "TIMEOUT";
    } else if (FAILED(result.preview_hr)) {
        capture_status = "CALLBACK_FAILED";
    } else if (!save_preview(png.Get())) {
        capture_status = "WRITE_FAILED";
    } else {
        native_capture_ok = true;
    }

    if (!native_capture_ok) {
        method = "CDP_FALLBACK";
        auto cdp_cb = Callback<ICoreWebView2CallDevToolsProtocolMethodCompletedHandler>(
            [&result](HRESULT code, LPCWSTR reply) -> HRESULT {
                result.cdp_done = true;
                result.cdp_hr = code;
                if (SUCCEEDED(code) && reply) result.cdp_reply = reply;
                return S_OK;
            });
        hr = result.webview->CallDevToolsProtocolMethod(
            L"Page.captureScreenshot", L"{\"format\":\"png\",\"captureBeyondViewport\":false}",
            cdp_cb.Get());
        if (FAILED(hr)) return fail("CDP_REQUEST", hr);
        if (!wait_for(result.cdp_done, 30000))
            return fail("CDP_TIMEOUT", HRESULT_FROM_WIN32(ERROR_TIMEOUT));
        if (FAILED(result.cdp_hr)) return fail("CDP_CALLBACK", result.cdp_hr);
        if (!save_cdp_preview(result.cdp_reply)) return fail("CDP_DECODE", E_FAIL);
    }

    puts("SWCOMPAT_WV2_RENDER_SCHEMA=1");
    puts("SWCOMPAT_WV2_RENDER_ENVIRONMENT=READY");
    puts("SWCOMPAT_WV2_RENDER_CONTROLLER=READY");
    puts("SWCOMPAT_WV2_RENDER_NAVIGATION=PASS");
    puts("SWCOMPAT_WV2_RENDER_DOM=PASS");
    std::printf("SWCOMPAT_WV2_RENDER_CAPTURE_PREVIEW=%s\n", capture_status);
    std::printf("SWCOMPAT_WV2_RENDER_PREVIEW=%s\n", method);
    puts("SWCOMPAT_WV2_RENDER_PROBE=PASS");
    std::fflush(stdout);
    result.webview.Reset();
    result.controller.Reset();
    result.environment.Reset();
    png.Reset();
    DestroyWindow(window);
    UnregisterClassW(klass.lpszClassName, klass.hInstance);
    CoUninitialize();
    FreeLibrary(dll);
    return 0;
}
