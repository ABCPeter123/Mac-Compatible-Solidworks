/* Original Windows x64 WebView2 environment and controller compatibility probe.
 *
 * Uses only Microsoft's published WebView2 C++ SDK interfaces and its genuine
 * WebView2Loader.dll. No SOLIDWORKS files, license code, browser binaries,
 * or copied implementation code. Win32 STA callbacks are pumped on this thread.
 * Do not confuse a completed diagnostic with successful controller creation.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <objbase.h>
#include <wrl.h>
#include <WebView2.h>
#include <cstdio>
#include <string>

using Microsoft::WRL::Callback;
using Microsoft::WRL::ComPtr;

using QueryVersion = HRESULT(STDAPICALLTYPE *)(PCWSTR, LPWSTR *);
using CreateEnvironment = HRESULT(STDAPICALLTYPE *)(
    PCWSTR, PCWSTR, ICoreWebView2EnvironmentOptions *,
    ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler *);

struct Probe {
    bool env_callback = false;
    bool controller_callback = false;
    HRESULT env_hr = E_UNEXPECTED;
    HRESULT controller_hr = E_UNEXPECTED;
    const char *environment_status = "NOT_REACHED";
    const char *controller_status = "NOT_REACHED";
    ComPtr<ICoreWebView2Environment> env;
    ComPtr<ICoreWebView2Controller> controller;
    ComPtr<ICoreWebView2> webview;
};

static LRESULT CALLBACK window_proc(HWND hwnd, UINT message, WPARAM wparam, LPARAM lparam) {
    if (message == WM_CLOSE) {
        DestroyWindow(hwnd);
        return 0;
    }
    if (message == WM_DESTROY) {
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hwnd, message, wparam, lparam);
}

static bool pump_until(const bool &completed, DWORD timeout_ms) {
    DWORD begin = GetTickCount();
    while (!completed && GetTickCount() - begin < timeout_ms) {
        MSG message = {};
        while (PeekMessageW(&message, nullptr, 0, 0, PM_REMOVE)) {
            if (message.message == WM_QUIT) return false;
            TranslateMessage(&message);
            DispatchMessageW(&message);
        }
        Sleep(10);
    }
    return completed;
}

static void print_hresult(const char *name, HRESULT code) {
    std::printf("SWCOMPAT_WV2_%s_HRESULT=0x%08lX\n",
                name, static_cast<unsigned long>(static_cast<DWORD>(code)));
}

static int failed(const char *stage) {
    std::printf("SWCOMPAT_WV2_STAGE=%s\nSWCOMPAT_WV2_PROBE=FAIL\n", stage);
    std::fflush(stdout);
    return 1;
}

int main() {
    HMODULE dll = LoadLibraryW(L"WebView2Loader.dll");
    if (!dll) return failed("LOADER_MISSING");
    auto query = reinterpret_cast<QueryVersion>(
        GetProcAddress(dll, "GetAvailableCoreWebView2BrowserVersionString"));
    auto create = reinterpret_cast<CreateEnvironment>(
        GetProcAddress(dll, "CreateCoreWebView2EnvironmentWithOptions"));
    if (!query || !create) {
        FreeLibrary(dll);
        return failed("SDK_EXPORT_MISSING");
    }

    HRESULT com_hr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    if (FAILED(com_hr)) {
        FreeLibrary(dll);
        return failed("COM_INITIALIZATION");
    }

    WNDCLASSW wc = {};
    wc.hInstance = GetModuleHandleW(nullptr);
    wc.lpfnWndProc = window_proc;
    wc.lpszClassName = L"SWCompatWebView2Host";
    HWND window = nullptr;
    if (!RegisterClassW(&wc)) {
        CoUninitialize();
        FreeLibrary(dll);
        return failed("REGISTER_CLASS");
    }
    window = CreateWindowExW(0, wc.lpszClassName, L"SWCompat WebView2 probe",
                             WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT,
                             480, 360, nullptr, nullptr, wc.hInstance, nullptr);
    if (!window) {
        UnregisterClassW(wc.lpszClassName, wc.hInstance);
        CoUninitialize();
        FreeLibrary(dll);
        return failed("CREATE_WINDOW");
    }
    ShowWindow(window, SW_SHOWNORMAL);
    UpdateWindow(window);

    WCHAR temp[MAX_PATH + 1] = {};
    DWORD count = GetTempPathW(MAX_PATH, temp);
    if (count == 0 || count >= MAX_PATH) {
        DestroyWindow(window);
        UnregisterClassW(wc.lpszClassName, wc.hInstance);
        CoUninitialize();
        FreeLibrary(dll);
        return failed("TEMP_DIRECTORY");
    }
    std::wstring user_dir(temp);
    user_dir += L"swcompat-webview2-probe-";
    user_dir += std::to_wstring(GetCurrentProcessId());

    LPWSTR version = nullptr;
    HRESULT version_hr = query(nullptr, &version);
    bool discovered = SUCCEEDED(version_hr) && version && version[0] != L'\0';
    if (SUCCEEDED(version_hr) && !discovered) {
        if (version) CoTaskMemFree(version);
        DestroyWindow(window);
        UnregisterClassW(wc.lpszClassName, wc.hInstance);
        CoUninitialize();
        FreeLibrary(dll);
        return failed("VERSION_REPLY_INVALID");
    }
    if (version) CoTaskMemFree(version);

    Probe probe;
    auto env_cb = Callback<ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler>(
        [&probe](HRESULT result, ICoreWebView2Environment *environment) -> HRESULT {
            probe.env_callback = true;
            probe.env_hr = result;
            if (SUCCEEDED(result) && environment) {
                probe.env = environment;
            } else if (SUCCEEDED(result)) {
                probe.env_hr = E_POINTER;
            }
            return S_OK;
        });

    HRESULT request_hr = create(nullptr, user_dir.c_str(), nullptr, env_cb.Get());
    if (!probe.env_callback) probe.env_hr = request_hr;
    if (FAILED(request_hr)) {
        probe.environment_status = "REQUEST_FAILED";
    } else if (!pump_until(probe.env_callback, 25000)) {
        probe.environment_status = "TIMEOUT";
        probe.env_hr = HRESULT_FROM_WIN32(ERROR_TIMEOUT);
    } else if (FAILED(probe.env_hr) || !probe.env) {
        probe.environment_status = "CALLBACK_FAILED";
    } else {
        probe.environment_status = "READY";
        auto controller_cb = Callback<ICoreWebView2CreateCoreWebView2ControllerCompletedHandler>(
            [&probe](HRESULT result, ICoreWebView2Controller *controller) -> HRESULT {
                probe.controller_callback = true;
                probe.controller_hr = result;
                if (SUCCEEDED(result) && controller) {
                    probe.controller = controller;
                } else if (SUCCEEDED(result)) {
                    probe.controller_hr = E_POINTER;
                }
                return S_OK;
            });

        HRESULT controller_call = probe.env->CreateCoreWebView2Controller(
            window, controller_cb.Get());
        if (!probe.controller_callback) probe.controller_hr = controller_call;
        if (FAILED(controller_call)) {
            probe.controller_status = "REQUEST_FAILED";
        } else if (!pump_until(probe.controller_callback, 25000)) {
            probe.controller_status = "TIMEOUT";
            probe.controller_hr = HRESULT_FROM_WIN32(ERROR_TIMEOUT);
        } else if (FAILED(probe.controller_hr) || !probe.controller) {
            probe.controller_status = "CALLBACK_FAILED";
        } else {
            HRESULT view_hr = probe.controller->get_CoreWebView2(&probe.webview);
            RECT bounds = {0, 0, 320, 240};
            HRESULT bounds_hr = probe.controller->put_Bounds(bounds);
            HRESULT visible_hr = probe.controller->put_IsVisible(TRUE);
            if (FAILED(view_hr) || !probe.webview ||
                FAILED(bounds_hr) || FAILED(visible_hr)) {
                probe.controller_status = "INTERFACE_FAILED";
                probe.controller_hr = FAILED(view_hr) ? view_hr :
                                      FAILED(bounds_hr) ? bounds_hr :
                                      FAILED(visible_hr) ? visible_hr : E_POINTER;
            } else {
                probe.controller_status = "READY";
            }
        }
    }

    puts("SWCOMPAT_WV2_SCHEMA=1");
    puts("SWCOMPAT_WV2_WINDOW=PASS");
    std::printf("SWCOMPAT_WV2_RUNTIME=%s\n", discovered ? "VERSION_FOUND" : "NOT_DISCOVERED");
    print_hresult("RUNTIME", version_hr);
    std::printf("SWCOMPAT_WV2_ENVIRONMENT=%s\n", probe.environment_status);
    print_hresult("ENVIRONMENT", probe.env_hr);
    std::printf("SWCOMPAT_WV2_CONTROLLER=%s\n", probe.controller_status);
    if (std::string(probe.controller_status) != "NOT_REACHED") {
        print_hresult("CONTROLLER", probe.controller_hr);
    }
    puts("SWCOMPAT_WV2_PROBE=COMPLETE");
    std::fflush(stdout);

    probe.webview.Reset();
    probe.controller.Reset();
    probe.env.Reset();
    DestroyWindow(window);
    UnregisterClassW(wc.lpszClassName, wc.hInstance);
    CoUninitialize();
    FreeLibrary(dll);
    return 0;
}
