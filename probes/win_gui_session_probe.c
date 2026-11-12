/* Independent Win32 + WGL GUI session probe. No SOLIDWORKS components.
 * Verifies a real HWND/message pump, synthetic input dispatch, responsive
 * WGL redraw, and a reversible Win32 file round-trip in an isolated prefix.
 * Posted events are NOT evidence of physical mouse or keyboard integration.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <GL/gl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SWC_BUTTON_ID 1001

typedef struct {
    int width, height;
    int paints, resizes, moves, clicks, wheels, commands, closes;
    int selected, zoom;
    int mouse_x, mouse_y;
} UiState;

static UiState ui;

static LRESULT CALLBACK window_proc(HWND hwnd, UINT message, WPARAM wp, LPARAM lp) {
    switch (message) {
    case WM_SIZE:
        ui.width = LOWORD(lp);
        ui.height = HIWORD(lp);
        ui.resizes++;
        return 0;
    case WM_PAINT: {
        PAINTSTRUCT paint;
        BeginPaint(hwnd, &paint);
        EndPaint(hwnd, &paint);
        ui.paints++;
        return 0;
    }
    case WM_MOUSEMOVE:
        ui.mouse_x = (short)LOWORD(lp);
        ui.mouse_y = (short)HIWORD(lp);
        ui.moves++;
        return 0;
    case WM_LBUTTONDOWN:
        ui.selected = 1;
        ui.clicks++;
        return 0;
    case WM_MOUSEWHEEL:
        if ((short)HIWORD(wp) > 0) ui.zoom++;
        ui.wheels++;
        return 0;
    case WM_COMMAND:
        if (LOWORD(wp) == SWC_BUTTON_ID && HIWORD(wp) == BN_CLICKED &&
            (HWND)lp == GetDlgItem(hwnd, SWC_BUTTON_ID)) {
            ui.commands++;
            return 0;
        }
        break;
    case WM_CLOSE:
        ui.closes++;
        DestroyWindow(hwnd);
        return 0;
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hwnd, message, wp, lp);
}

static void drain_messages(void) {
    MSG msg;
    while (PeekMessageW(&msg, NULL, 0, 0, PM_REMOVE)) {
        if (msg.message != WM_QUIT) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
}

static int received_input(void) {
    return ui.paints > 0 && ui.resizes > 0 &&
           ui.width >= 180 && ui.height >= 160 &&
           ui.moves > 0 && ui.clicks > 0 && ui.wheels > 0 &&
           ui.commands > 0 && ui.selected == 1 && ui.zoom == 1 &&
           ui.mouse_x == 39 && ui.mouse_y == 47;
}

static int pump_until(int (*condition)(void), DWORD timeout_ms) {
    DWORD start = GetTickCount();
    while ((DWORD)(GetTickCount() - start) < timeout_ms) {
        drain_messages();
        if (condition()) return 1;
        Sleep(10);
    }
    return 0;
}

static int is_closed(void) {
    return ui.closes == 1;
}

static int rgb_near(const unsigned char rgb[3], int r, int g, int b) {
    return abs((int)rgb[0] - r) <= 12 &&
           abs((int)rgb[1] - g) <= 12 &&
           abs((int)rgb[2] - b) <= 12;
}

static int render_frame(HDC dc, int selected) {
    if (ui.width < 1 || ui.height < 1) return 0;
    glViewport(0, 0, ui.width, ui.height);
    glMatrixMode(GL_PROJECTION);
    glLoadIdentity();
    glOrtho(-1, 1, -1, 1, -1, 1);
    glMatrixMode(GL_MODELVIEW);
    glLoadIdentity();
    glDisable(GL_DEPTH_TEST);
    glClearColor(0.06f, 0.08f, 0.12f, 1.0f);
    glClear(GL_COLOR_BUFFER_BIT);
    if (selected) glColor3f(0.12f, 0.82f, 0.12f);
    else glColor3f(0.82f, 0.12f, 0.12f);
    glBegin(GL_TRIANGLES);
    glVertex2f(-0.8f, -0.75f);
    glVertex2f(0.8f, -0.75f);
    glVertex2f(0.0f, 0.8f);
    glEnd();

    glFinish();
    GLboolean buffered = GL_FALSE;
    glGetBooleanv(GL_DOUBLEBUFFER, &buffered);
    glReadBuffer(buffered ? GL_BACK : GL_FRONT);
    glPixelStorei(GL_PACK_ALIGNMENT, 1);
    unsigned char center[3] = {0, 0, 0};
    glReadPixels(ui.width / 2, ui.height / 2, 1, 1, GL_RGB, GL_UNSIGNED_BYTE, center);
    GLenum gl_error = glGetError();
    printf("SWCOMPAT_GUI_PIXEL_%s=%u,%u,%u\n", selected ? "SELECTED" : "BASE",
           center[0], center[1], center[2]);
    fflush(stdout);
    if (gl_error != GL_NO_ERROR ||
        !(selected ? rgb_near(center, 31, 209, 31) : rgb_near(center, 209, 31, 31)))
        return 0;
    return SwapBuffers(dc) != 0;
}

static int file_roundtrip(void) {
    wchar_t directory[MAX_PATH + 1] = {0};
    wchar_t filename[MAX_PATH + 1] = {0};
    DWORD length = GetTempPathW(MAX_PATH, directory);
    if (!length || length >= MAX_PATH || !GetTempFileNameW(directory, L"swc", 0, filename))
        return 0;

    int ok = 0;
    char expected[128] = {0};
    char actual[128] = {0};
    int written = snprintf(expected, sizeof(expected), "selected=%d;zoom=%d;x=%d;y=%d",
                           ui.selected, ui.zoom, ui.mouse_x, ui.mouse_y);
    if (written < 0 || (size_t)written >= sizeof(expected)) goto finish;

    HANDLE file = CreateFileW(filename, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                              FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) goto finish;
    DWORD size = 0;
    BOOL saved = WriteFile(file, expected, (DWORD)written, &size, NULL);
    CloseHandle(file);
    if (!saved || size != (DWORD)written) goto finish;

    file = CreateFileW(filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                       FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) goto finish;
    DWORD read = 0;
    BOOL loaded = ReadFile(file, actual, sizeof(actual), &read, NULL);
    CloseHandle(file);
    if (!loaded || read != (DWORD)written ||
        memcmp(expected, actual, (size_t)written) != 0) goto finish;
    ok = 1;
finish:
    if (!DeleteFileW(filename)) return 0;
    if (GetFileAttributesW(filename) != INVALID_FILE_ATTRIBUTES) return 0;
    return ok;
}

int main(void) {
    HINSTANCE app = GetModuleHandleW(NULL);
    const wchar_t *class_name = L"SWCompatGuiSession";
    WNDCLASSW cls = {0};
    cls.style = CS_OWNDC | CS_HREDRAW | CS_VREDRAW;
    cls.lpfnWndProc = window_proc;
    cls.hInstance = app;
    cls.lpszClassName = class_name;

    HWND window = NULL;
    HDC dc = NULL;
    HGLRC context = NULL;
    const char *failed = NULL;

    if (!RegisterClassW(&cls)) {
        failed = "RegisterClassW";
        goto done;
    }
    window = CreateWindowExW(0, class_name, L"SWCompat Windows GUI session",
                             WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT,
                             360, 300, NULL, NULL, app, NULL);
    if (!window) {
        failed = "CreateWindowExW";
        goto done;
    }
    HWND button = CreateWindowExW(0, L"BUTTON", L"Change selection",
                                 WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                                 8, 8, 130, 28, window, (HMENU)(INT_PTR)SWC_BUTTON_ID,
                                 app, NULL);
    if (!button) {
        failed = "CreateWindowButton";
        goto done;
    }
    ShowWindow(window, SW_SHOWNORMAL);
    UpdateWindow(window);
    if (!SetWindowPos(window, NULL, 0, 0, 400, 330,
                      SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE)) {
        failed = "SetWindowPos";
        goto done;
    }
    drain_messages();
    dc = GetDC(window);
    if (!dc) {
        failed = "GetDC";
        goto done;
    }
    PIXELFORMATDESCRIPTOR pfd = {0};
    pfd.nSize = sizeof(pfd);
    pfd.nVersion = 1;
    pfd.dwFlags = PFD_DRAW_TO_WINDOW | PFD_SUPPORT_OPENGL | PFD_DOUBLEBUFFER;
    pfd.iPixelType = PFD_TYPE_RGBA;
    pfd.cColorBits = 24;
    pfd.iLayerType = PFD_MAIN_PLANE;
    int pf = ChoosePixelFormat(dc, &pfd);
    if (!pf || !SetPixelFormat(dc, pf, &pfd)) {
        failed = "WGLPixelFormat";
        goto done;
    }
    context = wglCreateContext(dc);
    if (!context || !wglMakeCurrent(dc, context)) {
        failed = "WGLCreateContext";
        goto done;
    }

    if (!render_frame(dc, 0)) {
        failed = "InitialFramebuffer";
        goto done;
    }
    printf("SWCOMPAT_GUI_INITIAL_FRAME=PASS\n");

    InvalidateRect(window, NULL, FALSE);
    UpdateWindow(window);
    if (!PostMessageW(window, WM_MOUSEMOVE, 0, MAKELPARAM(39, 47)) ||
        !PostMessageW(window, WM_LBUTTONDOWN, MK_LBUTTON, MAKELPARAM(39, 47)) ||
        !PostMessageW(window, WM_MOUSEWHEEL, MAKEWPARAM(0, WHEEL_DELTA), 0)) {
        failed = "PostSyntheticInput";
        goto done;
    }
    SendMessageW(button, BM_CLICK, 0, 0);
    if (!pump_until(received_input, 5000)) {
        failed = "MessageDispatch";
        goto done;
    }
    printf("SWCOMPAT_GUI_EVENT_LOOP=PASS\n");

    if (!render_frame(dc, 1)) {
        failed = "UpdatedFramebuffer";
        goto done;
    }
    printf("SWCOMPAT_GUI_UPDATED_FRAME=PASS\n");
    if (!file_roundtrip()) {
        failed = "FileSaveReopen";
        goto done;
    }
    printf("SWCOMPAT_GUI_FILE_ROUNDTRIP=PASS\n");

    if (!PostMessageW(window, WM_CLOSE, 0, 0) || !pump_until(is_closed, 5000)) {
        failed = "WindowClose";
        goto done;
    }
    printf("SWCOMPAT_GUI_CLOSE=PASS\n");
done:
    if (context) {
        wglMakeCurrent(NULL, NULL);
        wglDeleteContext(context);
    }
    if (dc && window && IsWindow(window)) ReleaseDC(window, dc);
    if (window && IsWindow(window)) DestroyWindow(window);
    UnregisterClassW(class_name, app);
    if (failed) {
        printf("SWCOMPAT_GUI_STAGE=%s\nSWCOMPAT_GUI_SMOKE=FAIL\nSWCOMPAT_WGL=FAIL\n", failed);
        fflush(stdout);
        return 1;
    }
    puts("SWCOMPAT_GUI_SMOKE=PASS\nSWCOMPAT_WGL=PASS");
    fflush(stdout);
    return 0;
}
