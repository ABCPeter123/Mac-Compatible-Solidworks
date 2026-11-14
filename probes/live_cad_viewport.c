/* Independent CAD-style 3D Win32/WGL session, no proprietary SOLIDWORKS.
 * Drives selection, extrusion, rotation, zoom, depth-tested pixel readback,
 * and persists a synthetic model to verify in another Windows process.
 * Posted messages do not prove physical Mac keyboard/mouse operation.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <GL/gl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define SWC_BUTTON_ID 1001
#define SWC_EXTRUDE_ID 1002

typedef struct {
    int width, height;
    int paints, resizes, moves, clicks, wheels, commands, closes;
    int selected, zoom, width_mm, feature_count, yaw, rotations, extrusions;
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
    case WM_KEYDOWN:
        if (wp == 'R') { ui.yaw = 15; ui.rotations++; }
        return 0;
    case WM_MOUSEWHEEL:
        if ((short)HIWORD(wp) > 0) ui.zoom++;
        ui.wheels++;
        return 0;
    case WM_COMMAND:
        if (HIWORD(wp) == BN_CLICKED &&
            (HWND)lp == GetDlgItem(hwnd, LOWORD(wp))) {
            if (LOWORD(wp) == SWC_BUTTON_ID) { ui.commands++; return 0; }
            if (LOWORD(wp) == SWC_EXTRUDE_ID) {
                ui.width_mm = 12;
                ui.feature_count = 2;
                ui.extrusions++;
                return 0;
            }
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
           ui.commands > 0 && ui.selected == 1 && ui.zoom == 2 &&
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

static int render_frame(HDC dc, int phase) {
    if (ui.width < 230 || ui.height < 200) return 0;
    glViewport(0, 0, ui.width, ui.height);
    glMatrixMode(GL_PROJECTION);
    glLoadIdentity();
    glOrtho(-1, 1, -1, 1, 0, 2);
    glMatrixMode(GL_MODELVIEW);
    glLoadIdentity();
    glScalef((float)ui.zoom, (float)ui.zoom, 1.0f);
    glRotatef((float)ui.yaw, 0, 1, 0);
    glEnable(GL_DEPTH_TEST);
    glDepthFunc(GL_LESS);
    glClearDepth(1.0);
    glClearColor(20.0f/255.0f, 26.0f/255.0f, 41.0f/255.0f, 1.0f);
    glClear(GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT);
    float w = (float)ui.width_mm/40.0f;
    float h = 0.50f;
    glColor3f(ui.selected ? 30.0f/255.0f : 235.0f/255.0f,
              ui.selected ? 209.0f/255.0f : 38.0f/255.0f, 38.0f/255.0f);
    glBegin(GL_QUADS);
    glVertex3f(-w, -h, -0.4f);
    glVertex3f( w, -h, -0.4f);
    glVertex3f( w,  h, -0.4f);
    glVertex3f(-w,  h, -0.4f);
    glEnd();
    /* Draw the far face AFTER the front. Without a real depth test it wins. */
    glColor3f(0.15f, 0.25f, 0.95f);
    glBegin(GL_QUADS);
    glVertex3f(-w, -h, -1.3f);
    glVertex3f( w, -h, -1.3f);
    glVertex3f( w,  h, -1.3f);
    glVertex3f(-w,  h, -1.3f);
    glEnd();
    glFinish();
    GLint bits = 0;
    glGetIntegerv(GL_DEPTH_BITS, &bits);
    if (bits < 16) return 0;
    GLboolean buffered = GL_FALSE;
    glGetBooleanv(GL_DOUBLEBUFFER, &buffered);
    glReadBuffer(buffered ? GL_BACK : GL_FRONT);
    glPixelStorei(GL_PACK_ALIGNMENT, 1);
    unsigned char center[3] = {0}, edge[3] = {0};
    int edge_x = (int)((phase >= 3 ? 0.25 : 0.3625) * ui.width);
    glReadPixels(ui.width/2, ui.height/2, 1, 1, GL_RGB, GL_UNSIGNED_BYTE, center);
    glReadPixels(edge_x, ui.height/2, 1, 1, GL_RGB, GL_UNSIGNED_BYTE, edge);
    GLenum error = glGetError();
    int center_ok = rgb_near(center, ui.selected ? 30 : 235,
                            ui.selected ? 209 : 38, 38);
    int edge_ok = phase >= 2 ? rgb_near(edge, 30, 209, 38)
                             : rgb_near(edge, 20, 26, 41);
    return error == GL_NO_ERROR && center_ok && edge_ok && SwapBuffers(dc) != 0;
}

typedef struct {
    unsigned char magic[8];
    uint32_t schema, revision, width_mm, height_mm, depth_mm;
    uint32_t features, selected, zoom, yaw;
} SyntheticPart;

static int model_matches(const SyntheticPart *part) {
    static const unsigned char magic[8] = {'S','W','C','A','D','3','D','1'};
    return memcmp(part->magic, magic, 8) == 0 &&
        part->schema == 1 && part->revision == 2 &&
        part->width_mm == 12 && part->height_mm == 20 &&
        part->depth_mm == 30 && part->features == 2 &&
        part->selected == 1 && part->zoom == 2 && part->yaw == 15;
}
static int write_model(const char *path) {
    SyntheticPart part = {{'S','W','C','A','D','3','D','1'},
                          1,2,(uint32_t)ui.width_mm,20,30,
                          (uint32_t)ui.feature_count,(uint32_t)ui.selected,
                          (uint32_t)ui.zoom,(uint32_t)ui.yaw};
    if (!model_matches(&part)) return 0;
    HANDLE f = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_NEW,
                           FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE) return 0;
    DWORD count = 0;
    BOOL wrote = WriteFile(f, &part, sizeof(part), &count, NULL);
    BOOL flushed = FlushFileBuffers(f);
    CloseHandle(f);
    return wrote && flushed && count == sizeof(part);
}
static int verify_model(const char *path) {
    HANDLE f = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE) return 0;
    SyntheticPart part = {0};
    DWORD count = 0;
    BOOL read_ok = ReadFile(f, &part, sizeof(part), &count, NULL);
    DWORD size = GetFileSize(f, NULL);
    CloseHandle(f);
    return read_ok && count == sizeof(part) &&
           size == sizeof(part) && model_matches(&part);
}

int main(int argc, char **argv) {
    if (argc != 3) return 2;
    if (strcmp(argv[1], "verify") == 0) {
        int valid = verify_model(argv[2]);
        puts(valid ? "SWCOMPAT_LIVE_INDEPENDENT_REOPEN=PASS" :
                     "SWCOMPAT_LIVE_INDEPENDENT_REOPEN=FAIL");
        return valid ? 0 : 1;
    }
    if (strcmp(argv[1], "run") != 0) return 2;
    if (GetFileAttributesA(argv[2]) != INVALID_FILE_ATTRIBUTES) return 2;
    ui.zoom = 1;
    ui.width_mm = 10;
    ui.feature_count = 1;

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
    HWND extrude = CreateWindowExW(0, L"BUTTON", L"Extrude",
                                 WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                                 145, 8, 90, 28, window, (HMENU)(INT_PTR)SWC_EXTRUDE_ID,
                                 app, NULL);
    if (!button || !extrude) {
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
    printf("SWCOMPAT_LIVE_INITIAL_DEPTH=PASS\n");

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
    printf("SWCOMPAT_LIVE_EVENT_LOOP=PASS\n");

    if (!render_frame(dc, 1)) {
        failed = "UpdatedFramebuffer";
        goto done;
    }
    printf("SWCOMPAT_LIVE_SELECTED_REDRAW=PASS\n");
    SendMessageW(extrude, BM_CLICK, 0, 0);
    if (ui.extrusions != 1 || ui.width_mm != 12 || ui.feature_count != 2 ||
        !render_frame(dc, 2)) {
        failed = "ExtrudeAndFrame";
        goto done;
    }
    puts("SWCOMPAT_LIVE_EXTRUDE_REDRAW=PASS");
    if (!render_frame(dc, 3)) {
        failed = "ZoomAndFrame";
        goto done;
    }
    puts("SWCOMPAT_LIVE_ZOOM_REDRAW=PASS");
    if (!PostMessageW(window, WM_KEYDOWN, 'R', 0)) {
        failed = "RotationPost";
        goto done;
    }
    DWORD start = GetTickCount();
    while (ui.rotations < 1 && GetTickCount() - start < 5000) {
        drain_messages();
        Sleep(10);
    }
    if (ui.rotations != 1 || ui.yaw != 15 || !render_frame(dc, 3)) {
        failed = "RotationAndFrame";
        goto done;
    }
    puts("SWCOMPAT_LIVE_ROTATION_REDRAW=PASS");
    if (!write_model(argv[2]) || !verify_model(argv[2])) {
        failed = "FileSaveReopen";
        goto done;
    }
    puts("SWCOMPAT_LIVE_SAVE_REOPEN=PASS");

    if (!PostMessageW(window, WM_CLOSE, 0, 0) || !pump_until(is_closed, 5000)) {
        failed = "WindowClose";
        goto done;
    }
    printf("SWCOMPAT_LIVE_CLOSE=PASS\n");
done:
    if (context) {
        wglMakeCurrent(NULL, NULL);
        wglDeleteContext(context);
    }
    if (dc && window && IsWindow(window)) ReleaseDC(window, dc);
    if (window && IsWindow(window)) DestroyWindow(window);
    UnregisterClassW(class_name, app);
    if (failed) {
        printf("SWCOMPAT_LIVE_STAGE=%s\nSWCOMPAT_LIVE_RESULT=FAIL\n", failed);
        fflush(stdout);
        return 1;
    }
    puts("SWCOMPAT_LIVE_RESULT=PASS");
    fflush(stdout);
    return 0;
}
