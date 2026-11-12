/* Windows x64 WGL/OpenGL test. Independent of SOLIDWORKS or proprietary SDKs. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <GL/gl.h>
#include <stdio.h>

static int failure(const char *step) {
    printf("SWCOMPAT_STAGE=%s\nSWCOMPAT_WINERR=%lu\nSWCOMPAT_WGL=FAIL\n", step, GetLastError());
    fflush(stdout);
    return 1;
}
int main(void) {
    HINSTANCE module = GetModuleHandleW(NULL);
    WNDCLASSW cls = {0};
    cls.style = CS_OWNDC;
    cls.lpfnWndProc = DefWindowProcW;
    cls.hInstance = module;
    cls.lpszClassName = L"SWCompatProbe";
    if (!RegisterClassW(&cls)) return failure("RegisterClassW");
    HWND hwnd = CreateWindowExW(0, cls.lpszClassName, L"SWCompat WGL", WS_OVERLAPPEDWINDOW,
                                CW_USEDEFAULT, CW_USEDEFAULT, 640, 480, NULL, NULL, module, NULL);
    if (!hwnd) return failure("CreateWindowExW");
    HDC dc = GetDC(hwnd);
    if (!dc) return failure("GetDC");
    printf("SWCOMPAT_WINDOW_VALID=%d\n", IsWindow(hwnd) ? 1 : 0);
    printf("SWCOMPAT_DISPLAY_BITS=%d\n", GetDeviceCaps(dc, BITSPIXEL));
    printf("SWCOMPAT_DISPLAY_PLANES=%d\n", GetDeviceCaps(dc, PLANES));
    PIXELFORMATDESCRIPTOR available = {0};
    SetLastError(0);
    int count = DescribePixelFormat(dc, 1, sizeof(available), &available);
    printf("SWCOMPAT_PIXELFORMAT_COUNT=%d\n", count);
    printf("SWCOMPAT_DESCRIBE_LASTERROR=%lu\n", GetLastError());
    int onscreen_opengl = 0;
    int bitmap_opengl = 0;
    for (int i = 1; i <= count && i <= 128; ++i) {
        PIXELFORMATDESCRIPTOR desc = {0};
        if (!DescribePixelFormat(dc, i, sizeof(desc), &desc)) {
            printf("SWCOMPAT_FORMAT_%d_DESCRIBE_FAILED=1\n", i);
            continue;
        }
        printf("SWCOMPAT_FORMAT_%d_FLAGS=0x%08lX\n", i, (unsigned long)desc.dwFlags);
        printf("SWCOMPAT_FORMAT_%d_COLOR=%u\n", i, desc.cColorBits);
        printf("SWCOMPAT_FORMAT_%d_DEPTH=%u\n", i, desc.cDepthBits);
        if (desc.dwFlags & PFD_SUPPORT_OPENGL) {
            if (desc.dwFlags & PFD_DRAW_TO_WINDOW) ++onscreen_opengl;
            if (desc.dwFlags & PFD_DRAW_TO_BITMAP) ++bitmap_opengl;
        }
    }
    printf("SWCOMPAT_ONSCREEN_OPENGL_FORMATS=%d\n", onscreen_opengl);
    printf("SWCOMPAT_BITMAP_OPENGL_FORMATS=%d\n", bitmap_opengl);

    /* Probe multiple requirements before concluding that the host has no
       compatible WGL format. ChoosePixelFormat does not modify the HDC. */
    struct candidate {
        const char *name;
        DWORD flags;
        BYTE color_bits;
        BYTE depth_bits;
    };
    const struct candidate candidates[] = {
        {"doublebuffer_24", PFD_DRAW_TO_WINDOW | PFD_SUPPORT_OPENGL | PFD_DOUBLEBUFFER, 24, 24},
        {"singlebuffer_24", PFD_DRAW_TO_WINDOW | PFD_SUPPORT_OPENGL, 24, 0},
        {"singlebuffer_auto", PFD_DRAW_TO_WINDOW | PFD_SUPPORT_OPENGL, 0, 0},
        {"doublebuffer_auto", PFD_DRAW_TO_WINDOW | PFD_SUPPORT_OPENGL | PFD_DOUBLEBUFFER, 0, 0},
        {"doublebuffer_dontcare", PFD_DRAW_TO_WINDOW | PFD_SUPPORT_OPENGL | PFD_DOUBLEBUFFER_DONTCARE, 0, 0},
    };
    PIXELFORMATDESCRIPTOR pfd = {0};
    int pf = 0;
    DWORD choose_error = 0;
    unsigned int selected = 0;
    for (unsigned int i = 0; i < sizeof(candidates) / sizeof(candidates[0]); i++) {
        pfd = (PIXELFORMATDESCRIPTOR){0};
        pfd.nSize = sizeof(pfd);
        pfd.nVersion = 1;
        pfd.dwFlags = candidates[i].flags;
        pfd.iPixelType = PFD_TYPE_RGBA;
        pfd.cColorBits = candidates[i].color_bits;
        pfd.cDepthBits = candidates[i].depth_bits;
        pfd.iLayerType = PFD_MAIN_PLANE;
        SetLastError(0);
        int selected_pf = ChoosePixelFormat(dc, &pfd);
        choose_error = GetLastError();
        printf("SWCOMPAT_CANDIDATE_%s=%d\n", candidates[i].name, selected_pf);
        printf("SWCOMPAT_CANDIDATE_%s_LASTERROR=%lu\n", candidates[i].name, choose_error);
        if (selected_pf) {
            pf = selected_pf;
            selected = i;
            break;
        }
    }
    printf("SWCOMPAT_PIXELFORMAT_CHOICE=%d\n", pf);
    printf("SWCOMPAT_CHOOSE_LASTERROR=%lu\n", choose_error);
    fflush(stdout);
    if (!pf) {
        SetLastError(choose_error);
        return failure("ChoosePixelFormat");
    }
    printf("SWCOMPAT_SELECTED_CANDIDATE=%s\n", candidates[selected].name);
    SetLastError(0);
    if (!SetPixelFormat(dc, pf, &pfd)) return failure("SetPixelFormat");
    printf("SWCOMPAT_PIXELFORMAT_SET=PASS\n");
    HGLRC gl = wglCreateContext(dc);
    if (!gl || !wglMakeCurrent(dc, gl)) return failure("wglCreateContext");
    const GLubyte *vendor = glGetString(GL_VENDOR);
    const GLubyte *renderer = glGetString(GL_RENDERER);
    const GLubyte *version = glGetString(GL_VERSION);
    printf("OPENGL_VENDOR=%s\nOPENGL_RENDERER=%s\nOPENGL_VERSION=%s\n",
           vendor ? (const char*)vendor : "unknown", renderer ? (const char*)renderer : "unknown",
           version ? (const char*)version : "unknown");
    glViewport(0, 0, 640, 480);
    glClearColor(0.1f, 0.2f, 0.3f, 1);
    glClear(GL_COLOR_BUFFER_BIT);
    SwapBuffers(dc);
    printf("SWCOMPAT_WGL=PASS\n");
    fflush(stdout);
    wglMakeCurrent(NULL, NULL);
    wglDeleteContext(gl);
    ReleaseDC(hwnd, dc);
    DestroyWindow(hwnd);
    UnregisterClassW(cls.lpszClassName, module);
    return 0;
}
