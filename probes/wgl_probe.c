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
    PIXELFORMATDESCRIPTOR pfd = {0};
    pfd.nSize = sizeof(pfd);
    pfd.nVersion = 1;
    pfd.dwFlags = PFD_DRAW_TO_WINDOW | PFD_SUPPORT_OPENGL | PFD_DOUBLEBUFFER;
    pfd.iPixelType = PFD_TYPE_RGBA;
    pfd.cColorBits = 24;
    pfd.cDepthBits = 24;
    pfd.iLayerType = PFD_MAIN_PLANE;
    int pf = ChoosePixelFormat(dc, &pfd);
    if (!pf || !SetPixelFormat(dc, pf, &pfd)) return failure("SetPixelFormat");
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
