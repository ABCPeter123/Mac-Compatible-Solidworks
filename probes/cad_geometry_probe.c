/* Independent Windows x64 WGL geometry/depth-buffer validation.
 * Renders two overlapping triangles at different depths, then checks the
 * actual pixels. The nearer triangle must occlude the farther one.
 * No SOLIDWORKS libraries or proprietary APIs are required.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <GL/gl.h>
#include <stdio.h>
#include <stdlib.h>

static int failure(const char *stage) {
    printf("SWCOMPAT_CAD_GEOMETRY_STAGE=%s\n", stage);
    printf("SWCOMPAT_CAD_GEOMETRY_WINERR=%lu\n", GetLastError());
    printf("SWCOMPAT_CAD_GEOMETRY=FAIL\nSWCOMPAT_WGL=FAIL\n");
    fflush(stdout);
    return 1;
}

static int rgb_near(const unsigned char *rgb, int r, int g, int b, int tolerance) {
    return abs((int)rgb[0] - r) <= tolerance &&
           abs((int)rgb[1] - g) <= tolerance &&
           abs((int)rgb[2] - b) <= tolerance;
}

int main(void) {
    WNDCLASSW cls = {0};
    cls.style = CS_OWNDC;
    cls.lpfnWndProc = DefWindowProcW;
    cls.hInstance = GetModuleHandleW(NULL);
    cls.lpszClassName = L"SWCompatCADGeometry";
    if (!RegisterClassW(&cls)) return failure("RegisterClassW");

    HWND window = CreateWindowExW(0, cls.lpszClassName, L"SWCompat CAD Geometry",
                    WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT,
                    256, 256, NULL, NULL, cls.hInstance, NULL);
    if (!window) return failure("CreateWindowExW");
    HDC dc = GetDC(window);
    if (!dc) return failure("GetDC");

    PIXELFORMATDESCRIPTOR pfd = {0};
    pfd.nSize = sizeof(pfd);
    pfd.nVersion = 1;
    pfd.dwFlags = PFD_DRAW_TO_WINDOW | PFD_SUPPORT_OPENGL | PFD_DOUBLEBUFFER;
    pfd.iPixelType = PFD_TYPE_RGBA;
    pfd.cColorBits = 24;
    pfd.cDepthBits = 24;
    pfd.iLayerType = PFD_MAIN_PLANE;
    int format = ChoosePixelFormat(dc, &pfd);
    if (!format) return failure("ChoosePixelFormat");
    if (!SetPixelFormat(dc, format, &pfd)) return failure("SetPixelFormat");
    printf("SWCOMPAT_GEOMETRY_PIXEL_FORMAT=%d\n", format);

    HGLRC context = wglCreateContext(dc);
    if (!context) return failure("wglCreateContext");
    if (!wglMakeCurrent(dc, context)) return failure("wglMakeCurrent");

    const GLubyte *renderer = glGetString(GL_RENDERER);
    const GLubyte *version = glGetString(GL_VERSION);
    printf("SWCOMPAT_GEOMETRY_RENDERER=%s\n", renderer ? (const char*)renderer : "unknown");
    printf("SWCOMPAT_GEOMETRY_VERSION=%s\n", version ? (const char*)version : "unknown");

    glViewport(0, 0, 256, 256);
    glMatrixMode(GL_PROJECTION);
    glLoadIdentity();
    glOrtho(-1, 1, -1, 1, -1, 1);
    glMatrixMode(GL_MODELVIEW);
    glLoadIdentity();
    glEnable(GL_DEPTH_TEST);
    glDepthFunc(GL_LESS);
    glClearDepth(1.0);
    glClearColor(0.08f, 0.10f, 0.16f, 1.0f);
    glClear(GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT);

    /* Draw far green triangle first. */
    glColor3f(0.1f, 0.85f, 0.15f);
    glBegin(GL_TRIANGLES);
    glVertex3f(-0.75f, -0.75f, 0.5f);
    glVertex3f( 0.75f, -0.75f, 0.5f);
    glVertex3f( 0.0f,   0.75f, 0.5f);
    glEnd();

    /* Draw near red triangle; its center must occlude the green triangle. */
    glColor3f(0.92f, 0.15f, 0.15f);
    glBegin(GL_TRIANGLES);
    glVertex3f(-0.80f, -0.80f, -0.5f);
    glVertex3f( 0.80f, -0.80f, -0.5f);
    glVertex3f( 0.0f,   0.80f, -0.5f);
    glEnd();
    glFinish();

    GLboolean double_buffered = GL_FALSE;
    glGetBooleanv(GL_DOUBLEBUFFER, &double_buffered);
    glReadBuffer(double_buffered ? GL_BACK : GL_FRONT);
    unsigned char center[4] = {0};
    unsigned char outside[4] = {0};
    glReadPixels(128, 128, 1, 1, GL_RGBA, GL_UNSIGNED_BYTE, center);
    glReadPixels(8, 8, 1, 1, GL_RGBA, GL_UNSIGNED_BYTE, outside);
    GLenum err = glGetError();
    printf("SWCOMPAT_GEOMETRY_CENTER_RGBA=%u,%u,%u,%u\n",
           center[0], center[1], center[2], center[3]);
    printf("SWCOMPAT_GEOMETRY_OUTSIDE_RGBA=%u,%u,%u,%u\n",
           outside[0], outside[1], outside[2], outside[3]);
    printf("SWCOMPAT_GEOMETRY_GL_ERROR=%u\n", (unsigned)err);
    fflush(stdout);

    if (err != GL_NO_ERROR || !rgb_near(center, 235, 38, 38, 8) ||
        !rgb_near(outside, 20, 26, 41, 8)) return failure("DepthOrPixelMismatch");
    if (!SwapBuffers(dc)) return failure("SwapBuffers");

    printf("SWCOMPAT_CAD_GEOMETRY=PASS\nSWCOMPAT_WGL=PASS\n");
    fflush(stdout);
    wglMakeCurrent(NULL, NULL);
    wglDeleteContext(context);
    ReleaseDC(window, dc);
    DestroyWindow(window);
    UnregisterClassW(cls.lpszClassName, cls.hInstance);
    return 0;
}
