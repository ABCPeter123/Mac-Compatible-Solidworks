/* Tests Wine WGL's bitmap-only path without SOLIDWORKS or a visible window. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <GL/gl.h>
#include <stdio.h>

static int fail(const char *stage) {
    printf("SWCOMPAT_BITMAP_STAGE=%s\n", stage);
    printf("SWCOMPAT_BITMAP_WINERR=%lu\n", GetLastError());
    printf("SWCOMPAT_BITMAP_WGL=FAIL\n");
    fflush(stdout);
    return 1;
}

int main(void) {
    HDC dc = CreateCompatibleDC(NULL);
    if (!dc) return fail("CreateCompatibleDC");

    BITMAPINFO bmi = {0};
    bmi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    bmi.bmiHeader.biWidth = 64;
    bmi.bmiHeader.biHeight = -64;
    bmi.bmiHeader.biPlanes = 1;
    bmi.bmiHeader.biBitCount = 32;
    bmi.bmiHeader.biCompression = BI_RGB;
    void *bits = NULL;
    HBITMAP bitmap = CreateDIBSection(dc, &bmi, DIB_RGB_COLORS, &bits, NULL, 0);
    if (!bitmap || !bits) return fail("CreateDIBSection");
    HGDIOBJ old = SelectObject(dc, bitmap);
    if (!old || old == HGDI_ERROR) return fail("SelectObject");

    PIXELFORMATDESCRIPTOR desc = {0};
    int count = DescribePixelFormat(dc, 1, sizeof(desc), &desc);
    printf("SWCOMPAT_BITMAP_FORMAT_COUNT=%d\n", count);

    int pf = 0;
    for (int i = 1; i <= count && i <= 128; ++i) {
        PIXELFORMATDESCRIPTOR fmt = {0};
        if (!DescribePixelFormat(dc, i, sizeof(fmt), &fmt)) continue;
        if ((fmt.dwFlags & (PFD_DRAW_TO_BITMAP | PFD_SUPPORT_OPENGL)) ==
                          (PFD_DRAW_TO_BITMAP | PFD_SUPPORT_OPENGL)) {
            printf("SWCOMPAT_BITMAP_CANDIDATE=%d\n", i);
            pf = i;
            desc = fmt;
            break;
        }
    }
    printf("SWCOMPAT_BITMAP_SELECTED=%d\n", pf);
    fflush(stdout);
    if (!pf) return fail("NoBitmapPixelFormat");
    SetLastError(0);
    if (!SetPixelFormat(dc, pf, &desc)) return fail("SetPixelFormat");
    HGLRC context = wglCreateContext(dc);
    if (!context) return fail("wglCreateContext");
    if (!wglMakeCurrent(dc, context)) return fail("wglMakeCurrent");

    const GLubyte *version = glGetString(GL_VERSION);
    const GLubyte *renderer = glGetString(GL_RENDERER);
    printf("SWCOMPAT_BITMAP_OPENGL_VERSION=%s\n", version ? (const char *)version : "unavailable");
    printf("SWCOMPAT_BITMAP_OPENGL_RENDERER=%s\n", renderer ? (const char *)renderer : "unavailable");
    if (!version || !renderer) return fail("glGetString");

    glViewport(0, 0, 64, 64);
    glClearColor(0.5f, 0.25f, 0.125f, 1.0f);
    glClear(GL_COLOR_BUFFER_BIT);
    unsigned char pixel[4] = {0, 0, 0, 0};
    glReadPixels(32, 32, 1, 1, GL_RGBA, GL_UNSIGNED_BYTE, pixel);
    GLenum gl_error = glGetError();
    printf("SWCOMPAT_BITMAP_OPENGL_ERROR=%u\n", (unsigned int)gl_error);
    printf("SWCOMPAT_BITMAP_PIXEL=%u,%u,%u,%u\n",
           pixel[0], pixel[1], pixel[2], pixel[3]);
    printf("SWCOMPAT_BITMAP_WGL=%s\n", gl_error == GL_NO_ERROR ? "PASS" : "FAIL");
    fflush(stdout);
    wglMakeCurrent(NULL, NULL);
    wglDeleteContext(context);
    SelectObject(dc, old);
    DeleteObject(bitmap);
    DeleteDC(dc);
    return gl_error == GL_NO_ERROR ? 0 : 1;
}
