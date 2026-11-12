/* Native macOS CGL probe for isolating host OpenGL capabilities from Wine.
   This uses Apple's OpenGL framework only. No SOLIDWORKS dependencies. */
#include <OpenGL/OpenGL.h>
#include <OpenGL/gl.h>
#include <stdio.h>

static int attempt(const char *name, const CGLPixelFormatAttribute *attributes) {
    CGLPixelFormatObj format = NULL;
    GLint formats = 0;
    CGLError err = CGLChoosePixelFormat(attributes, &format, &formats);
    printf("SWCOMPAT_CGL_%s_ERROR=%d\n", name, (int)err);
    printf("SWCOMPAT_CGL_%s_COUNT=%d\n", name, (int)formats);
    if (err != kCGLNoError || format == NULL || formats == 0) {
        if (format) CGLReleasePixelFormat(format);
        return 0;
    }
    CGLContextObj context = NULL;
    err = CGLCreateContext(format, NULL, &context);
    printf("SWCOMPAT_CGL_%s_CONTEXT_ERROR=%d\n", name, (int)err);
    CGLReleasePixelFormat(format);
    if (err != kCGLNoError || context == NULL) {
        if (context) CGLReleaseContext(context);
        return 0;
    }
    err = CGLSetCurrentContext(context);
    printf("SWCOMPAT_CGL_%s_CURRENT_ERROR=%d\n", name, (int)err);
    if (err == kCGLNoError) {
        const GLubyte *renderer = glGetString(GL_RENDERER);
        const GLubyte *version = glGetString(GL_VERSION);
        printf("SWCOMPAT_CGL_RENDERER=%s\n", renderer ? (const char *)renderer : "unavailable");
        printf("SWCOMPAT_CGL_VERSION=%s\n", version ? (const char *)version : "unavailable");
    }
    CGLSetCurrentContext(NULL);
    CGLReleaseContext(context);
    return err == kCGLNoError;
}

int main(void) {
    const CGLPixelFormatAttribute onscreen[] = {kCGLPFADoubleBuffer, (CGLPixelFormatAttribute)0};
    const CGLPixelFormatAttribute minimal[] = {kCGLPFAColorSize, (CGLPixelFormatAttribute)24, (CGLPixelFormatAttribute)0};
    const CGLPixelFormatAttribute offline[] = {kCGLPFAAllowOfflineRenderers, (CGLPixelFormatAttribute)0};
    const int found = attempt("DOUBLEBUFFER", onscreen) ||
                      attempt("MINIMAL", minimal) ||
                      attempt("OFFLINE", offline);
    printf("SWCOMPAT_CGL=%s\n", found ? "PASS" : "UNAVAILABLE");
    return found ? 0 : 3;
}
