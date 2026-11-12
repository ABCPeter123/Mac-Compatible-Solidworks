# Win32 event-driven WGL GUI session probe

The standalone Windows x64 executable in probes/win_gui_session_probe.c tests a small but relevant part of a CAD application's desktop runtime. It is authored for this repository. It contains no SOLIDWORKS executable, DLL, installer, add-in, serial or license component.

## What this verifies

1. Create a real Win32 top-level window and a child push button.
2. Show the window, resize it, and dispatch WM_PAINT and WM_SIZE through a normal Windows message pump.
3. Render a red triangle into a WGL framebuffer and verify its pixels.
4. Post synthetic WM_MOUSEMOVE, WM_LBUTTONDOWN and WM_MOUSEWHEEL messages. Click the child button using BM_CLICK, and check the expected callback states.
5. Redraw the same framebuffer with a green triangle after selection changes, verifying the new color with glReadPixels.
6. Save simulated user-interface state with Win32 CreateFileW/WriteFile, reopen with ReadFile, verify exact contents and delete the temporary file.
7. Deliver WM_CLOSE through the event queue, destroy the window and clean up the WGL context.

The program returns nonzero on any failing check and emits SWCOMPAT_GUI_SMOKE=PASS only if every stage passes. It also emits SWCOMPAT_WGL=PASS to fit the existing isolated WGL probe harness. File paths and temporary contents are not printed.

**Synthetic posted messages do not prove that physical mouse movement, keyboard input, OS window focus or external GUI automation works on a Mac.** A passing triangle redraw does not establish a SOLIDWORKS CAD viewport, sketch tools, GPU acceleration or full interactive performance. Save/reopen only covers this test program's state bytes, not a SLDPRT file.

## Reproduce on a configured host

Compile the executable with the existing build command:

~~~sh
sh scripts/build-wgl-probe.sh
~~~

Using a disposable Wine prefix that already has the project-tested Windows x64 Mesa software renderer staged:

~~~sh
export WINEDLLOVERRIDES="opengl32,libgallium_wgl,libglapi=n,b"
export GALLIUM_DRIVER=llvmpipe
export MESA_LOADER_DRIVER_OVERRIDE=llvmpipe
export LIBGL_ALWAYS_SOFTWARE=1

python3 -m swcompat --prefix "/path/to/test-prefix" \
  --logs-dir build/logs probe-wgl \
  --exe build/win_gui_session_probe.exe
~~~

On Linux Wine CI, this command runs under xvfb-run. On Apple Silicon CI, the same original x64 executable runs under checksum-pinned Wine 11.21 and Mesa 25.1.9. Both use the existing [software OpenGL workflow](../.github/workflows/wine-software-opengl.yml) rather than a separate GPU configuration.

Look for the markers:

- SWCOMPAT_GUI_INITIAL_FRAME=PASS
- SWCOMPAT_GUI_EVENT_LOOP=PASS
- SWCOMPAT_GUI_UPDATED_FRAME=PASS
- SWCOMPAT_GUI_FILE_ROUNDTRIP=PASS
- SWCOMPAT_GUI_CLOSE=PASS
- SWCOMPAT_GUI_SMOKE=PASS

These markers are produced after the program validates the relevant Win32 and OpenGL operations. If a test fails, SWCOMPAT_GUI_STAGE identifies the failing stage without exporting a private path.

## Next gate

The original SOLIDWORKS 2026 installer and running SOLIDWORKS UI remain untested. Follow up with authorized installer execution and captured, sanitized failure evidence. The next real CAD usability acceptance remains sketch creation, extrusion, rotation, saving a part, and reopening it under the licensed Windows application.
