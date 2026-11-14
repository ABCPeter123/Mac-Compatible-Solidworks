# Post-install experiment: integrated 3D Win32 CAD-style session

This experiment exercises a much more demanding later-stage Windows application workflow **before** genuine Microsoft .NET Framework and SOLIDWORKS have been successfully installed on Apple Silicon Wine. It does not use vendor binaries, native SOLIDWORKS automation or proprietary CAD file formats.

## What the independent executable tests

The self-authored Windows x64 program [live_cad_viewport.c](../probes/live_cad_viewport.c) creates a genuine Win32 top-level window, push buttons, message loop and WGL OpenGL context. It draws a depth-tested 3D front surface with a farther blue surface **after** the front surface. The test requires the nearer surface to remain visible, checking actual framebuffer pixels with glReadPixels, rather than trusting GL function return codes.

The program then exercises and verifies changes in a single live application session:

1. **Initial geometry:** 10 mm wide, 20 mm high, 30 mm deep synthetic shape. Check red front pixels and the background at a point outside the initial width.
2. **Selection:** Deliver a synthetic mouse click, check the Win32 event counters and child selection button, then verify the selected front pixels change to green.
3. **Extrusion-like edit:** Click a Win32 child button. Widen the model from 10 to 12 mm and add a synthetic second feature. Verify that a previously background pixel is now covered by the geometry.
4. **Zoom:** Deliver a synthetic mouse wheel event, change zoom from 1 to 2, and verify a farther-away pixel is now covered.
5. **Rotation:** Deliver a synthetic keyboard event, rotate the 3D vertices 15 degrees around Y, and verify the depth-tested redraw **and a changed silhouette pixel** that was previously covered by the model.
6. **Persistence:** Save a versioned original synthetic model to a fixed temporary Win32 file with WriteFile and FlushFileBuffers. Reopen and compare exact structured contents in the current process.
7. **Independent reopen:** End the GUI process, launch the same original Windows executable in a second process, read the same file independently and verify exact data. The host also checks every expected byte before deleting the temporary file.

The exact binary document representation is **self-authored** and is not a native SOLIDWORKS SLDPRT, SLDASM or SLDDRW file. The earlier [OLE compound-document experiment](CAD_POSTINSTALL_PARALLEL.md) separately tests genuine Windows COM structured storage.

[Automated CI](../.github/workflows/live-cad-3d-session-ci.yml) compiles the original Windows executable with MSVC and checks the binary model reader on native Windows. It also executes the full 3D session on Linux Wine and hosted Apple Silicon Wine with checksum-pinned Mesa 25.1.9, Wine 11.21 and CPU llvmpipe OpenGL.

The private diagnostic emits only fixed test status markers, not raw Win32/Wine output or personal paths. The experiment refuses an unmarked Wine prefix or a preexisting model path. All test artifacts are short-lived.

## What it does not establish

The input events are posted/sent synthetically inside Windows, not physical mouse or keyboard integration with macOS. The rendered pixels are independently verified inside the OpenGL framebuffer, not in a screenshot of a physical Mac display. The GPU is CPU-emulated and not representative of actual SOLIDWORKS CAD performance. Saving a self-authored model is not evidence of SOLIDWORKS document serialization or feature-tree regeneration.

Genuine SOLIDWORKS installation, native Windows .NET Framework 4.8.1, activation, assembly/drawing operations, real CAD file support, end-to-end UI composition and usability remain unverified. No compatibility success flag is set from a synthetic pass.
