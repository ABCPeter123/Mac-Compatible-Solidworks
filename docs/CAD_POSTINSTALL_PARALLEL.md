# Parallel post-install compatibility research, before .NET and SOLIDWORKS are installed

The original SOLIDWORKS Installation Manager has been launched on Apple Silicon Wine, but **complete installation, licensed product activation, CAD startup, and native SLDPRT persistence have never been verified**. Genuine Microsoft .NET Framework remains blocked in its nested installer, with Windows error 1603 and a nonzero child exit.

We can still investigate independent operating-system services needed by interactive CAD software. These are **component tests**, never evidence that SOLIDWORKS itself runs.

## Existing later-stage surfaces

| Surface | Test | Important limitation |
| --- | --- | --- |
| 3D viewport and depth | probes/cad_geometry_probe.c | Software OpenGL, not production SOLIDWORKS rendering or GPU performance |
| Window, events, zoom and redraw | probes/win_gui_session_probe.c | Posted synthetic input, not verified physical Mac peripherals |
| COM activation | probes/com_inproc_server.c and probes/com_lifecycle_check.c | Independent test COM server, not SOLIDWORKS automation |
| Basic MSI install | probes/msi_transaction_probe.wxs | One synthetic payload, no native Microsoft .NET MSI custom actions |
| WebView2 execution | docs/WEBVIEW2_RENDERING.md | Browser window pixel presentation remains unverified |
| **Compound-document create/edit/save/reopen** | **probes/cad_ole_document.cpp** | Synthetic cuboid data in OLE structured storage, not a SOLIDWORKS part |

## Independent CAD-like save, edit and reopen

The [CAD OLE document workflow](../.github/workflows/cad-ole-document-ci.yml) builds a single original MSVC x64 Windows executable and requires three separate process invocations to work on native Windows:

1. **Create:** Initialize COM, create a real OLE Compound File Binary (CFB), write a synthetic 10×20×30 mm cuboid, then commit a nested storage and stream.
2. **Edit:** Start a second Win32 process, reopen and verify that document via StgOpenStorage, change the dimensions to 12×20×30 mm, record a second synthetic feature, then commit.
3. **Verify:** Start a third Win32 process, reopen the saved document and verify the edited model exactly. Confirm the CFB magic bytes from the host side and delete only the fixed disposable test document.

The same binary runs under Wine 11.21 on Apple Silicon in a newly initialized explicitly marked Wine prefix. Reports contain only finite stage statuses and a synthetic-document success boolean. No serial, activation data, proprietary installer or native SOLIDWORKS document is used.

This tests Windows COM/OLE storage and commits across **distinct Windows processes**, a useful post-install software capability. It does not reverse engineer, create, open or establish support for genuine .SLDPRT, .SLDASM or .SLDDRW files. We also do not assert that every SOLIDWORKS release uses these same storage calls internally.

A real end-to-end result still requires a legitimately installed SOLIDWORKS executable in a persistent local Wine prefix, verified startup, visible UI, licensed product operation, model creation, genuine file save/reopen and viewport redraw. Work on the Microsoft .NET installer can continue independently of these operating-system component tests.
