# Microsoft Visual C++ dynamic runtime smoke test

The goal is to test native Windows C++ runtime behavior on Apple Silicon without relying on Visual C++ registry keys alone. SOLIDWORKS 2026 lists both 32-bit and 64-bit Visual C++ Redistributables as prerequisites.

## Build

The [workflow](../.github/workflows/msvc-runtime-ci.yml) compiles the independent original C++17 source `probes/msvc_runtime_smoke.cpp` with **Microsoft Visual C++ (MSVC 2022)** from the hosted Windows runner:

- Native Windows x64 build using `/MD`, linking dynamic runtime DLLs.
- Native Windows x86 build using `/MD`, for WoW64 compatibility testing.
- `dumpbin /dependents` must confirm dynamic imports from `MSVCP140.dll` and `VCRUNTIME140.dll`.

The executable tests actual C++ standard-library and C-runtime functionality, not merely a successful `LoadLibrary` call:

- `std::vector`, `std::sort`, and `std::accumulate`.
- `std::async` and `std::future`, including threaded execution.
- `std::ostringstream`, string formatting and comparisons.
- C++17 `std::filesystem` temporary path selection, file write and read.
- C++ exception reporting and clean exit, with markers for each subsystem.

## Execution environments

The identical Windows executables are tested on:

1. Native Windows Server 2025, as a Win32 API baseline.
2. Wine 11.21 running on hosted Apple Silicon macOS 15, in a disposable 64-bit prefix.

The Python harness `scripts/msvc_runtime_check.py` validates both executable exit status and exact success markers, including actual process architecture. Each CI run stores separate x86 and x64 JSON reports.

## Interpretation

A successful test demonstrates this particular MSVC-built executable works. It does **not** prove that the official VC++ 2022 x86/x64 redistributables are installed, nor that Wine implements every Microsoft C++ runtime feature that SOLIDWORKS uses. Wine may provide its own implementations of compatible DLLs.

The test uses no SOLIDWORKS binaries, activation keys or other proprietary program files. A real, legally licensed SOLIDWORKS installation remains necessary for application-level validation.
