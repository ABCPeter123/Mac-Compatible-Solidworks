# Functional COM registration and activation

This diagnostic tests classic Windows **in-process COM server** behavior with an original, harmless DLL and separate Windows client executable.

## What it exercises

1. The COM server exports `DllGetClassObject`, `DllCanUnloadNow`, `DllRegisterServer` and `DllUnregisterServer`.
2. Registration stores a test CLSID under the **current user's** `Software\\Classes\\CLSID` tree, pointing at the self-authored DLL. This requires no administrator privileges.
3. A separate process calls `CoCreateInstance` to activate the object, obtains `IUnknown`, performs `QueryInterface`, and releases the COM reference.
4. The registration is removed, and a fresh process verifies `REGDB_E_CLASSNOTREG`.
5. A Python harness attempts cleanup after failed activation and emits structured results.

This is stronger than the earlier probe's successful `CoInitializeEx` call or ShellLink activation. It verifies the ability to register a new COM class and activate it across processes using a DLL in the Wine prefix.

## Where the test runs

The [COM lifecycle workflow](../.github/workflows/com-lifecycle-ci.yml) builds the Windows x64 DLL and executable with MinGW-w64, then runs the identical binaries under:

- Native Windows Server 2025, as a Win32 API reference.
- Wine on Ubuntu Linux.
- Wine 11.21 on Apple Silicon macOS 15.

Each Wine run uses a disposable prefix. Results are kept as JSON CI artifacts.

## Limits

A passing COM lifecycle test **does not** establish compatibility with SOLIDWORKS, which uses many other COM interfaces, threading models, registration styles, add-ins and automation objects. Nor does it demonstrate that a licensed installation works. Our test uses no proprietary SOLIDWORKS files, Windows installation media, or activation data.

A physical Mac and legitimately licensed SOLIDWORKS installer are still required before an end-to-end CAD claim can be made.
