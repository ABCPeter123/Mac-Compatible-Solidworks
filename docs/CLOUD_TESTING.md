# Testing without owning a Mac

The [Compatibility foundation](../.github/workflows/compatibility-ci.yml) workflow runs automatically on pushes and pull requests. You can also trigger its experimental Linux Wine smoke test using **Actions > Compatibility foundation > Run workflow**.

## What CI measures

| Job | Host | Result |
| --- | --- | --- |
| Python portability | Ubuntu, macOS 15 ARM64 and Intel | Validate launcher, diagnostics and error analysis |
| Native Mac diagnostics | macOS 15 ARM64 and Intel | Compile the Swift/Metal probe and publish host capability JSON |
| Cross-compile WGL | Ubuntu x64 | Build a real Windows x64 executable that uses WGL/OpenGL |
| Wine smoke (opt in) | Ubuntu x64 with Xvfb/Mesa | Exercise Win32 execution and WGL under Wine on Linux |

The ARM64 macOS runner is labeled `macos-15`; the Intel runner is `macos-15-intel`. GitHub-hosted runner images and capacities can change over time, so keep the labels under review.

CI artifacts are available from the workflow run page. **No SOLIDWORKS binaries, installer files, activation data, or license keys should be uploaded** to public Actions.

## Explicit limitations

The macOS CI jobs deliberately do not install Wine by default. They prove that the macOS-native development and reporting environment works, not that Windows programs run on macOS. The Linux Wine smoke test verifies a separate host configuration. Standard macOS runners may have no usable GPU and do not provide an interactive 3D CAD workstation.

A meaningful SOLIDWORKS test will need a supported licensing arrangement, installer access, and an interactive macOS test machine. Until then, do not label any green CI job as SOLIDWORKS compatibility.
