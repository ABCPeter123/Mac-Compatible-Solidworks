# Recheck MSI-installed original Windows service after a Wine-only restart

The prior Apple Silicon run conclusively showed a service registration visibility difference: our self-authored MSI install-only returned ZERO and installed exact service executable bytes; Windows `reg.exe` found the hard-coded service key under `HKLM\SYSTEM\CurrentControlSet\Services\SWCompatOriginalServiceTest`, while an independent Windows service control process using `OpenServiceW` returned ABSENT. Native Windows installed and observed the same service correctly.

This motivates testing Wine's documented Windows-only service/boot refresh. The existing original `scripts.netfx481_trial.wineboot_restart` helper restarts **only** a marked disposable Wine prefix, using `wineboot --restart` or the macOS Wine bundle's `wine wineboot.exe --restart` fallback. It never reboots macOS and does not modify the real host's Windows services or licensed software.

The new `scripts/msi_service_restart_refresh.py` runs only when the signed-off original MSI evidence shows MSI ZERO, exact binary PRESENT_MATCH, registry PRESENT and independent SCM ABSENT. It performs one bounded Wine restart and then checks both Windows service registry and independent `OpenServiceW` status in the same prefix. The output contains fixed enums only; no user paths, raw registry output or Wine diagnostics are collected.

**Interpretation:** `service_visibility_recovered: true` requires the Wine restart itself to complete and both the registry and independent SCM to report the original service. If the registry entry remains present but SCM still returns ABSENT, a generic external reboot workaround does not correct the observed behavior, and the next engineering target is Wine's service database synchronization or `OpenServiceW`/StartServices interaction. Neither outcome establishes the cause of the Microsoft CLR installer 1603 by itself. A service-start-capable MSI would need an additional direct fix inside its own deferred actions, rather than only a restart after installation.

The genuine Microsoft .NET 4.0 runtime, 4.8.1 servicing/CLR and real SOLIDWORKS installation remain unverified.
