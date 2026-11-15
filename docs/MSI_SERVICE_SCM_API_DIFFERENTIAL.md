# Original MSI-installed Windows service: direct SCM API differential

The original WiX x64 MSI built from source passes on native Windows. Under Apple Silicon Wine 11.21, the install-only variant installs the **exact original service executable** and writes the expected `HKLM\\SYSTEM\\CurrentControlSet\\Services\\SWCompatOriginalServiceTest` registry key. A separate process calling `OpenServiceW` returns service absent (Windows 1060). Enabling the MSI `StartServices` action causes the same package to roll back. Wine `wineboot --restart` completed, but the observed post-restart SCM probe was `UNKNOWN`, not a verified recovery.

This experiment does **not** invent a general-purpose Win32 shim or alter Microsoft installers. It asks whether Wine's `CreateServiceW` can register the already MSI-written, benign service in the same marked disposable Wine prefix. The test:

1. Validates the preceding original MSI, independent registry/SCM, and bounded restart reports. Requires a completed Wine-only restart, persisted registry key and SCM not already visible.
2. Verifies the MSI-installed service binary still matches the original MSVC-built fixture exactly. Converts that actual existing path using Wine's drive mapper.
3. Runs the original compiled self-authored `service_smoke.exe install <same-installed-binary>` in a separate Wine process, executing the real `OpenSCManagerW` and `CreateServiceW` APIs.
4. Classifies only four fixed protocol markers and finite Windows error categories, including service already exists (1073), access denied (5), SCM database locked (1055), and RPC unavailable (1722/1726). Logs and arbitrary paths are discarded.
5. Separately queries the service through a fresh SCM client. If it is stopped, calls the original `StartServiceW` implementation once and independently checks for RUNNING. It never starts a service with an unverified binary.
6. Requires strict report validation; never claims .NET or SOLIDWORKS compatibility. The entire prefix is created only for this GitHub Actions run.

Interpretation:

- `CREATED` followed by `STOPPED` or `RUNNING`: a narrow SCM registration repair candidate exists, but its real MSI integration and .NET custom-action semantics still need testing.
- `ALREADY_EXISTS` followed by `ABSENT`: the registry and SCM create path recognize a name that `OpenServiceW` cannot open. The next target is Wine's service database synchronization and the distinct access/search paths.
- `DATABASE_LOCKED`, `RPC_UNAVAILABLE`, or `INVALID_OUTPUT`: address that specific observed service-control or process failure, not arbitrary MSI components.
- `STARTED` plus independently observed `RUNNING`: the benign fixture's direct API service start is proven. It **does not** show that native Microsoft .NET Framework loads or that genuine SOLIDWORKS starts.

No original Microsoft or SOLIDWORKS media is modified. No license logic, false registry readiness, host services or persistent user prefixes are involved. The Apple Silicon CI outcome determines whether the next justified work is a safe Wine SCM registration synchronization shim, a lower-level service RPC fix, or simply better diagnostics.