# Native .NET Framework 4.0: Microsoft verbose MSI logging in a disposable Wine prefix

The original hash-pinned and Microsoft Authenticode-verified .NET Framework 4.0 installer reproducibly exits with full Windows error 1603 on hosted Apple Silicon Wine 11.21. Its immediate child process exited nonzero; `Framework64\v4.0.30319\clr.dll` and the native CLR loader remain absent. A self-authored MSI installs successfully, so a blanket missing `msiserver` shim is not justified.

Our preceding [nested setup log and Wine MSI error diagnostics](NETFX40_INNER_MSI.md) found one nested Microsoft MSI log and a generic 1603 but no recognizable `Return value 3` marker. Scoped `WINEDEBUG=-all,err+msi` returned `MSI_ACTION_FINALIZE` and `OTHER_MSI_ERROR`, **not** the cabinet/FDI or Windows error 193 indicators from some older Wine/Winetricks issues. `InstallFinalize` is often a rollback result, not the original failing custom action.

## Experimental diagnostic change

Microsoft documents the Windows Installer per-machine policy:

- Registry: `HKLM\Software\Policies\Microsoft\Windows\Installer`
- `REG_SZ Logging=voicewarmupx`
- Each MSI transaction **may** create `MSI*.LOG` in its Windows `%TEMP%`, unless logging was already set by command line/API or the implementation differs.

This project adds a **strictly opt-in** `--experiment-enable-verbose-msi` mode. It only works in an initialized, explicitly marked disposable Wine prefix. It refuses a pre-existing Logging policy value. It creates only this one value using Windows `reg.exe`, verifies the exact documented string, runs the original unmodified Microsoft Framework offline installer, and deletes the exact policy value in a `finally` clause. CI fails if the policy cannot be verified or removed. It does **not** touch the host macOS registry or any persistent user prefix.

The bounded classifier scans `MSI*.LOG` only in disposable Wine TEMP directories, in addition to the previously recognized Microsoft .NET 4.0 named logs. For a log over 4 MiB, it reads **only the final 4 MiB**, reports `PARTIAL_SCAN`, and checks for Windows Installer's `Action ended HH:MM:SS: ... Return value 3` records. These are mapped only to broad finite groups. No raw setup logs, arbitrary action names, file paths, original Microsoft binaries or user account information enter GitHub artifacts. No registry value is fabricated to assert that .NET is installed.

## Decision rule for intermediate compatibility hooks

A target hook is justified only by an observed, reproducible failing API or action. If the new evidence points to `InstallFiles`, validate Wine's cabinet/media resolution and FDI extraction with an independent minimal MSI. If it points to DLL custom actions or 1723/193, reproduce the specific 32/64-bit custom-action loader path. If it points to service/COM/Fusion/GAC registration, build a Windows-vs-Wine fixture for that operation. For `InstallFinalize` alone, **do not** alter MSI's finalization behavior; find the earlier cause.

A passing diagnostic workflow means collection worked. The native Microsoft CLR is **not ready** unless the independent disk, loader and managed execution gates pass. No outcome here demonstrates running genuine SOLIDWORKS.

References: [Microsoft Windows Installer Logging policy](https://learn.microsoft.com/en-us/windows/win32/msi/logging); [Microsoft Windows Installer logging troubleshooting](https://learn.microsoft.com/en-us/troubleshoot/windows-client/application-management/enable-windows-installer-logging); [Microsoft .NET Framework deployment](https://learn.microsoft.com/en-us/dotnet/framework/deployment/deployment-guide-for-developers).
