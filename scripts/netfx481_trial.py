"""Genuine Microsoft .NET Framework 4.8.1 installer experiment on Apple Silicon Wine.

Strictly disposable prefixes, original Microsoft-signed Windows payload (signature
verified on Windows CI), complete SHA-256, bounded Windows executable, and a
self-authored managed fixture. A Wine Mono PASS is explicitly NOT .NET 4.8.1.
No arbitrary raw installer logs, hashes, paths, versions, or license data are
included in the emitted report.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import tempfile

SENTINEL = ".swcompat-netfx481-disposable"
MIN_BYTES = 15 * 1024 * 1024
MAX_BYTES = 250 * 1024 * 1024
MAX_PROBE_OUTPUT = 4096
FIELDS = {
    "SCHEMA": {"1"},
    "REGISTRY": {"AT_LEAST_481", "BELOW_481", "NOT_FOUND", "UNAVAILABLE"},
    "CLR_FAMILY": {"MONO", "MICROSOFT_CLR_CANDIDATE", "UNKNOWN"},
    "MANAGED": {"PASS", "FAIL"},
}
LINE = re.compile(r"^SWCOMPAT_NETFX481_([A-Z_]+)=([A-Z0-9_]+)$")
SHA = re.compile(r"[0-9a-fA-F]{64}\Z")


def validate_prefix(prefix: Path) -> None:
    if (prefix.is_symlink() or not (prefix / SENTINEL).is_file()
            or not (prefix / "drive_c").is_dir()
            or not (prefix / "system.reg").is_file()):
        raise ValueError("Only initialized, marked disposable Wine prefixes are allowed")


def verify_media(installer: Path, manifest: Path) -> bool:
    if installer.is_symlink() or manifest.is_symlink():
        raise ValueError("Linked installer files are not permitted")
    if installer.name.casefold() != "ndp481-x86-x64-allos-enu.exe" or not installer.is_file():
        raise ValueError("Expected Microsoft .NET Framework 4.8.1 offline installer")
    if not MIN_BYTES <= installer.stat().st_size <= MAX_BYTES:
        raise ValueError("Unexpected Microsoft installer size")
    expected = manifest.read_text(encoding="ascii").strip()
    if not SHA.fullmatch(expected):
        raise ValueError("Invalid SHA256 manifest")
    digest = hashlib.sha256()
    with installer.open("rb") as stream:
        for data in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(data)
    if digest.hexdigest().lower() != expected.lower():
        raise ValueError("SHA256 mismatch")
    return True


def parse_probe(raw: bytes, exit_code: int) -> dict[str, str]:
    empty = {key.lower(): "NOT_VERIFIED" for key in FIELDS if key != "SCHEMA"}
    if exit_code not in (0, 1) or len(raw) > MAX_PROBE_OUTPUT or b"\x00" in raw:
        return empty
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError:
        return empty
    values: dict[str, str] = {}
    for line in text.splitlines():
        match = LINE.fullmatch(line.strip())
        if not match:
            if line.startswith("SWCOMPAT_NETFX481_"):
                return empty
            continue
        key, value = match.groups()
        if key not in FIELDS or value not in FIELDS[key] or key in values:
            return empty
        values[key] = value
    if set(values) != set(FIELDS) or values["SCHEMA"] != "1":
        return empty
    result = {key.lower(): values[key] for key in FIELDS if key != "SCHEMA"}
    if (result["managed"] == "PASS") != (exit_code == 0):
        return empty
    return result


# Only these isolated DLL-load experiments are accepted; do not modify the
# host Wine prefix or turn off normal Windows DLL loading globally.
NATIVE_DLL_OVERRIDES = {
    "native_first": "mscoree=n,b;clr=n,b",
    "native_only": "mscoree=n;clr=n",
}


def probe(wine: Path, prefix: Path, fixture: Path, timeout: int = 70, *,
          override: str | None = None) -> dict[str, str]:
    if override is not None and override not in NATIVE_DLL_OVERRIDES:
        raise ValueError("Unknown controlled DLL-load experiment")
    env = os.environ.copy()
    env.pop("WINEDLLOVERRIDES", None)
    env.update({"WINEPREFIX": str(prefix), "WINEARCH": "win64", "WINEDEBUG": "-all"})
    if override is not None:
        env["WINEDLLOVERRIDES"] = NATIVE_DLL_OVERRIDES[override]
    with tempfile.TemporaryFile() as out:
        try:
            run = subprocess.run(
                [str(wine), str(fixture)], cwd=fixture.parent, env=env,
                stdin=subprocess.DEVNULL, stdout=out, stderr=subprocess.STDOUT,
                timeout=timeout, check=False,
            )
            exit_code = run.returncode
        except (OSError, subprocess.TimeoutExpired):
            exit_code = 124
        out.seek(0)
        raw = out.read(MAX_PROBE_OUTPUT + 1)
    return parse_probe(raw, exit_code)


def runtime_ready(state: dict[str, str]) -> bool:
    return (state.get("registry") == "AT_LEAST_481"
            and state.get("clr_family") == "MICROSOFT_CLR_CANDIDATE"
            and state.get("managed") == "PASS")


# The genuine .NET installer may see a spoofed Wine Release value and
# short-circuit even when the actual managed runtime is Wine Mono. Only the
# explicit experiment may remove this SINGLE value in a disposable prefix.
NETFX_FULL_KEY = r"HKLM\Software\Microsoft\NET Framework Setup\NDP\v4\Full"
NETFX_WOW6432_FULL_KEY = r"HKLM\Software\Wow6432Node\Microsoft\NET Framework Setup\NDP\v4\Full"


def reg_code(wine: Path, prefix: Path, *arguments: str) -> int | None:
    """Execute isolated registry commands without exposing their output."""
    validate_prefix(prefix)
    env = os.environ.copy()
    env.pop("WINEDLLOVERRIDES", None)
    env.update({"WINEPREFIX": str(prefix), "WINEARCH": "win64", "WINEDEBUG": "-all"})
    try:
        result = subprocess.run(
            [str(wine), "reg.exe", *arguments], cwd=prefix, env=env,
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, timeout=20, check=False,
        )
        return result.returncode
    except (OSError, subprocess.TimeoutExpired):
        return None


def clear_false_wow6432_release(wine: Path, prefix: Path, before: dict) -> dict[str, str]:
    """Remove only a proven false Mono Release from the 32-bit registry view.

    Winetricks issue 2367 documents stale Wow6432Node registration blocking
    Microsoft .NET installation in Wine-derived environments. Never modify
    an unmarked or established Wine prefix.
    """
    validate_prefix(prefix)
    if before.get("clr_family") != "MONO" or before.get("registry") != "AT_LEAST_481":
        return {"before": "NOT_APPLICABLE", "action": "NOT_APPLICABLE", "after": "NOT_APPLICABLE"}
    key = NETFX_WOW6432_FULL_KEY
    initial = reg_code(wine, prefix, "query", key, "/v", "Release")
    if initial == 1:
        return {"before": "ABSENT", "action": "NOT_NEEDED", "after": "ABSENT"}
    if initial != 0:
        return {"before": "UNVERIFIED", "action": "QUERY_FAILED", "after": "UNVERIFIED"}
    deleted = reg_code(wine, prefix, "delete", key, "/v", "Release", "/f")
    if deleted != 0:
        return {"before": "PRESENT", "action": "DELETE_FAILED", "after": "UNVERIFIED"}
    checked = reg_code(wine, prefix, "query", key, "/v", "Release")
    return {
        "before": "PRESENT",
        "action": "CLEARED" if checked == 1 else "VERIFY_FAILED",
        "after": "ABSENT" if checked == 1 else "UNVERIFIED",
    }


def clear_false_release(wine: Path, prefix: Path, before: dict) -> str:
    validate_prefix(prefix)
    if before.get("registry") != "AT_LEAST_481" or before.get("clr_family") != "MONO":
        return "NOT_APPLICABLE"
    reg = lambda *arguments: reg_code(wine, prefix, *arguments)
    # Never delete the entire framework key, all registry hives, or any
    # host Windows value. The change exists only in the marked Wine prefix.
    deleted = reg("delete", NETFX_FULL_KEY, "/v", "Release", "/f")
    if deleted != 0:
        return "DELETE_FAILED"
    # Only count correction if the exact release indicator really vanished.
    query = reg("query", NETFX_FULL_KEY, "/v", "Release")
    return "CLEARED" if query == 1 else "STILL_PRESENT_OR_UNVERIFIED"


def run_installer(wine: Path, prefix: Path, installer: Path, timeout: int, *,
                  log_windows_path: str | None = None) -> tuple[str, int | None]:
    env = os.environ.copy()
    env.update({"WINEPREFIX": str(prefix), "WINEARCH": "win64", "WINEDEBUG": "-all"})
    # /q is Microsoft's documented unattended option. Do not supply
    # /AcceptEULA or make any claims about licensing agreement on behalf
    # of the end user. The installer may refuse to run without it.
    # Microsoft .NET Framework deployment supports /log <file>. Write only
    # to a hard-coded private C: path when diagnostic opt-in is explicit.
    if log_windows_path is not None:
        from scripts.netfx481_setup_evidence import WINDOWS_LOG_PATH
        if log_windows_path != WINDOWS_LOG_PATH:
            raise ValueError("Unexpected Microsoft installer transcript destination")
    command = [str(wine), str(installer), "/q", "/norestart"]
    if log_windows_path is not None:
        command.extend(["/log", log_windows_path])
    try:
        proc = subprocess.Popen(
            command,
            cwd=installer.parent, env=env, stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
    except OSError:
        return "START_FAILED", None
    try:
        rc = proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGTERM)
        except (OSError, AttributeError):
            proc.kill()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except OSError:
                pass
            proc.wait(timeout=5)
        return "TIMEOUT", None
    return ("EXIT_ZERO" if rc == 0 else "EXIT_NONZERO", rc)


# Unix status 194 may mean Windows MSI 3010 (restart required) truncated
# to the low eight exit-status bits. It is NOT sufficient proof by itself.
POSSIBLE_3010_UNIX_CODE = 194


def wineboot_restart(wine: Path, prefix: Path, *, timeout: int = 100) -> str:
    """Simulate a Windows restart, only in an explicitly marked Wine prefix."""
    validate_prefix(prefix)
    boot = wine.with_name("wineboot")
    # Some macOS Wine bundles have a wineboot symlink instead of a
    # standalone Unix executable. Treat a symlink as a reason to use Wine's
    # built-in Windows wineboot.exe, not as a terminal setup failure.
    command = ([str(boot), "--restart"]
               if not boot.is_symlink() and boot.is_file() and os.access(boot, os.X_OK)
               else [str(wine), "wineboot.exe", "--restart"])
    env = os.environ.copy()
    env.pop("WINEDLLOVERRIDES", None)
    env.update({"WINEPREFIX": str(prefix), "WINEARCH": "win64", "WINEDEBUG": "-all"})
    try:
        result = subprocess.run(
            command, cwd=prefix, env=env,
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, timeout=timeout, check=False,
        )
    except subprocess.TimeoutExpired:
        return "TIMED_OUT"
    except OSError:
        return "START_FAILED"
    return "COMPLETED" if result.returncode == 0 else "EXIT_NONZERO"


def combine(before: dict, after: dict, termination: str, code: int | None,
            *, native_first: dict | None = None,
            native_only: dict | None = None,
            registry_adjustment: str = "NOT_REQUESTED",
            wow6432_release: dict[str, str] | None = None,
            wine_mono_removal: dict | None = None,
            wine_restart: dict[str, str] | None = None,
            setup_evidence: dict | None = None,
            secondary_evidence: dict | None = None,
            win32_launch: dict | None = None,
            payload_audit: dict | None = None,
            clr_dll_load: str = "NOT_REQUESTED") -> dict:
    if registry_adjustment not in {
        "NOT_REQUESTED", "NOT_APPLICABLE", "CLEARED", "DELETE_FAILED", "STILL_PRESENT_OR_UNVERIFIED"
    }:
        raise ValueError("Unsupported registry adjustment")
    if termination not in {
        "START_FAILED", "EXIT_ZERO", "EXIT_NONZERO", "TIMEOUT",
        "SKIPPED_ALREADY_READY", "SKIPPED_REGISTRY_NOT_CORRECTED", "SKIPPED_MONO_NOT_REMOVED"
    }:
        raise ValueError("Unsupported termination")
    native_first = native_first or {"registry": "NOT_VERIFIED", "clr_family": "NOT_VERIFIED", "managed": "NOT_VERIFIED"}
    native_only = native_only or {"registry": "NOT_VERIFIED", "clr_family": "NOT_VERIFIED", "managed": "NOT_VERIFIED"}
    wow6432_release = wow6432_release or {
        "before": "NOT_TESTED", "action": "NOT_TESTED", "after": "NOT_TESTED"
    }
    if wow6432_release["action"] not in {
        "NOT_TESTED", "NOT_APPLICABLE", "NOT_NEEDED", "CLEARED",
        "QUERY_FAILED", "DELETE_FAILED", "VERIFY_FAILED"
    }:
        raise ValueError("Unsupported 32-bit correction state")
    wine_mono_removal = wine_mono_removal or {
        "before": None, "after": None, "action": "NOT_TESTED"
    }
    if wine_mono_removal["action"] not in {
        "NOT_TESTED", "NOT_APPLICABLE", "REMOVED", "INVENTORY_FAILED",
        "MONO_NOT_REGISTERED", "REMOVE_FAILED", "VERIFY_FAILED"
    }:
        raise ValueError("Unsupported Wine Mono removal state")
    wine_restart = wine_restart or {"reason": "NOT_REQUESTED", "action": "NOT_REQUESTED"}
    if wine_restart["reason"] not in {"NOT_REQUESTED", "NO_3010_SIGNAL", "UNIX_194_POSSIBLE_3010", "WIN32_3010_CONFIRMED"} or wine_restart["action"] not in {
        "NOT_REQUESTED", "NOT_NEEDED", "COMPLETED", "WINEBOOT_MISSING",
        "TIMED_OUT", "START_FAILED", "EXIT_NONZERO",
        "SKIPPED_CHILD_ACTIVE", "SKIPPED_CHILD_UNVERIFIED"
    }:
        raise ValueError("Unsupported Wine restart result")
    setup_evidence = setup_evidence or {
        "status": "NOT_REQUESTED", "phase": "UNKNOWN", "codes": []
    }
    from scripts.netfx481_setup_evidence import KNOWN_RESULTS, KNOWN_PHASES, KNOWN_CODES
    if (setup_evidence.get("status") not in KNOWN_RESULTS
            or setup_evidence.get("phase") not in KNOWN_PHASES
            or not isinstance(setup_evidence.get("codes"), list)
            or len(setup_evidence["codes"]) > len(KNOWN_CODES)
            or any(x not in KNOWN_CODES.values() for x in setup_evidence["codes"])):
        raise ValueError("Unsafe or unexpected setup transcript evidence")
    from scripts.netfx481_setup_evidence import (
        validate_secondary_report, SECONDARY_SOURCE_NAMES
    )
    secondary_evidence = secondary_evidence or {
        "status": "NOT_REQUESTED", "files_scanned": 0,
        "sources": {key: 0 for key in sorted(SECONDARY_SOURCE_NAMES)},
        "phase": "UNKNOWN", "codes": [],
    }
    if not validate_secondary_report(secondary_evidence):
        raise ValueError("Unsafe or unexpected secondary log report")
    from scripts.netfx481_win32_exit import blank as blank_win32, validate as validate_win32
    win32_launch = win32_launch or blank_win32()
    if not validate_win32(win32_launch):
        raise ValueError("Unsafe Win32 launcher evidence")
    from scripts.netfx481_payload_audit import blank as blank_payload, validate as validate_payload
    from scripts.netfx481_clr_load import STATUSES as CLR_LOAD_STATES
    payload_audit = payload_audit or blank_payload()
    if not validate_payload(payload_audit) or clr_dll_load not in CLR_LOAD_STATES:
        raise ValueError("Unsafe native CLR file or loader result")
    return {
        "schema": 1,
        "scope": "MICROSOFT_NETFX481_WINE_DISPOSABLE_EXPERIMENT",
        "media_sha256_verified": True,
        "publisher_signature": "VERIFIED_BY_WINDOWS_CI_NOT_THIS_SCRIPT",
        "before": before,
        "registry_adjustment": registry_adjustment,
        "wow6432_release": wow6432_release,
        "wine_mono_removal": wine_mono_removal,
        "wine_restart": wine_restart,
        "setup_evidence": setup_evidence,
        "secondary_evidence": secondary_evidence,
        "win32_launch": win32_launch,
        "payload_audit": payload_audit,
        "clr_dll_load": clr_dll_load,
        "after": after,
        "after_native_first": native_first,
        "after_native_only": native_only,
        "install_execution": termination,
        "installer_exit_code": code if termination in {"EXIT_ZERO", "EXIT_NONZERO"} else None,
        "framework_runtime_ready": runtime_ready(after),
        "native_first_runtime_ready": runtime_ready(native_first),
        "native_only_runtime_ready": runtime_ready(native_only),
        "runtime_ready_with_controlled_override": (
            runtime_ready(native_first) or runtime_ready(native_only)
        ),
        "new_framework_installation_confirmed": (
            (termination == "EXIT_ZERO" or (
                code == 3010 and win32_launch["category"] == "REBOOT_REQUIRED"
                and wine_restart["action"] == "COMPLETED"
            ) or (
                code == POSSIBLE_3010_UNIX_CODE and win32_launch["status"] == "NOT_REQUESTED"
                and wine_restart["action"] == "COMPLETED"
            ))
            and not runtime_ready(before)
            and (runtime_ready(after) or runtime_ready(native_first) or runtime_ready(native_only))
        ),
        "registry_signal_only": after.get("registry") == "AT_LEAST_481" and not runtime_ready(after),
        "solidworks_compatibility": "NOT_DEMONSTRATED",
    }


def trial(wine: Path, prefix: Path, installer: Path, manifest: Path, fixture: Path,
          timeout: int = 210, *, experiment_clear_false_release: bool = False,
          experiment_clear_wow6432_release: bool = False,
          experiment_remove_wine_mono: bool = False,
          experiment_reboot_after_possible_3010: bool = False,
          experiment_setup_log: bool = False,
          win32_launcher: Path | None = None,
          clr_loader: Path | None = None) -> dict:
    if os.name == "nt":
        raise ValueError("Native Windows execution is not permitted")
    for path in (wine, prefix, installer, manifest, fixture,
                 *([win32_launcher] if win32_launcher is not None else []),
                 *([clr_loader] if clr_loader is not None else [])):
        if path.is_symlink():
            raise ValueError("Symbolic link inputs are not permitted")
    wine = wine.resolve(strict=True)
    prefix = prefix.resolve(strict=True)
    installer = installer.resolve(strict=True)
    manifest = manifest.resolve(strict=True)
    fixture = fixture.resolve(strict=True)
    if win32_launcher is not None:
        win32_launcher = win32_launcher.resolve(strict=True)
    if clr_loader is not None:
        clr_loader = clr_loader.resolve(strict=True)
    validate_prefix(prefix)
    if not wine.is_file() or not os.access(wine, os.X_OK):
        raise ValueError("Wine executable is missing")
    if fixture.name.casefold() != "netfx481_runtime_probe.exe" or not fixture.is_file():
        raise ValueError("Original compiled .NET runtime fixture missing")
    verify_media(installer, manifest)
    if experiment_clear_wow6432_release and not experiment_clear_false_release:
        raise ValueError("32-bit correction requires 64-bit correction opt-in")
    if experiment_remove_wine_mono and not (
        experiment_clear_false_release and experiment_clear_wow6432_release
    ):
        raise ValueError("Wine Mono removal requires both controlled registry corrections")
    if experiment_reboot_after_possible_3010 and not experiment_remove_wine_mono:
        raise ValueError("Reboot experiment requires verified Wine Mono removal")
    if experiment_setup_log and not experiment_remove_wine_mono:
        raise ValueError("Microsoft setup diagnostics require verified Wine Mono removal")
    if win32_launcher is not None and not (experiment_remove_wine_mono and experiment_setup_log):
        raise ValueError("Win32 launch experiment requires Mono removal and private setup transcript")
    if clr_loader is not None and not (experiment_remove_wine_mono and win32_launcher is not None):
        raise ValueError("CLR payload audit requires verified Mono removal and Windows process monitor")
    before = probe(wine, prefix, fixture)
    if runtime_ready(before):
        return combine(before, before, "SKIPPED_ALREADY_READY", None)
    registry_adjustment = "NOT_REQUESTED"
    if experiment_clear_false_release:
        registry_adjustment = clear_false_release(wine, prefix, before)
        if registry_adjustment in {"DELETE_FAILED", "STILL_PRESENT_OR_UNVERIFIED"}:
            return combine(before, before, "SKIPPED_REGISTRY_NOT_CORRECTED", None,
                           registry_adjustment=registry_adjustment)
    wow6432 = None
    if experiment_clear_wow6432_release:
        wow6432 = clear_false_wow6432_release(wine, prefix, before)
        if wow6432["action"] in {"QUERY_FAILED", "DELETE_FAILED", "VERIFY_FAILED"}:
            return combine(before, before, "SKIPPED_REGISTRY_NOT_CORRECTED", None,
                           registry_adjustment=registry_adjustment,
                           wow6432_release=wow6432)
    wine_mono_removal = None
    if experiment_remove_wine_mono:
        from scripts.wine_mono_removal import remove_mono
        wine_mono_removal = remove_mono(wine, prefix, before)
        if wine_mono_removal["action"] != "REMOVED":
            return combine(before, before, "SKIPPED_MONO_NOT_REMOVED", None,
                           registry_adjustment=registry_adjustment,
                           wow6432_release=wow6432,
                           wine_mono_removal=wine_mono_removal)
    from scripts.netfx481_payload_audit import snapshot as payload_snapshot, compare as payload_compare
    payload_before = payload_snapshot(prefix) if clr_loader is not None else None
    log_output = None
    setup_evidence = None
    if experiment_setup_log:
        from scripts.netfx481_setup_evidence import private_log_path
        log_output = private_log_path(prefix)
    win32_evidence = None
    try:
        if win32_launcher is not None:
            from scripts.netfx481_win32_exit import launch as win32_launch_process, termination as win32_termination
            win32_evidence = win32_launch_process(
                wine, prefix, installer, win32_launcher,
                timeout=min(timeout + 30, 390),
            )
            termination, code = win32_termination(win32_evidence)
        else:
            termination, code = run_installer(
                wine, prefix, installer, timeout,
                log_windows_path=(r"C:\swcompat-netfx481-private\framework-setup.txt"
                                  if log_output is not None else None),
            )
    finally:
        if log_output is not None:
            from scripts.netfx481_setup_evidence import classify_log, discard_log
            setup_evidence = classify_log(log_output)
            discard_log(log_output)
    restart = None
    if experiment_reboot_after_possible_3010:
        if (win32_evidence is not None and win32_evidence["status"] == "EXIT_CAPTURED"
                and code == 3010):
            lifecycle = win32_evidence["child_lifecycle"]
            action = ("SKIPPED_CHILD_ACTIVE" if lifecycle == "STILL_ACTIVE" else
                      "SKIPPED_CHILD_UNVERIFIED" if lifecycle in {"PARTIAL", "UNKNOWN"} else
                      wineboot_restart(wine, prefix))
            restart = {"reason": "WIN32_3010_CONFIRMED", "action": action}
        elif win32_evidence is None and termination == "EXIT_NONZERO" and code == POSSIBLE_3010_UNIX_CODE:
            restart = {"reason": "UNIX_194_POSSIBLE_3010",
                       "action": wineboot_restart(wine, prefix)}
        else:
            restart = {"reason": "NO_3010_SIGNAL", "action": "NOT_NEEDED"}
    payload_audit = None
    clr_dll_load = "NOT_REQUESTED"
    if clr_loader is not None:
        from scripts.netfx481_clr_load import run as run_clr_load
        payload_audit = payload_compare(payload_before, payload_snapshot(prefix))
        clr_dll_load = run_clr_load(wine, prefix, clr_loader)
    after = probe(wine, prefix, fixture)
    # Try native Microsoft CLR DLL loading without installing or patching any
    # product binaries. This discriminates Wine Mono being selected by default
    # from a functioning native CLR that Wine's loader could actually invoke.
    native_first = probe(wine, prefix, fixture, override="native_first")
    native_only = probe(wine, prefix, fixture, override="native_only")
    secondary_evidence = None
    if experiment_setup_log:
        from scripts.netfx481_setup_evidence import scan_secondary_logs
        secondary_evidence = scan_secondary_logs(prefix)
    return combine(before, after, termination, code,
                   native_first=native_first, native_only=native_only,
                   registry_adjustment=registry_adjustment,
                   wow6432_release=wow6432,
                   wine_mono_removal=wine_mono_removal,
                   wine_restart=restart,
                   setup_evidence=setup_evidence,
                   secondary_evidence=secondary_evidence,
                   win32_launch=win32_evidence,
                   payload_audit=payload_audit,
                   clr_dll_load=clr_dll_load)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Opt-in signed Microsoft .NET Framework 4.8.1 experiment on disposable Wine")
    ap.add_argument("--wine", type=Path, required=True)
    ap.add_argument("--prefix", type=Path, required=True)
    ap.add_argument("--installer", type=Path, required=True)
    ap.add_argument("--sha256-file", type=Path, required=True)
    ap.add_argument("--probe", type=Path, required=True)
    ap.add_argument("--output", type=Path, required=True)
    ap.add_argument("--timeout", type=int, default=210)
    ap.add_argument("--agree-disposable-prefix", action="store_true", required=True)
    ap.add_argument("--experiment-clear-false-release", action="store_true",
                    help="Only in marked disposable prefixes, remove a spoofed Mono .NET 4.8.1 Release value before official setup")
    ap.add_argument("--experiment-clear-wow6432-release", action="store_true",
                    help="Also correct Mono's false 32-bit Wow6432Node Release value; requires --experiment-clear-false-release")
    ap.add_argument("--experiment-remove-wine-mono", action="store_true",
                    help="Uninstall Wine Mono MSI in marked disposable prefix before Microsoft .NET; requires both registry flags")
    ap.add_argument("--experiment-reboot-after-possible-3010", action="store_true",
                    help="Reboot Wine only after Unix 194 possibly indicates Windows 3010; requires Mono removal")
    ap.add_argument("--experiment-setup-log", action="store_true",
                    help="Classify private original Microsoft setup /log without uploading or printing raw transcript")
    ap.add_argument("--win32-launcher", type=Path,
                    help="Run original verified setup via self-authored Windows CreateProcess fixture, capture real 32-bit exit")
    ap.add_argument("--clr-loader", type=Path,
                    help="Audit actual native .NET CLR PE files and test Win32 LoadLibraryW in disposable Wine prefix")
    args = ap.parse_args(argv)
    if not 60 <= args.timeout <= 360:
        ap.error("Invalid bounded timeout")
    try:
        protected_paths = [args.installer, args.sha256_file, args.probe]
        protected_paths.extend(path for path in (args.win32_launcher, args.clr_loader) if path is not None)
        if args.output.is_symlink() or args.output.resolve() in {path.resolve() for path in protected_paths}:
            raise ValueError("Report would overwrite input or symlink")
        result = trial(args.wine, args.prefix, args.installer, args.sha256_file, args.probe, args.timeout,
                       experiment_clear_false_release=args.experiment_clear_false_release,
                       experiment_clear_wow6432_release=args.experiment_clear_wow6432_release,
                       experiment_remove_wine_mono=args.experiment_remove_wine_mono,
                       experiment_reboot_after_possible_3010=args.experiment_reboot_after_possible_3010,
                       experiment_setup_log=args.experiment_setup_log,
                       win32_launcher=args.win32_launcher,
                       clr_loader=args.clr_loader)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    except (OSError, ValueError):
        ap.error("Trial refused: inspect disposable Wine setup and verified Microsoft package")
    print("False 4.8.1 registry release correction:", result["registry_adjustment"])
    print("32-bit false release correction:", result["wow6432_release"]["action"])
    print("Wine Mono MSI uninstall:", result["wine_mono_removal"]["action"])
    print("Possible Windows 3010 reboot:", result["wine_restart"]["reason"])
    print("Disposable Wine restart:", result["wine_restart"]["action"])
    print("Microsoft setup diagnostic availability:", result["setup_evidence"]["status"])
    print("Microsoft setup failure phase:", result["setup_evidence"]["phase"])
    print("Microsoft setup recognized error categories:", ",".join(result["setup_evidence"]["codes"]) or "NONE")
    print("Secondary Microsoft setup logs:", result["secondary_evidence"]["status"])
    print("Secondary Microsoft setup files inspected:", result["secondary_evidence"]["files_scanned"])
    print("Secondary Microsoft setup phase:", result["secondary_evidence"]["phase"])
    print("Secondary Microsoft setup error categories:", ",".join(result["secondary_evidence"]["codes"]) or "NONE")
    print("Original full Win32 exit status:", result["win32_launch"]["exit_hex"])
    print("Original full Win32 result:", result["win32_launch"]["category"])
    print("Original Win32 bootstrapper child:", result["win32_launch"]["child_seen"])
    print("Direct child lifecycle after parent exits:", result["win32_launch"]["child_lifecycle"])
    print("Direct child exit aggregate:", result["win32_launch"]["child_exit"])
    print("Original .NET CLR x64 on disk before:", result["payload_audit"]["before"]["CLR64"])
    print("Original .NET CLR x64 on disk after:", result["payload_audit"]["after"]["CLR64"])
    print("CLR x64 file change:", result["payload_audit"]["changes"]["CLR64"])
    print("Original .NET CLR Win32 LoadLibraryW:", result["clr_dll_load"])
    print("Microsoft .NET 4.8.1 original setup:", result["install_execution"])
    print("Independent Microsoft CLR candidate after:", result["after"]["clr_family"])
    print("Registered .NET 4.8.1 after:", result["after"]["registry"])
    print("Functional managed execution after:", result["after"]["managed"])
    print("Real .NET 4.8.1 readiness:", result["framework_runtime_ready"])
    print("Native-first Microsoft CLR candidate:", result["after_native_first"]["clr_family"])
    print("Native-only Microsoft CLR candidate:", result["after_native_only"]["clr_family"])
    print("Runtime ready with controlled native loading:", result["runtime_ready_with_controlled_override"])
    print("SOLIDWORKS: NOT_DEMONSTRATED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
