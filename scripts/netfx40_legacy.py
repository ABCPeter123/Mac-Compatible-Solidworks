"""Run original Microsoft .NET Framework 4.0 through the legacy Winetricks path.

The setup media is hash-pinned and Authenticode-checked on a Windows CI runner,
then used only in a newly initialized marked Wine prefix. Unlike Winetricks,
this experiment never adds fictitious CLR installation registry values. No
vendor executable, setup text, path or Wine output enters the public report.
"""
from __future__ import annotations

import argparse
from functools import partial
import hashlib
import json
import os
import signal
from pathlib import Path
import subprocess
import tempfile
import threading

from scripts.netfx481_trial import (
    NETFX_FULL_KEY, NETFX_WOW6432_FULL_KEY, probe, validate_prefix,
    wineboot_restart,
)
from scripts.netfx48_baseline import clear_unbacked_release
from scripts.netfx481_payload_audit import snapshot, STATES
from scripts.netfx481_clr_load import run as clr_load, STATUSES as LOAD_STATES
from scripts.netfx481_win32_exit import (
    parse as parse_win32, CATEGORIES, CHILD_VALUES, LIFECYCLE_VALUES, EXIT_VALUES,
)
from scripts.netfx40_msi_evidence import scan as scan_inner_msi, empty as empty_msi, validate as validate_msi
from scripts.netfx40_msi_inventory import (scan as scan_msi_inventory,
    empty as empty_msi_inventory, validate as validate_msi_inventory)
from scripts.netfx40_msi_custom_type import (_private_failed_action, parse as parse_custom_type, empty as empty_custom_type,
    relevant as relevant_custom_trace, validate as validate_custom_type,
    MAX_RETAINED_BYTES, MAX_RETAINED_LINES, MAX_LINE_BYTES)
from scripts.netfx40_wine_msi_errors import parse as parse_wine_msi, empty as empty_wine_msi, validate as validate_wine_msi, MAX_BYTES as WINE_MSI_MAX
from scripts.netfx40_msi_logging_policy import apply as enable_msi_logging, restore as restore_msi_logging, blank as blank_logging, validate as validate_logging
from scripts.wine_mono_removal import inventory, remove_mono
from scripts.netfx40_private_action import store as store_private_action
from swcompat.wine_paths import windows_media_path

INSTALLER_NAME = "dotnetfx40_full_x86_x64.exe"
LAUNCHER_NAME = "netfx40_win32_launch.exe"
# SHA256 of the original Microsoft standalone EXE, independently pinned
# by Winetricks. Also checked for valid Microsoft Authenticode on Windows.
OFFICIAL_SHA256 = "65e064258f2e418816b304f646ff9e87af101e4c9552ab064bb74d281c38659f"
STAGES = {"MEASURED", "ALREADY_NATIVE", "BLOCKED_WINVER", "BLOCKED_REGISTRY",
          "BLOCKED_INSTALLER_CLEANUP",
          "BLOCKED_MONO_REMOVAL", "BLOCKED_WIN32_SELFTEST", "BLOCKED_MEDIA", "BLOCKED_MSI_LOGGING",
          "BLOCKED_SCM_RESTART"}
STATES_START = {"NOT_RUN", "EXIT_CAPTURED", "START_FAILED", "TIMEOUT", "BAD_REPORT",
                "INVALID_ARGUMENT", "WAIT_FAILED", "PROCESS_FAILED"}
MONO_STATES = {"NOT_RUN", "REMOVED", "MONO_NOT_REGISTERED", "INVENTORY_FAILED",
               "REMOVE_FAILED", "VERIFY_FAILED"}
SELF_STATES = {"NOT_RUN", "PASS", "NO_OUTPUT", "BAD_REPORT", "PROCESS_FAILED", "TIMEOUT"}
REG_STATES = {"NOT_RUN", "NOT_NEEDED", "CLEARED", "QUERY_FAILED", "DELETE_FAILED", "VERIFY_FAILED"}
SETUP_CLEANUP = {"NOT_REQUESTED", "NOT_STARTED", "PIPE_CLOSED", "GROUP_REAPED",
                 "PREFIX_REAPED", "UNVERIFIED"}


def verify_media(installer: Path) -> None:
    if (installer.is_symlink() or not installer.is_file()
            or installer.name.casefold() != INSTALLER_NAME
            or not 35 * 1024 * 1024 <= installer.stat().st_size <= 70 * 1024 * 1024):
        raise ValueError("Unexpected original .NET 4.0 media")
    digest = hashlib.sha256()
    with installer.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    if digest.hexdigest() != OFFICIAL_SHA256:
        raise ValueError("Original Microsoft .NET 4.0 SHA256 mismatch")


def _env(prefix: Path, *, installation: bool = False) -> dict[str, str]:
    env = os.environ.copy()
    env.pop("WINEDLLOVERRIDES", None)
    env.update({"WINEPREFIX": str(prefix), "WINEARCH": "win64", "WINEDEBUG": "-all"})
    if installation:
        # Upstream Winetricks load_dotnet40 uses this override only for setup.
        env["WINEDLLOVERRIDES"] = "fusion=b"
        # Narrow Wine error channel, captured privately, never printed raw.
        env["WINEDEBUG"] = "-all,err+msi,fixme+msi"
    return env


def set_legacy_winver(wine: Path, prefix: Path, *, profile: str = "winxp") -> str:
    if profile not in {"winxp", "win7"}:
        raise ValueError("Unsupported original .NET 4.0 experiment profile")
    validate_prefix(prefix)
    try:
        done = subprocess.run(
            [str(wine), "winecfg.exe", "-v", profile],
            env=_env(prefix), cwd=prefix,
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, timeout=45, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return "FAILED"
    return "APPLIED" if done.returncode == 0 else "FAILED"


def _run(wine: Path, prefix: Path, fixture: Path, arguments: list[str],
         *, setup: bool = False, timeout: int = 75) -> dict:
    validate_prefix(prefix)
    if fixture.is_symlink() or not fixture.is_file() or fixture.name.casefold() != LAUNCHER_NAME:
        raise ValueError("Expected self-authored .NET 4.0 Win32 launcher")
    env = _env(prefix, installation=setup)
    with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as private_errors:
        try:
            result = subprocess.run(
                [str(wine), str(fixture), *arguments], cwd=fixture.parent,
                env=env, stdin=subprocess.DEVNULL, stdout=output,
                stderr=private_errors if setup else subprocess.DEVNULL,
                check=False, timeout=timeout,
            )
            code = result.returncode
            failed = None
        except subprocess.TimeoutExpired:
            code, failed = 124, "TIMEOUT"
        except OSError:
            code, failed = 124, "PROCESS_FAILED"
        output.seek(0)
        raw = output.read(4097)
        private_errors.seek(0)
        diagnostic = private_errors.read(WINE_MSI_MAX + 1) if setup else b""
    wine_errors = parse_wine_msi(diagnostic) if setup else empty_wine_msi()
    if failed:
        return {"status": failed, "category": "NOT_AVAILABLE",
                "exit_hex": "NOT_VERIFIED", "child_seen": "NOT_VERIFIED",
                "child_lifecycle": "NOT_VERIFIED", "child_exit": "NOT_VERIFIED",
                "wine_msi_errors": wine_errors}
    result = parse_win32(raw, code)
    result["wine_msi_errors"] = wine_errors
    return result


def _may_store_incomplete_action(store_private: bool, state: dict, result: dict) -> bool:
    """Allow *candidate* MSI table queries from bounded partial evidence.

    A still-open descendant stderr pipe is not the same as a line/byte
    overflow. This never changes TRUNCATED status to SCANNED or proves
    installer causality. A known rollback-only action is rejected separately.
    """
    return (store_private is True
            and result.get("status") == "EXIT_CAPTURED"
            and result.get("category") == "MSI_FATAL_ERROR"
            and type(state.get("lines")) is int
            and (not state.get("overflow") and state.get("reason") == "NONE" or
                 (state.get("overflow") is True
                  and state.get("reason") == "READER_UNFINISHED"
                  and type(state.get("lines")) is int
                  and 0 < state["lines"] < MAX_RETAINED_LINES)))


def _terminate_private_setup_group(process: subprocess.Popen) -> bool:
    """Stop the isolated original installer *group*, not only its launcher.

    The original Win32 wrapper terminates the initial Microsoft bootstrapper
    after its own bounded wait, but nested original MSI/managed optimization
    descendants can survive and hold its captured stderr pipe. Terminate
    only the new Unix session created for this one disposable Wine command.
    Never target a user's global Wine prefix or enumerate unrelated PIDs.
    """
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(process.pid, sig)
        except ProcessLookupError:
            pass
        except OSError:
            return False
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass
        except OSError:
            return False
    return True


def _terminate_private_setup_wineserver(wine: Path, prefix: Path) -> bool:
    """Stop only the original installer's marked, ephemeral CI Wine prefix.

    Wine client descendants can escape the immediate Unix process group but
    remain attached to the same Wine server. The server's -k and -w switches
    use WINEPREFIX to select an isolated Wine session. Never touch a generic,
    persistent, user-owned, symlinked or non-CI prefix; never run wineboot or
    another installer during uncertain cleanup.
    """
    runner = os.environ.get("RUNNER_TEMP")
    if os.name == "nt" or not runner:
        return False
    try:
        root = Path(runner)
        validate_prefix(prefix)
        server = wine.with_name("wineserver")
        if (root.is_symlink() or not root.is_dir()
                or prefix.is_symlink() or prefix.name != "netfx40-msxml3-prefix"
                or prefix.parent.resolve() != root.resolve()
                or any(x.is_symlink() for x in (
                    prefix / ".swcompat-netfx481-disposable",
                    prefix / "system.reg", prefix / "drive_c"))
                or wine.is_symlink() or not wine.is_file()
                or not server.is_file() or not os.access(server, os.X_OK)
                or not server.resolve(strict=True).is_relative_to(
                    wine.resolve(strict=True).parent.parent)):
            return False
        env = _env(prefix)
        for argument in ("-k", "-w"):
            result = subprocess.run(
                [str(server), argument], cwd=prefix, env=env,
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, timeout=18, check=False,
            )
            if result.returncode != 0:
                return False
        return True
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return False


def _run_traced(wine: Path, prefix: Path, fixture: Path,
                arguments: list[str], *, setup: bool = True, timeout: int = 75,
                store_private: bool = False) -> dict:
    """Stream private Wine MSI debug output; never spool raw trace to disk.

    Only selected MSI err/fixme and exact custom-action type lines enter a
    bounded in-memory buffer. Arbitrary source/target/command text is never
    printed, placed in the result, or uploaded to an artifact.
    """
    if not setup:
        raise ValueError("Custom-action trace only for signed original setup")
    validate_prefix(prefix)
    if fixture.is_symlink() or not fixture.is_file() or fixture.name.casefold() != LAUNCHER_NAME:
        raise ValueError("Expected original self-authored Win32 process monitor")
    env = _env(prefix, installation=True)
    env["WINEDEBUG"] = "-all,err+msi,fixme+msi,trace+msi"
    retained = bytearray()
    state = {"overflow": False, "lines": 0, "reason": "NONE"}
    code, failed = 124, "PROCESS_FAILED"
    cleanup = "NOT_STARTED"
    with tempfile.TemporaryFile() as output:
        try:
            process = subprocess.Popen(
                [str(wine), str(fixture), *arguments], cwd=fixture.parent,
                env=env, stdin=subprocess.DEVNULL, stdout=output,
                stderr=subprocess.PIPE, start_new_session=True,
            )
        except OSError:
            process = None
        if process is not None:
            def drain() -> None:
                assert process.stderr is not None
                try:
                    with process.stderr as pipe:
                        while True:
                            line = pipe.readline(MAX_LINE_BYTES + 1)
                            if not line:
                                return
                            if not relevant_custom_trace(line):
                                continue
                            if state["lines"] >= MAX_RETAINED_LINES:
                                state["overflow"] = True
                                if state["reason"] == "NONE":
                                    state["reason"] = "LINE_LIMIT"
                                continue
                            if len(retained) + len(line) > MAX_RETAINED_BYTES:
                                state["overflow"] = True
                                if state["reason"] == "NONE":
                                    state["reason"] = "BYTE_LIMIT"
                                continue
                            retained.extend(line)
                            state["lines"] += 1
                except OSError:
                    state["overflow"] = True
                    if state["reason"] == "NONE":
                        state["reason"] = "READER_UNFINISHED"

            reader = threading.Thread(target=drain, daemon=True)
            reader.start()
            try:
                code = process.wait(timeout=timeout)
                failed = None
            except subprocess.TimeoutExpired:
                failed = "TIMEOUT"
            except OSError:
                failed = "PROCESS_FAILED"
            if failed is None:
                # A finished Win32 launcher is NOT proof its MSI descendants
                # exited. Their inherited stderr pipe may still be open.
                reader.join(timeout=5)
            if failed is not None or reader.is_alive():
                signalled = _terminate_private_setup_group(process)
                # Group SIGKILL is bounded; wait for actual pipe closure.
                reader.join(timeout=5)
                if signalled and not reader.is_alive():
                    cleanup = "GROUP_REAPED"
                else:
                    # Only when the isolated Unix group did not close its
                    # pipe, stop the *same disposable prefix* Wine server.
                    # Detached Wine clients can survive outside that group.
                    stopped = _terminate_private_setup_wineserver(wine, prefix)
                    if stopped:
                        reader.join(timeout=10)
                    cleanup = ("PREFIX_REAPED" if stopped and not reader.is_alive()
                               else "UNVERIFIED")
            else:
                cleanup = "PIPE_CLOSED"
            if reader.is_alive():
                state["overflow"] = True
                if state["reason"] == "NONE":
                    state["reason"] = "READER_UNFINISHED"
        output.seek(0)
        raw = output.read(4097)
    private = bytes(retained)
    errors = parse_wine_msi(private, oversized=state["overflow"])
    reason = state["reason"]
    if failed is not None and reason == "NONE":
        reason = "PROCESS_INCOMPLETE"
    action_type = parse_custom_type(
        private, truncated=state["overflow"] or failed is not None,
        capture_reason=reason,
    )
    if failed:
        return {"status": failed, "category": "NOT_AVAILABLE",
                "exit_hex": "NOT_VERIFIED", "child_seen": "NOT_VERIFIED",
                "child_lifecycle": "NOT_VERIFIED", "child_exit": "NOT_VERIFIED",
                "wine_msi_errors": errors, "custom_action_type": action_type,
                "setup_cleanup": cleanup}
    result = parse_win32(raw, code)
    result["wine_msi_errors"] = errors
    result["custom_action_type"] = action_type
    result["setup_cleanup"] = cleanup
    if _may_store_incomplete_action(store_private, state, result):
        raw_action = _private_failed_action(private)
        normalized = (raw_action.rsplit(b"]", 1)[-1]
                      if raw_action and b"]" in raw_action else raw_action)
        store_private_action(prefix, normalized)
    # Do not return any original action string, even in an internal dict.
    return result


def inspect(wine: Path, prefix: Path, installer: Path, launcher: Path,
            loader: Path, managed: Path, timeout: int = 210, *,
            enable_verbose_msi: bool = False, refresh_scm_after_mono: bool = False,
            enable_custom_action_type: bool = False,
            enable_msi_inventory: bool = False,
            enable_private_action: bool = False,
            enable_extended_setup_wait: bool = False,
            enable_win7_setup: bool = False) -> dict:
    if os.name == "nt":
        raise ValueError("Wine experiment cannot modify native Windows")
    if enable_extended_setup_wait and timeout < 330:
        raise ValueError("Extended Win32 wait needs matching outer timeout")
    if type(enable_win7_setup) is not bool:
        raise ValueError("Windows 7 setup selection must be boolean")
    if any(p.is_symlink() for p in (wine, prefix, installer, launcher, loader, managed)):
        raise ValueError("Refuse linked experiment media")
    # Prevent relative "build/build/foo.exe" errors from changing cwd.
    wine, prefix, installer, launcher, loader, managed = (
        p.resolve(strict=True) for p in (wine, prefix, installer, launcher, loader, managed)
    )
    validate_prefix(prefix)
    if not wine.is_file() or not os.access(wine, os.X_OK):
        raise ValueError("Wine not executable")
    if launcher.name.casefold() != LAUNCHER_NAME or loader.name.casefold() != "netfx481_clr_load.exe" or managed.name.casefold() != "netfx481_runtime_probe.exe":
        raise ValueError("Unexpected self-authored probes")
    verify_media(installer)
    disk_before = snapshot(prefix)
    report = {
        "schema": 1, "scope": "ORIGINAL_NETFX40_LEGACY_WINE",
        "status": "MEASURED", "winver": "NOT_RUN",
        "setup_profile": "win7" if enable_win7_setup else "winxp",
        "registry64": "NOT_RUN", "registry32": "NOT_RUN",
        "mono": "NOT_RUN", "selftest": "NOT_RUN",
        "installer_status": "NOT_RUN", "installer_exit": "NOT_AVAILABLE",
        "installer_exit_hex": "NOT_VERIFIED",
        "installer_child_seen": "NOT_VERIFIED",
        "installer_child_lifecycle": "NOT_VERIFIED",
        "installer_child_exit": "NOT_VERIFIED",
        "installer_cleanup": "NOT_REQUESTED",
        "inner_msi": empty_msi(),
        "msi_inventory": empty_msi_inventory(),
        "wine_msi_errors": empty_wine_msi(),
        "custom_action_type": empty_custom_type(),
        "msi_logging_policy": blank_logging(),
        "pre_setup_scm_restart": "NOT_REQUESTED",
        "reboot": "NOT_RUN",
        "clr64_before": disk_before["CLR64"][0],
        "clr64_after": disk_before["CLR64"][0],
        "clr32_before": disk_before["CLR32"][0],
        "clr32_after": disk_before["CLR32"][0],
        "mscorlib64_after": disk_before["MSCORLIB64"][0],
        "native_loader": "NOT_REQUESTED",
        "runtime_family": "NOT_VERIFIED", "managed_functionality": "NOT_VERIFIED",
        "candidate_native40": False, "netfx481_ready": False,
        "solidworks_compatibility": "NOT_DEMONSTRATED",
    }
    if disk_before["CLR64"][0] != "ABSENT":
        report["status"] = "ALREADY_NATIVE"
        return report
    report["winver"] = set_legacy_winver(wine, prefix, profile=report["setup_profile"])
    if report["winver"] != "APPLIED":
        report["status"] = "BLOCKED_WINVER"
        return report
    for key, field in ((NETFX_FULL_KEY, "registry64"),
                       (NETFX_WOW6432_FULL_KEY, "registry32")):
        state = clear_unbacked_release(wine, prefix, key)
        report[field] = state
        if state not in {"CLEARED", "NOT_NEEDED"}:
            report["status"] = "BLOCKED_REGISTRY"
            return report
    try:
        products = inventory(wine, prefix)
    except ValueError:
        report["mono"] = "INVENTORY_FAILED"
        report["status"] = "BLOCKED_MONO_REMOVAL"
        return report
    if products:
        cleanup = remove_mono(wine, prefix, {"clr_family": "MONO"})
        report["mono"] = cleanup["action"]
        if report["mono"] != "REMOVED":
            report["status"] = "BLOCKED_MONO_REMOVAL"
            return report
    else:
        report["mono"] = "MONO_NOT_REGISTERED"
    if refresh_scm_after_mono:
        # The original SCM MSI differential showed Wine's service database
        # can rehydrate after a bounded restart; test that between *separate*
        # native Microsoft prerequisite stages without modifying their bytes.
        report["pre_setup_scm_restart"] = wineboot_restart(wine, prefix)
        if report["pre_setup_scm_restart"] != "COMPLETED":
            report["status"] = "BLOCKED_SCM_RESTART"
            return report
    pre = _run(wine, prefix, launcher, ["--selftest-3010"], timeout=65)
    report["selftest"] = ("PASS" if pre["status"] == "EXIT_CAPTURED"
                          and pre["exit_hex"] == "00000BC2" else
                          "NO_OUTPUT" if pre["status"] == "BAD_REPORT" else
                          pre["status"] if pre["status"] in SELF_STATES else "BAD_REPORT")
    if report["selftest"] != "PASS":
        report["status"] = "BLOCKED_WIN32_SELFTEST"
        return report
    windows_path = windows_media_path(wine, prefix, installer)
    setup_args = [windows_path] + (["--extended-wait-330"]
                                   if enable_extended_setup_wait else [])
    setup_runner = (partial(_run_traced, store_private=enable_private_action)
                    if enable_custom_action_type else _run)
    if enable_verbose_msi:
        action = enable_msi_logging(wine, prefix)
        report["msi_logging_policy"]["activation"] = action
        if action != "APPLIED":
            report["msi_logging_policy"]["restoration"] = restore_msi_logging(wine, prefix, action)
            report["status"] = "BLOCKED_MSI_LOGGING"
            return report
        try:
            installed = setup_runner(wine, prefix, launcher, setup_args,
                                     setup=True, timeout=min(timeout + 40, 390))
        finally:
            report["msi_logging_policy"]["restoration"] = restore_msi_logging(wine, prefix, action)
    else:
        installed = setup_runner(wine, prefix, launcher, setup_args,
                                 setup=True, timeout=min(timeout + 40, 390))
    report["installer_status"] = installed["status"]
    report["installer_exit"] = installed["category"]
    report["installer_exit_hex"] = installed["exit_hex"]
    report["installer_child_seen"] = installed.get("child_seen", "NOT_VERIFIED")
    report["installer_child_lifecycle"] = installed.get("child_lifecycle", "NOT_VERIFIED")
    report["installer_child_exit"] = installed.get("child_exit", "NOT_VERIFIED")
    report["installer_cleanup"] = installed.get("setup_cleanup", "NOT_REQUESTED")
    if report["installer_cleanup"] == "UNVERIFIED":
        # A detached installer may still own native MSI/CLR services. Do not
        # start any more original Wine commands or falsely treat CLR as safe.
        report["status"] = "BLOCKED_INSTALLER_CLEANUP"
        return report
    # Inspect the actual nested MSI failure before reboot can clear TEMP logs.
    # Raw logs NEVER leave this marked disposable prefix.
    report["inner_msi"] = scan_inner_msi(prefix)
    if enable_msi_inventory:
        # Run after the unchanged authentic installer exits, before a
        # reboot can clear TEMP. This is a presence check, NOT MSI identity.
        report["msi_inventory"] = scan_msi_inventory(prefix)
    report["wine_msi_errors"] = installed.get("wine_msi_errors", empty_wine_msi())
    report["custom_action_type"] = installed.get("custom_action_type", empty_custom_type())
    if installed["status"] == "EXIT_CAPTURED" and installed["category"] == "REBOOT_REQUIRED":
        report["reboot"] = wineboot_restart(wine, prefix)
    else:
        report["reboot"] = "NOT_NEEDED"

    disk_after = snapshot(prefix)
    after = probe(wine, prefix, managed)
    report.update({
        "clr64_after": disk_after["CLR64"][0],
        "clr32_after": disk_after["CLR32"][0],
        "mscorlib64_after": disk_after["MSCORLIB64"][0],
        "native_loader": clr_load(wine, prefix, loader),
        "runtime_family": after["clr_family"],
        "managed_functionality": after["managed"],
    })
    report["candidate_native40"] = (
        disk_before["CLR64"][0] == "ABSENT"
        and disk_after["CLR64"][0] == "PE_AMD64"
        and disk_after["MSCORLIB64"][0] == "PE_AMD64"
        and report["native_loader"] == "LOADED"
        and report["runtime_family"] == "MICROSOFT_CLR_CANDIDATE"
        and report["managed_functionality"] == "PASS"
        and installed["status"] == "EXIT_CAPTURED"
        and installed["category"] in {"SUCCESS", "REBOOT_REQUIRED"}
        and report["reboot"] in {"NOT_NEEDED", "COMPLETED"}
    )
    return report


def validate(r: dict) -> bool:
    return (
        type(r) is dict
        and set(r) == {"schema", "scope", "status", "winver", "setup_profile", "registry64", "registry32",
                       "mono", "selftest", "installer_status", "installer_exit",
                       "installer_exit_hex", "installer_child_seen",
                       "installer_child_lifecycle", "installer_child_exit", "installer_cleanup", "inner_msi", "msi_inventory",
                       "wine_msi_errors", "custom_action_type", "msi_logging_policy",
                       "pre_setup_scm_restart", "reboot", "clr64_before", "clr64_after",
                       "clr32_before", "clr32_after", "mscorlib64_after",
                       "native_loader", "runtime_family", "managed_functionality",
                       "candidate_native40", "netfx481_ready", "solidworks_compatibility"}
        and r["schema"] == 1 and r["scope"] == "ORIGINAL_NETFX40_LEGACY_WINE"
        and r["status"] in STAGES
        and r["winver"] in {"NOT_RUN", "APPLIED", "FAILED"}
        and r["setup_profile"] in {"winxp", "win7"}
        and r["registry64"] in REG_STATES and r["registry32"] in REG_STATES
        and r["mono"] in MONO_STATES and r["selftest"] in SELF_STATES
        and r["installer_status"] in STATES_START
        and r["installer_cleanup"] in SETUP_CLEANUP
        and (r["status"] != "BLOCKED_INSTALLER_CLEANUP" or
             r["installer_cleanup"] == "UNVERIFIED")
        and (r["installer_cleanup"] != "UNVERIFIED" or
             r["status"] == "BLOCKED_INSTALLER_CLEANUP")
        and r["installer_exit"] in (CATEGORIES | {"NOT_AVAILABLE"})
        and r["installer_child_seen"] in CHILD_VALUES
        and r["installer_child_lifecycle"] in LIFECYCLE_VALUES
        and r["installer_child_exit"] in EXIT_VALUES
        and validate_msi(r["inner_msi"])
        and validate_msi_inventory(r["msi_inventory"])
        and validate_wine_msi(r["wine_msi_errors"])
        and validate_custom_type(r["custom_action_type"])
        and validate_logging(r["msi_logging_policy"])
        and r["pre_setup_scm_restart"] in {
            "NOT_REQUESTED", "COMPLETED", "TIMED_OUT", "START_FAILED", "EXIT_NONZERO"
        }
        and (r["installer_status"] == "NOT_RUN"
             or r["pre_setup_scm_restart"] in {"NOT_REQUESTED", "COMPLETED"})
        and (r["installer_status"] != "EXIT_CAPTURED" or
             ((r["installer_child_seen"] == "OBSERVED" and
               r["installer_child_lifecycle"] in {"ALL_EXITED", "PARTIAL", "STILL_ACTIVE"})
              or (r["installer_child_seen"] == "NOT_OBSERVED" and
                  r["installer_child_lifecycle"] == "NOT_OBSERVED")
              or (r["installer_child_seen"] == "UNKNOWN" and
                  r["installer_child_lifecycle"] == "UNKNOWN")))
        and (r["installer_child_lifecycle"] != "ALL_EXITED" or
             r["installer_child_exit"] in {"ALL_ZERO", "NONZERO", "REBOOT_REQUIRED"})
        and (r["installer_child_lifecycle"] == "ALL_EXITED" or
             r["installer_child_exit"] == "NOT_VERIFIED")
        and type(r["installer_exit_hex"]) is str
        and (r["installer_exit_hex"] == "NOT_VERIFIED" or
             (len(r["installer_exit_hex"]) == 8 and all(c in "0123456789ABCDEF"
                                                      for c in r["installer_exit_hex"])))
        and r["reboot"] in {"NOT_RUN", "NOT_NEEDED", "COMPLETED", "TIMED_OUT", "START_FAILED", "EXIT_NONZERO"}
        and all(r[k] in STATES for k in ("clr64_before", "clr64_after", "clr32_before",
                                         "clr32_after", "mscorlib64_after"))
        and r["native_loader"] in LOAD_STATES
        and r["runtime_family"] in {"NOT_VERIFIED", "MONO", "MICROSOFT_CLR_CANDIDATE", "UNKNOWN"}
        and r["managed_functionality"] in {"NOT_VERIFIED", "PASS", "FAIL"}
        and type(r["candidate_native40"]) is bool
        and r["netfx481_ready"] is False
        and r["solidworks_compatibility"] == "NOT_DEMONSTRATED"
    )


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Original Microsoft .NET 4.0 legacy Winetricks-style native CLR test")
    for key in ("wine", "prefix", "installer", "launcher", "loader", "managed", "output"):
        p.add_argument("--" + key, required=True, type=Path)
    p.add_argument("--timeout", type=int, default=210)
    p.add_argument("--agree-disposable-prefix", action="store_true", required=True)
    p.add_argument("--experiment-enable-verbose-msi", action="store_true")
    p.add_argument("--experiment-restart-after-mono", action="store_true")
    p.add_argument("--experiment-trace-custom-action-type", action="store_true")
    p.add_argument("--experiment-inventory-retained-msi", action="store_true")
    p.add_argument("--experiment-private-original-action", action="store_true")
    p.add_argument("--experiment-extended-setup-wait", action="store_true")
    p.add_argument("--experiment-win7-setup", action="store_true")
    args = p.parse_args(argv)
    if not 60 <= args.timeout <= 360:
        p.error("Invalid bounded runtime")
    try:
        if args.output.is_symlink() or args.output.resolve() in {
            x.resolve() for x in (args.wine, args.prefix, args.installer, args.launcher,
                                  args.loader, args.managed)
        }:
            raise ValueError("Output cannot overwrite experiment")
        report = inspect(args.wine, args.prefix, args.installer, args.launcher,
                         args.loader, args.managed, args.timeout,
                         enable_verbose_msi=args.experiment_enable_verbose_msi,
                         refresh_scm_after_mono=args.experiment_restart_after_mono,
                         enable_custom_action_type=args.experiment_trace_custom_action_type,
                         enable_msi_inventory=args.experiment_inventory_retained_msi,
                         enable_private_action=args.experiment_private_original_action,
                         enable_extended_setup_wait=args.experiment_extended_setup_wait,
                         enable_win7_setup=args.experiment_win7_setup)
        if not validate(report):
            raise ValueError("Privacy-safe report invalid")
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="ascii")
    except (ValueError, OSError):
        p.error("Original signed Microsoft .NET 4.0 disposable-prefix experiment refused")
    for key in ("status", "winver", "setup_profile", "mono", "selftest", "installer_status",
                "installer_cleanup",
                "installer_exit", "installer_child_seen",
                "installer_child_lifecycle", "installer_child_exit",
                "reboot", "clr64_before", "clr64_after",
                "clr32_after", "mscorlib64_after", "native_loader",
                "runtime_family", "managed_functionality", "candidate_native40"):
        print("Native .NET 4.0", key, report[key])
    for key in ("status", "files_scanned", "msi_files", "primary_source",
                "msi_result", "first_failed_action_class", "errors", "causality"):
        print("Original .NET 4.0 nested MSI", key, report["inner_msi"][key])
    for key in ("status", "msi_candidates", "netfx_named_candidates",
                "directories_checked", "file_entries_checked"):
        print("Microsoft MSI retained candidate inventory", key, report["msi_inventory"][key])
    for key in ("status", "classes", "msi_error_lines",
                "first_failed_action", "service_action_failures",
                "nonstandard_name_hint"):
        print("Wine MSI narrow error channel", key, report["wine_msi_errors"][key])
    for key in ("status", "family", "base_type", "execution", "impersonation",
                "asynchronous", "ts_aware", "capture_reason"):
        print("Microsoft MSI private action type", key, report["custom_action_type"][key])
    for key in ("activation", "restoration"):
        print("Microsoft MSI verbose logging policy", key, report["msi_logging_policy"][key])
    return 1 if report["status"] == "BLOCKED_INSTALLER_CLEANUP" else 0


if __name__ == "__main__":
    raise SystemExit(main())
