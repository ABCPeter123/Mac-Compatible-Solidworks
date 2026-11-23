"""Isolated signed Microsoft .NET 4.8 x64 MSI+MSP control after bootstrapper 5100.

This experiment bypasses the *bootstrapper only*, not Microsoft's MSI content.
It is not a supported Windows installation technique. Never assert a working
4.8, 4.8.1, or SOLIDWORKS without genuine on-disk CLR and managed execution.
Original Microsoft media must be authenticated by Windows CI and SHA256-bound.
Never upload vendor binaries, Windows Installer database or private logs.
"""
from __future__ import annotations

import argparse
import json
import os
import re
from pathlib import Path
import subprocess
import tempfile
import time
from collections.abc import Callable

from scripts.netfx40_msxml3_restart import validate as valid_native40
from scripts.netfx40_to_48_direct import verify_original_media
from scripts.netfx40_to_48_intermediate import _env, _release, _set_winver, _terminate_group
from scripts.netfx40_msi_evidence import (
    classify_msi_log, classify_action, _decode,
    ACTION_CLASSES, ERROR_CLASSES, MAX_FILE_BYTES,
)
from scripts.netfx48_msi_service_evidence import (
    blank as blank_service_evidence,
    classify as classify_service_evidence,
    valid as valid_service_evidence,
)
from scripts.netfx48_assembly_cache import inspect_assembly_cache, STATES as CACHE_STATES
from scripts.netfx48_ngen_queue_control import (
    blank as blank_queue, valid as valid_queue,
    prepare as prepare_queue, resume as resume_queue,
)
from scripts.netfx48_ngen_progress import (
    NgenProgress, blank as blank_progress,
    valid as valid_progress, SAMPLE_INTERVAL,
)
from scripts.netfx48_ngen_log_evidence import (
    baseline as ngen_baseline, inspect as inspect_ngen,
    blank as blank_ngen, valid as valid_ngen,
)
from scripts.netfx481_clr_load import run as load_clr, STATUSES as LOAD_STATES
from scripts.netfx48_scm_service_probe import (
    measure as measure_scm, selftest as selftest_scm,
    valid as valid_scm, blank as blank_scm, SELFTEST_STATUSES,
)
from scripts.netfx481_payload_audit import snapshot
from scripts.netfx481_trial import validate_prefix, probe, wineboot_restart

MSI_TIMEOUTS = {420, 1200}

STEPS = {
    "NOT_RUN", "SUCCESS", "EXIT_NONZERO", "TIMED_OUT",
    "TIMED_OUT_CLEANUP_DENIED", "START_FAILED",
}
LOG_STATES = {"NOT_RUN", "NO_LOG", "CLASSIFIED", "TOO_LARGE", "UNSAFE", "UNREADABLE"}
PRIVATE_LOG = "netfx48-msi-install-private.log"
# An MSI hang may have no Return value 3. Retain the last *action class*,
# never its raw name, timestamp, command, vendor log line, or package path.
ACTION_STARTED = re.compile(
    r"(?i)\b(?:Action start\s+\d{1,2}:\d{2}:\d{2}:\s*|"
    r"Doing action:\s*)([a-z][a-z0-9_. -]{0,90})\.?"
)


def last_started_action(raw: bytes) -> str:
    if type(raw) is not bytes or len(raw) > MAX_FILE_BYTES:
        return "UNKNOWN"
    decoded = _decode(raw)
    if decoded is None:
        return "UNKNOWN"
    last = "UNKNOWN"
    for line in decoded.splitlines():
        if len(line) > 8192:
            continue
        match = ACTION_STARTED.search(line)
        if match:
            last = classify_action(match.group(1).strip().rstrip("."))
    return last


def blank_msi_log() -> dict:
    return {"status": "NOT_RUN", "failure": False, "action": "UNKNOWN",
            "last_started_action": "UNKNOWN", "errors": [],
            **blank_service_evidence()}


def classify_private_msi_log(root: Path) -> dict:
    """Publish only existing coarse classifier enums, never vendor log content."""
    log = root / PRIVATE_LOG
    if root.is_symlink() or log.is_symlink():
        return {**blank_msi_log(), "status": "UNSAFE"}
    try:
        if not log.is_file():
            return {**blank_msi_log(), "status": "NO_LOG"}
        size = log.stat().st_size
        if size > MAX_FILE_BYTES:
            return {**blank_msi_log(), "status": "TOO_LARGE"}
        with log.open("rb") as src:
            raw = src.read(MAX_FILE_BYTES + 1)
        if len(raw) > MAX_FILE_BYTES:
            return {**blank_msi_log(), "status": "TOO_LARGE"}
        scan = classify_msi_log(raw)
        if not scan["readable"]:
            return {**blank_msi_log(), "status": "UNREADABLE"}
        return {"status": "CLASSIFIED", "failure": scan["failure"],
                "action": scan["action"],
                "last_started_action": last_started_action(raw),
                "errors": scan["errors"], **classify_service_evidence(raw)}
    except OSError:
        return {**blank_msi_log(), "status": "UNREADABLE"}
    finally:
        try:
            if log.is_file() and not log.is_symlink():
                log.unlink()
        except OSError:
            pass


def valid_msi_log(report: object) -> bool:
    if type(report) is not dict or set(report) != set(blank_msi_log()):
        return False
    if not valid_service_evidence({
            key: report[key] for key in blank_service_evidence()}):
        return False
    if (any(type(report[k]) is not str for k in
            ("status", "action", "last_started_action"))
            or report["status"] not in LOG_STATES
            or type(report["failure"]) is not bool
            or report["action"] not in ACTION_CLASSES
            or report["last_started_action"] not in ACTION_CLASSES
            or type(report["errors"]) is not list
            or any(type(x) is not str or x not in ERROR_CLASSES
                   for x in report["errors"])
            or report["errors"] != sorted(set(report["errors"]))):
        return False
    if report["status"] != "CLASSIFIED":
        return report == {**blank_msi_log(), "status": report["status"]}
    if report["failure"] is False and report["action"] != "UNKNOWN":
        return False
    return True

MEDIA = {"NOT_RUN", "VERIFIED", "FILES_MISSING", "UNSAFE", "INVALID_PACKAGE"}
WINVER = {"NOT_RUN", "APPLIED", "FAILED"}
RESTART = {"NOT_RUN", "COMPLETED", "EXIT_NONZERO", "START_FAILED", "TIMED_OUT"}
RELEASE = {"UNAVAILABLE", "NOT_FOUND", "BELOW_48", "NETFX48_RANGE", "AT_LEAST_481"}
LOADER = LOAD_STATES | {"NOT_VERIFIED"}
NATIVE = {"NOT_VERIFIED", "PASS", "FAIL"}
TARGET = "swcompat-original-netfx48-msi"
MSI = "netfx_Full_x64.msi"
MSP = "netfx_Patch_x64.msp"
MAX_VENDOR_BYTES = 250 * 1024 * 1024
MIN_MSI_BYTES = 4096
OLE_HEADER = bytes.fromhex("D0 CF 11 E0 A1 B1 1A E1")


def blank() -> dict:
    return {
        "status": "NOT_ELIGIBLE", "native40_persistent": False,
        "msi_timeout_seconds": 420,
        "win7": "NOT_RUN", "extract": "NOT_RUN", "media": "NOT_RUN",
        "install": "NOT_RUN", "patch": "NOT_RUN",
        "install_log": blank_msi_log(), "ngen_log": blank_ngen(),
        "ngen_progress": blank_progress(),
        "ngen_queue_policy": "OFF", "ngen_queue": blank_queue(),
        "scm_preflight": blank_scm(), "scm_postflight": blank_scm(),
        "scm_startup": "NOT_RUN",
        "cache_policy": "OBSERVE", "cache_state": "NOT_RUN",
        "win10": "NOT_RUN", "restart": "NOT_RUN",
        "clr64_changed": False, "release": "UNAVAILABLE",
        "loader": "NOT_VERIFIED", "native_only_managed": "NOT_VERIFIED",
        "native48_candidate": False, "framework481_confirmed": False,
        "solidworks_compatibility": "NOT_DEMONSTRATED",
    }


def validate(result: object) -> bool:
    if type(result) is not dict or set(result) != set(blank()):
        return False
    if (result["msi_timeout_seconds"] not in MSI_TIMEOUTS
            or type(result["msi_timeout_seconds"]) is not int
            or result["status"] not in {"NOT_ELIGIBLE", "MEASURED"}
            or result["win7"] not in WINVER or result["win10"] not in WINVER
            or any(result[k] not in STEPS for k in ("extract", "install", "patch"))
            or result["media"] not in MEDIA or result["restart"] not in RESTART
            or not valid_msi_log(result["install_log"])
            or not valid_ngen(result["ngen_log"])
            or not valid_progress(result["ngen_progress"])
            or type(result["ngen_queue_policy"]) is not str
            or result["ngen_queue_policy"] not in {"OFF", "PAUSE"}
            or not valid_queue(result["ngen_queue"])
            or (result["ngen_queue_policy"] == "OFF"
                and result["ngen_queue"] != blank_queue())
            or (result["ngen_queue"]["status"] == "DIRTY"
                and result["win10"] != "NOT_RUN")
            or (result["ngen_queue_policy"] == "PAUSE"
                and result["install"] != "NOT_RUN"
                and result["ngen_queue"]["status"] not in {"COMPLETE", "INCOMPLETE", "DIRTY"})
            or (result["install"] == "NOT_RUN"
                and result["ngen_progress"] != blank_progress())
            or (result["install"] in {"NOT_RUN", "TIMED_OUT_CLEANUP_DENIED"}
                and result["ngen_log"] != blank_ngen())
            or not valid_scm(result["scm_preflight"])
            or not valid_scm(result["scm_postflight"])
            or result["scm_startup"] not in SELFTEST_STATUSES
            or result["cache_policy"] not in {"OBSERVE", "PREPARE"}
            or result["cache_state"] not in CACHE_STATES
            or (result["cache_policy"] != "PREPARE"
                and result["cache_state"] == "CREATED")
            or (result["install"] != "NOT_RUN"
                and result["cache_state"] not in {"PRESENT", "MISSING", "CREATED"})
            or (result["scm_startup"] != "PASS"
                and (result["scm_preflight"] != blank_scm()
                     or result["scm_postflight"] != blank_scm()))
            or (result["scm_postflight"] != blank_scm()
                and result["install"] in {"NOT_RUN", "TIMED_OUT_CLEANUP_DENIED"})
            or (result["install"] == "NOT_RUN"
                and result["install_log"] != blank_msi_log())
            or (result["install"] != "NOT_RUN"
                and result["install_log"]["status"] == "NOT_RUN")
            or result["release"] not in RELEASE
            or not isinstance(result["loader"], str)
            or result["loader"] not in LOADER
            or result["native_only_managed"] not in NATIVE
            or result["framework481_confirmed"] is not False
            or result["solidworks_compatibility"] != "NOT_DEMONSTRATED"
            or any(type(result[k]) is not bool for k in (
                "native40_persistent", "clr64_changed", "native48_candidate"))):
        return False
    if result["status"] == "NOT_ELIGIBLE":
        return result == blank()
    ready = (
        result["native40_persistent"] and result["win7"] == "APPLIED"
        and result["extract"] == "SUCCESS" and result["media"] == "VERIFIED"
        and result["install"] == "SUCCESS" and result["patch"] == "SUCCESS"
        and (result["ngen_queue_policy"] == "OFF"
             or result["ngen_queue"]["status"] == "COMPLETE")
        and result["win10"] == "APPLIED" and result["restart"] == "COMPLETED"
        and result["clr64_changed"] and result["release"] == "NETFX48_RANGE"
        and result["loader"] == "LOADED" and result["native_only_managed"] == "PASS"
    )
    return result["native48_candidate"] is ready


def verify_extracted_media(root: Path) -> str:
    """No arbitrary MSI paths, symlinks, filenames or external MSPs."""
    if root.is_symlink():
        return "UNSAFE"
    if not root.is_dir():
        return "FILES_MISSING"
    for filename in (MSI, MSP):
        file = root / filename
        if file.is_symlink():
            return "UNSAFE"
        if not file.is_file():
            return "FILES_MISSING"
        try:
            size = file.stat().st_size
            with file.open("rb") as stream:
                magic = stream.read(8)
        except OSError:
            return "UNSAFE"
        if not MIN_MSI_BYTES <= size <= MAX_VENDOR_BYTES or magic != OLE_HEADER:
            return "INVALID_PACKAGE"
    return "VERIFIED"


def private_run(args: list[str], env: dict[str, str], cwd: Path,
                timeout: int, *, progress: Callable[[], None] | None = None,
                on_diagnostic: Callable[[bytes], None] | None = None) -> str:
    """Keep vendor output private; optionally classify bounded captured bytes.

    The callback runs only after the installer is reaped and never receives
    more than 8 MiB plus one truncation sentinel byte. Nothing is printed.
    """
    with tempfile.TemporaryFile() as sink:
        try:
            child = subprocess.Popen(
                args, env=env, cwd=cwd, stdin=subprocess.DEVNULL,
                stdout=sink, stderr=sink, start_new_session=True,
            )
        except OSError:
            return "START_FAILED"
        try:
            if progress is None:
                code = child.wait(timeout=timeout)
            else:
                deadline = time.monotonic() + timeout
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise subprocess.TimeoutExpired(args, timeout)
                    try:
                        code = child.wait(timeout=min(SAMPLE_INTERVAL, remaining))
                        break
                    except subprocess.TimeoutExpired:
                        progress()  # fixed NGen metadata only, never text
                        if time.monotonic() >= deadline:
                            raise
        except subprocess.TimeoutExpired:
            # Original Wine installers can spawn grandchildren. Never leave
            # a detached still-running original MSI process *group* behind.
            try:
                _terminate_group(child)
            except PermissionError:
                # macOS can deny SIGKILL to a Wine process group even after
                # the group accepted SIGTERM. Do not conceal the real MSI
                # timeout behind that host cleanup error.
                try:
                    child.kill()
                    child.wait(timeout=5)
                except (OSError, subprocess.TimeoutExpired):
                    pass
                return "TIMED_OUT_CLEANUP_DENIED"
            if on_diagnostic is not None:
                sink.seek(0)
                on_diagnostic(sink.read(8 * 1024 * 1024 + 1))
            return "TIMED_OUT"
        if on_diagnostic is not None:
            sink.seek(0)
            on_diagnostic(sink.read(8 * 1024 * 1024 + 1))
    return "SUCCESS" if code == 0 else "EXIT_NONZERO"


def inspect(wine: Path, prefix: Path, installer: Path, digest: Path,
            loader: Path, managed: Path, native40: dict, *,
            service_fixture: Path | None = None,
            prepare_assembly_cache: bool = False,
            msi_timeout_seconds: int = 420,
            pause_native_ngen_queue: bool = False) -> dict:
    if type(pause_native_ngen_queue) is not bool:
        raise ValueError("Genuine NGen queue pause must be explicit")
    if type(msi_timeout_seconds) is not int or msi_timeout_seconds not in MSI_TIMEOUTS:
        raise ValueError("Unsupported authenticated MSI timeout budget")
    if type(prepare_assembly_cache) is not bool:
        raise ValueError("Cache preparation must be explicitly boolean")
    if os.name == "nt" or any(p.is_symlink() for p in (
            wine, prefix, installer, digest, loader, managed)):
        raise ValueError("Only isolated native Microsoft 4.0 Wine tests permitted")
    wine, prefix, installer, digest, loader, managed = (
        p.resolve(strict=True) for p in
        (wine, prefix, installer, digest, loader, managed)
    )
    validate_prefix(prefix)
    verify_original_media(installer, digest)
    if (loader.name != "netfx481_clr_load.exe"
            or managed.name != "netfx481_runtime_probe.exe"
            or not wine.is_file() or not os.access(wine, os.X_OK)):
        raise ValueError("Unrecognized signed original Microsoft installer fixture")
    if not valid_native40(native40) or not native40["persistent_native_managed"]:
        return blank()
    before = snapshot(prefix)
    initial = probe(wine, prefix, managed, override="native_only")
    if (before["CLR64"][0] != "PE_AMD64"
            or load_clr(wine, prefix, loader) != "LOADED"
            or initial["clr_family"] != "MICROSOFT_CLR_CANDIDATE"
            or initial["managed"] != "PASS"):
        return blank()

    root = prefix / "drive_c" / TARGET
    if root.is_symlink() or root.exists():
        raise ValueError("Original signed MSI extraction must start with empty directory")
    env = _env(wine, prefix)
    win7 = _set_winver(wine, prefix, env, "win7")
    cache_policy = "PREPARE" if prepare_assembly_cache else "OBSERVE"
    cache_state = "NOT_RUN"
    if win7 == "APPLIED":
        cache_state = inspect_assembly_cache(prefix, prepare=prepare_assembly_cache)
        if cache_state in {"UNSAFE", "FAILED"}:
            # Do not launch another original Microsoft setup if its one
            # target directory cannot be independently authenticated.
            result = {**blank(), "status": "MEASURED",
                      "native40_persistent": True, "win7": win7,
                      "cache_policy": cache_policy, "cache_state": cache_state,
                      "msi_timeout_seconds": msi_timeout_seconds,
                      "ngen_queue_policy": "PAUSE" if pause_native_ngen_queue else "OFF"}
            if not validate(result):
                raise ValueError("Invalid fail-closed NGen cache report")
            return result

    # Compare native SCM before and after MSI under the same Win7 profile.
    # A Windows-version switch must not confound the service transition.
    scm_startup = "NOT_RUN"
    scm_preflight = blank_scm()
    if service_fixture is not None:
        if service_fixture.is_symlink() or service_fixture.name != "netfx48_scm_service_probe.exe":
            raise ValueError("Unrecognized native read-only SCM executable")
        service_fixture = service_fixture.resolve(strict=True)
        if win7 == "APPLIED":
            scm_startup = selftest_scm(wine, prefix, service_fixture)
            if scm_startup == "PASS":
                scm_preflight = measure_scm(wine, prefix, service_fixture)
    extracted, media, installed, patched = ("NOT_RUN", "NOT_RUN", "NOT_RUN", "NOT_RUN")
    restart = "NOT_RUN"
    install_log = blank_msi_log()
    ngen_log = blank_ngen()
    ngen_progress = blank_progress()
    queue_report = blank_queue()
    queue_policy = "PAUSE" if pause_native_ngen_queue else "OFF"
    scm_postflight = blank_scm()
    try:
        if win7 == "APPLIED":
            # /x extracts the *unmodified* official Microsoft's original MSI
            # and MSP to the dedicated disposable C: directory.
            extracted = private_run(
                [str(wine), str(installer), "/x:C:\\" + TARGET, "/q"],
                env, prefix, 150,
            )
            if extracted == "SUCCESS":
                media = verify_extracted_media(root)
            if media == "VERIFIED" and pause_native_ngen_queue:
                queue_report = prepare_queue(wine, prefix, env, private_run)
            if media == "VERIFIED" and (not pause_native_ngen_queue or queue_report["status"] == "PREPARED"):
                # Only new NGen log bytes after original MSI startup can
                # contribute bounded signals. Pre-existing CLR4 logs cannot.
                ngen_start = ngen_baseline(prefix)
                progress = NgenProgress(prefix)
                installed = private_run(
                    [str(wine), "msiexec.exe", "/i",
                     "C:\\" + TARGET + "\\" + MSI, "/qn", "/norestart",
                     "/L*v", "C:\\" + TARGET + "\\" + PRIVATE_LOG],
                    env, prefix, msi_timeout_seconds,
                    progress=progress.sample,
                )
                if installed != "TIMED_OUT_CLEANUP_DENIED":
                    progress.sample()
                ngen_progress = progress.snapshot()
                install_log = classify_private_msi_log(root)
                if installed != "TIMED_OUT_CLEANUP_DENIED":
                    ngen_log = inspect_ngen(prefix, ngen_start)
                # Compare actual Win32 SCM state immediately after the genuine
                # MSI attempt, before any optional MSP servicing. No query
                # follows a denied installer process-group cleanup.
                if (service_fixture is not None and scm_startup == "PASS"
                        and installed != "TIMED_OUT_CLEANUP_DENIED"):
                    scm_postflight = measure_scm(wine, prefix, service_fixture)
                # Keep both signed framework packages in the same native
                # queue-pause servicing window, per Microsoft's NGen guidance.
                # The custom MSI and MSP operations remain unmodified.
                if installed == "SUCCESS":
                    patched = private_run(
                        [str(wine), "msiexec.exe", "/p",
                         "C:\\" + TARGET + "\\" + MSP,
                         "/qn", "/norestart", "EXTUI=1"],
                        env, prefix, 420,
                    )
                if pause_native_ngen_queue:
                    queue_report = resume_queue(
                        wine, prefix, env, queue_report, private_run,
                        dirty=("TIMED_OUT_CLEANUP_DENIED" in (installed, patched)))
    finally:
        # A denied process-group cleanup can leave active Windows Installer
        # descendants. Do not issue *any* further Wine commands in that prefix.
        denied = ("TIMED_OUT_CLEANUP_DENIED" in (extracted, installed, patched)
                  or queue_report["status"] == "DIRTY")
        win10 = ("NOT_RUN" if denied
                 else _set_winver(wine, prefix, env, "win10"))
    if denied:
        result = {**blank(), "status": "MEASURED",
                  "native40_persistent": True, "win7": win7,
                  "extract": extracted, "media": media, "install": installed,
                  "patch": patched, "install_log": install_log,
                  "ngen_log": ngen_log, "ngen_progress": ngen_progress,
                  "ngen_queue_policy": queue_policy, "ngen_queue": queue_report,
                  "scm_preflight": scm_preflight,
                  "scm_postflight": scm_postflight,
                  "scm_startup": scm_startup,
                  "cache_policy": cache_policy, "cache_state": cache_state,
                  "msi_timeout_seconds": msi_timeout_seconds}
        if not validate(result):
            raise ValueError("Invalid fail-closed signed MSI timeout report")
        return result
    if installed == "SUCCESS" and patched == "SUCCESS" and win10 == "APPLIED":
        restart = wineboot_restart(wine, prefix, timeout=90)

    after = snapshot(prefix)
    current = probe(wine, prefix, managed, override="native_only")
    result = {
        "status": "MEASURED", "native40_persistent": True,
        "msi_timeout_seconds": msi_timeout_seconds,
        "win7": win7, "extract": extracted, "media": media,
        "install": installed, "patch": patched, "install_log": install_log,
        "ngen_log": ngen_log, "ngen_progress": ngen_progress,
        "ngen_queue_policy": queue_policy, "ngen_queue": queue_report,
        "scm_preflight": scm_preflight, "scm_postflight": scm_postflight,
        "scm_startup": scm_startup,
        "cache_policy": cache_policy, "cache_state": cache_state,
        "win10": win10, "restart": restart,
        "clr64_changed": (before["CLR64"][1] != after["CLR64"][1]
                          and after["CLR64"][0] == "PE_AMD64"),
        "release": _release(wine, prefix, env),
        "loader": load_clr(wine, prefix, loader),
        "native_only_managed": current["managed"],
        "native48_candidate": False, "framework481_confirmed": False,
        "solidworks_compatibility": "NOT_DEMONSTRATED",
    }
    result["native48_candidate"] = (
        result["native40_persistent"] and result["win7"] == "APPLIED"
        and result["extract"] == "SUCCESS" and result["media"] == "VERIFIED"
        and result["install"] == "SUCCESS" and result["patch"] == "SUCCESS"
        and (result["ngen_queue_policy"] == "OFF"
             or result["ngen_queue"]["status"] == "COMPLETE")
        and result["win10"] == "APPLIED" and result["restart"] == "COMPLETED"
        and result["clr64_changed"] and result["release"] == "NETFX48_RANGE"
        and result["loader"] == "LOADED" and result["native_only_managed"] == "PASS"
    )
    if not validate(result):
        raise ValueError("Unverifiable original Microsoft .NET 4.8 MSI result")
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Original signed 4.8 x64 MSI isolation experiment")
    for key in ("wine", "prefix", "installer", "sha256-file", "loader",
                "managed", "native40-report", "output"):
        parser.add_argument("--" + key, required=True, type=Path)
    parser.add_argument("--service-fixture", type=Path)
    parser.add_argument("--prepare-assembly-cache", action="store_true")
    parser.add_argument("--pause-native-ngen-queue", action="store_true")
    parser.add_argument("--msi-timeout-seconds", type=int,
                        choices=sorted(MSI_TIMEOUTS), default=420)
    parser.add_argument("--agree-disposable-prefix", action="store_true", required=True)
    a = parser.parse_args(argv)
    result = inspect(a.wine, a.prefix, a.installer, a.sha256_file,
                     a.loader, a.managed,
                     json.loads(a.native40_report.read_text(encoding="utf-8")),
                     service_fixture=a.service_fixture,
                     prepare_assembly_cache=a.prepare_assembly_cache,
                     pause_native_ngen_queue=a.pause_native_ngen_queue,
                     msi_timeout_seconds=a.msi_timeout_seconds)
    if a.output.is_symlink():
        raise ValueError("Linked experiment report")
    a.output.parent.mkdir(parents=True, exist_ok=True)
    a.output.write_text(json.dumps(result, sort_keys=True), encoding="ascii")
    for key, value in result.items():
        print("Original .NET 4.8 signed MSI experiment", key, value)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
