"""Differential CreateServiceW test after a real MSI service registration under Wine.

A self-authored original MSI installed its exact service binary and service
registry key, yet a new SCM client failed to find it. Test whether calling the
real Windows SCM registration API makes *that same benign service* visible.
This is an opt-in, isolated experiment, not a general-purpose service shim.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

from scripts.netfx481_trial import validate_prefix
from scripts.msi_service_restart_refresh import validate as validate_restart
from scripts.msi_service_action_trial import (
    EXE_NAME, SERVICE_STATES, binary_state, installed_binary, query_service,
    _env,
)
from scripts.msi_service_registry_observation import service_registry
from swcompat.wine_paths import windows_media_path

SCOPE = "DISPOSABLE_ORIGINAL_MSI_SERVICE_SCM_API_DIFFERENTIAL_NOT_SOLIDWORKS"
REGISTRATION = {
    "NOT_RUN", "CREATED", "ALREADY_EXISTS", "ACCESS_DENIED",
    "DATABASE_LOCKED", "RPC_UNAVAILABLE", "OTHER_FAILURE", "INVALID_OUTPUT",
}
START = {
    "NOT_RUN", "STARTED", "ACCESS_DENIED", "DATABASE_LOCKED",
    "TIMEOUT", "RPC_UNAVAILABLE", "OTHER_FAILURE", "INVALID_OUTPUT",
}
EXACT = re.compile(rb"SWCOMPAT_SERVICE_(PHASE|ERROR|STATE|CHECK)=([A-Za-z0-9]+)\Z")
ERROR_CLASSES = {
    5: "ACCESS_DENIED", 1055: "DATABASE_LOCKED",
    1722: "RPC_UNAVAILABLE", 1726: "RPC_UNAVAILABLE",
}


def parse_operation(raw: bytes, exit_code: int, action: str) -> str:
    """Decode only four self-authored markers. Never copy private process output."""
    if action not in {"install", "start"}:
        raise ValueError("Unsupported original SCM operation")
    invalid = "INVALID_OUTPUT"
    if exit_code not in (0, 1) or len(raw) > 2048 or b"\x00" in raw:
        return invalid
    fields = {}
    for line in raw.splitlines():
        if not line.startswith(b"SWCOMPAT_SERVICE_"):
            continue
        match = EXACT.fullmatch(line.strip())
        if not match:
            # The self-authored service may print PID/status markers, which
            # are irrelevant to this operation, but any other output is not.
            return invalid
        key = match.group(1).decode("ascii")
        if key in fields:
            return invalid
        fields[key] = match.group(2).decode("ascii")
    if set(fields) != {"PHASE", "ERROR", "STATE", "CHECK"} or fields["PHASE"] != action:
        return invalid
    try:
        code = int(fields["ERROR"])
        state = int(fields["STATE"])
    except ValueError:
        return invalid
    if not 0 <= code <= 65535 or not 0 <= state <= 7:
        return invalid
    if exit_code == 0 and fields["CHECK"] == "PASS" and code == 0:
        if action == "install" and state == 0:
            return "CREATED"
        if action == "start" and state == 4:
            return "STARTED"
    if exit_code == 1 and fields["CHECK"] == "FAIL":
        if action == "install" and code == 1073:
            return "ALREADY_EXISTS"
        if action == "start" and code == 1053:
            return "TIMEOUT"
        return ERROR_CLASSES.get(code, "OTHER_FAILURE")
    return invalid


def operation(wine: Path, prefix: Path, executable: Path, action: str,
              windows_executable: str | None = None) -> str:
    if action not in {"install", "start"}:
        raise ValueError("Unsupported Win32 operation")
    command = [str(wine), str(executable), action]
    if action == "install":
        if not windows_executable:
            raise ValueError("Missing original self-authored service executable path")
        command.append(windows_executable)
    with tempfile.TemporaryFile() as output:
        try:
            completed = subprocess.run(
                command, cwd=executable.parent, env=_env(prefix),
                stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.DEVNULL,
                timeout=35, check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            return "INVALID_OUTPUT"
        output.seek(0)
        data = output.read(2049)
    return parse_operation(data, completed.returncode, action)


def inspect(wine: Path, prefix: Path, executable: Path, prior: Path) -> dict:
    if os.name == "nt" or any(p.is_symlink() for p in (wine, prefix, executable, prior)):
        raise ValueError("Disposable Wine original-service experiment only")
    wine, prefix, executable, prior = (
        p.resolve(strict=True) for p in (wine, prefix, executable, prior)
    )
    validate_prefix(prefix)
    if not wine.is_file() or not os.access(wine, os.X_OK):
        raise ValueError("Missing original Wine binary")
    if not executable.is_file() or executable.name.casefold() != EXE_NAME:
        raise ValueError("Missing original Win32 service fixture")
    if not prior.is_file() or prior.stat().st_size > 8192:
        raise ValueError("Invalid previous bounded diagnostic")
    previous = json.loads(prior.read_text(encoding="ascii"))
    if not validate_restart(previous):
        raise ValueError("Invalid original service restart evidence")
    eligible = (previous["trial"] == "MEASURED"
                and previous["restart"] == "COMPLETED"
                and previous["registry_after"] == "PRESENT"
                and previous["scm_after"] not in {"RUNNING", "STOPPED"})
    report = {
        "schema": 1, "scope": SCOPE,
        "trial": "MEASURED" if eligible else "NOT_APPLICABLE",
        "installed_binary": "NOT_RUN", "scm_before": "UNKNOWN",
        "registry_before": "UNAVAILABLE", "api_register": "NOT_RUN",
        "scm_after_register": "UNKNOWN", "api_start": "NOT_RUN",
        "scm_final": "UNKNOWN", "registry_final": "UNAVAILABLE",
        "registration_visibility_recovered": False,
        "service_running_verified": False,
        "native_microsoft_clr": False,
        "solidworks_compatibility": "NOT_DEMONSTRATED",
    }
    if not eligible:
        return report
    report["installed_binary"] = binary_state(prefix, executable)
    report["registry_before"] = service_registry(wine, prefix)
    report["scm_before"] = query_service(wine, prefix, executable, "status")
    if (report["installed_binary"] != "PRESENT_MATCH"
            or report["registry_before"] != "PRESENT"
            or report["scm_before"] in {"RUNNING", "STOPPED"}):
        return report
    path = installed_binary(prefix)
    # Real Wine path conversion is required. No fabricated C:/ or registry.
    windows_path = windows_media_path(wine, prefix, path)
    report["api_register"] = operation(wine, prefix, executable, "install", windows_path)
    report["scm_after_register"] = query_service(wine, prefix, executable, "status")
    report["registration_visibility_recovered"] = (
        report["api_register"] == "CREATED"
        and report["scm_after_register"] in {"RUNNING", "STOPPED"}
    )
    if report["scm_after_register"] == "STOPPED":
        report["api_start"] = operation(wine, prefix, executable, "start")
    report["scm_final"] = query_service(wine, prefix, executable, "status")
    report["registry_final"] = service_registry(wine, prefix)
    report["service_running_verified"] = (
        report["registry_final"] == "PRESENT"
        and report["installed_binary"] == "PRESENT_MATCH"
        and report["api_start"] == "STARTED"
        and report["scm_final"] == "RUNNING"
    )
    return report


def validate(r: dict) -> bool:
    keys = {
        "schema", "scope", "trial", "installed_binary", "scm_before",
        "registry_before", "api_register", "scm_after_register", "api_start",
        "scm_final", "registry_final", "registration_visibility_recovered",
        "service_running_verified", "native_microsoft_clr",
        "solidworks_compatibility",
    }
    if type(r) is not dict or set(r) != keys:
        return False
    if (type(r["schema"]) is not int or r["schema"] != 1
            or r["scope"] != SCOPE or r["trial"] not in {"MEASURED", "NOT_APPLICABLE"}
            or r["installed_binary"] not in {
                "NOT_RUN", "ABSENT", "PRESENT_MATCH", "CHANGED", "LINKED", "IO_ERROR"}
            or r["registry_before"] not in {"UNAVAILABLE", "PRESENT", "ABSENT"}
            or r["registry_final"] not in {"UNAVAILABLE", "PRESENT", "ABSENT"}
            or any(r[k] not in SERVICE_STATES for k in (
                "scm_before", "scm_after_register", "scm_final"))
            or r["api_register"] not in REGISTRATION or r["api_start"] not in START
            or type(r["registration_visibility_recovered"]) is not bool
            or type(r["service_running_verified"]) is not bool
            or r["native_microsoft_clr"] is not False
            or r["solidworks_compatibility"] != "NOT_DEMONSTRATED"):
        return False
    if r["trial"] == "NOT_APPLICABLE":
        return (r["installed_binary"] == "NOT_RUN"
                and r["api_register"] == "NOT_RUN"
                and r["api_start"] == "NOT_RUN"
                and r["registration_visibility_recovered"] is False
                and r["service_running_verified"] is False)
    attempted = r["api_register"] != "NOT_RUN"
    if attempted and (r["installed_binary"] != "PRESENT_MATCH"
                      or r["registry_before"] != "PRESENT"
                      or r["scm_before"] in {"RUNNING", "STOPPED"}):
        return False
    if r["api_start"] != "NOT_RUN" and (
            not attempted or r["scm_after_register"] != "STOPPED"):
        return False
    if r["registration_visibility_recovered"] != (
            r["api_register"] == "CREATED"
            and r["scm_after_register"] in {"RUNNING", "STOPPED"}):
        return False
    return r["service_running_verified"] == (
        r["registry_final"] == "PRESENT"
        and r["installed_binary"] == "PRESENT_MATCH"
        and r["api_start"] == "STARTED"
        and r["scm_final"] == "RUNNING"
    )


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Original MSI cross-process SCM API registration experiment")
    for key in ("wine", "prefix", "exe", "prior", "output"):
        p.add_argument("--" + key, required=True, type=Path)
    p.add_argument("--agree-disposable-prefix", action="store_true", required=True)
    args = p.parse_args(argv)
    try:
        if args.output.is_symlink() or args.output.resolve() in {
            p.resolve() for p in (args.wine, args.prefix, args.exe, args.prior)
        }:
            raise ValueError("Unsafe output path")
        report = inspect(args.wine, args.prefix, args.exe, args.prior)
        if not validate(report):
            raise ValueError("Invalid original MSI service differential")
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="ascii")
    except (ValueError, OSError, json.JSONDecodeError):
        p.error("Unsafe or incomplete original SCM API differential")
    for key in ("trial", "installed_binary", "scm_before", "registry_before",
                "api_register", "scm_after_register", "api_start", "scm_final",
                "registry_final", "registration_visibility_recovered",
                "service_running_verified"):
        print("Original MSI Win32 API service differential", key, report[key])
    print("Microsoft CLR and SOLIDWORKS compatibility: NOT DEMONSTRATED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
