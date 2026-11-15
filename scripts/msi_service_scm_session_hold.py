"""Read-only cross-process SCM lookup while another Wine process holds SCM handles.

Only the original self-authored service in a marked disposable Wine prefix.
Never register, start, stop or remove external services.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time

from scripts.netfx481_trial import validate_prefix
from scripts.msi_service_action_trial import EXE_NAME, SERVICE_STATES, _env, binary_state, service_result, LINE, MARKERS
from scripts.msi_service_registry_observation import service_registry
from scripts.msi_service_scm_coherence import validate as validate_prior

SCOPE = "DISPOSABLE_ORIGINAL_MSI_CROSS_PROCESS_SCM_HANDLE_LIFETIME_NOT_SOLIDWORKS"
HOLDER = {"NOT_RUN", "SERVICE_OPEN", "MANAGER_ONLY", "FAILED", "NO_MARKER"}
CONCLUSIONS = {"NOT_APPLICABLE", "VISIBLE_ONLY_WITH_HOLDER",
               "STILL_ABSENT_WITH_HOLDER", "INCONSISTENT", "UNRESOLVED"}
PREFIX = b"SWCOMPAT_SCM_HOLDER="
PROTOCOL_DETAILS = {
    "NOT_RUN", "VALID", "TIMEOUT", "LAUNCH_ERROR", "BAD_EXIT",
    "OVERSIZED", "NUL_BYTE", "NO_HEADER", "INVALID_MARKER",
    "DUPLICATE_MARKER", "MISSING_MARKER", "WRONG_PHASE",
    "UNRECOGNIZED_STATUS", "HOLDER_NOT_READY",
}


def protocol_detail(raw: bytes, code: int, mode: str) -> str:
    """Distinguish strict original Win32 marker failures without exporting output."""
    if len(raw) > 2048:
        return "OVERSIZED"
    if b"\0" in raw:
        return "NUL_BYTE"
    if code not in (0, 1):
        return "BAD_EXIT"
    if b"SWCOMPAT_SERVICE_PHASE=" not in raw:
        return "NO_HEADER"
    seen: dict[str, str] = {}
    for line in raw.splitlines():
        if not line.startswith(b"SWCOMPAT_SERVICE_"):
            continue
        match = LINE.fullmatch(line.strip())
        if not match:
            return "INVALID_MARKER"
        key = match.group(1).decode("ascii")
        if key in MARKERS:
            if key in seen:
                return "DUPLICATE_MARKER"
            seen[key] = match.group(2).decode("ascii")
    if set(seen) != MARKERS:
        return "MISSING_MARKER"
    if seen["PHASE"].lower() != mode:
        return "WRONG_PHASE"
    return "VALID" if service_result(raw, code, mode) != "UNKNOWN" else "UNRECOGNIZED_STATUS"

QUERY_DIAGNOSTICS = {
    "NOT_RUN", "PARSED", "LAUNCH_FAILED", "TIMED_OUT",
    "BAD_EXIT", "NO_PROTOCOL", "MALFORMED", "OVERSIZED",
    "NOT_EXECUTED",
}


def query_with_diagnostic(wine: Path, prefix: Path, exe: Path) -> tuple[str, str, str]:
    """Reproduce original Win32 query once, preserving only fixed failure kinds.

    Never expose Wine stderr, arbitrary stdout, paths or untrusted text.
    """
    with tempfile.TemporaryFile() as output:
        try:
            completed = subprocess.run(
                [str(wine), str(exe), "status"],
                cwd=exe.parent, env=_env(prefix), stdin=subprocess.DEVNULL,
                stdout=output, stderr=subprocess.DEVNULL, timeout=25,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return "UNKNOWN", "TIMED_OUT", "TIMEOUT"
        except OSError:
            return "UNKNOWN", "LAUNCH_FAILED", "LAUNCH_ERROR"
        output.seek(0)
        raw = output.read(2049)
    if len(raw) > 2048:
        return "UNKNOWN", "OVERSIZED", "OVERSIZED"
    if completed.returncode not in (0, 1):
        return "UNKNOWN", "BAD_EXIT", "BAD_EXIT"
    if b"SWCOMPAT_SERVICE_PHASE=" not in raw:
        return "UNKNOWN", "NO_PROTOCOL", "NO_HEADER"
    status = service_result(raw, completed.returncode, "status")
    detail = protocol_detail(raw, completed.returncode, "status")
    return (status, "PARSED", "VALID") if status != "UNKNOWN" else ("UNKNOWN", "MALFORMED", detail)



def parse_holder(raw: bytes) -> str:
    if len(raw) > 1024 or b"\0" in raw:
        return "NO_MARKER"
    rows = [line.strip() for line in raw.splitlines() if line.startswith(PREFIX)]
    if len(rows) != 1:
        return "NO_MARKER"
    result = rows[0][len(PREFIX):]
    return result.decode("ascii") if result in {
        b"SERVICE_OPEN", b"MANAGER_ONLY", b"FAILED"
    } else "NO_MARKER"


def during_holder(wine: Path, prefix: Path, exe: Path) -> tuple[str, str, str, str]:
    """Wait for exact holder readiness and query from a *different* process."""
    with tempfile.TemporaryFile() as output:
        try:
            proc = subprocess.Popen(
                [str(wine), str(exe), "scm-hold"],
                cwd=exe.parent, env=_env(prefix), stdin=subprocess.DEVNULL,
                stdout=output, stderr=subprocess.DEVNULL, start_new_session=True,
            )
        except OSError:
            return "NO_MARKER", "UNKNOWN", "NOT_EXECUTED", "HOLDER_NOT_READY"
        try:
            ready = "NO_MARKER"
            for _ in range(48):
                output.seek(0)
                ready = parse_holder(output.read(1025))
                if ready in {"SERVICE_OPEN", "MANAGER_ONLY", "FAILED"}:
                    break
                if proc.poll() is not None:
                    break
                time.sleep(0.25)
            if ready not in {"SERVICE_OPEN", "MANAGER_ONLY"}:
                return ready, "UNKNOWN", "NOT_EXECUTED", "HOLDER_NOT_READY"
            # The original harmless Win32 executable is run via Wine again
            # with the same prefix, while this process retains SCM handles.
            if proc.poll() is not None:
                return "NO_MARKER", "UNKNOWN", "NOT_EXECUTED", "HOLDER_NOT_READY"
            visible, diagnostic, detail = query_with_diagnostic(wine, prefix, exe)
            if proc.poll() is not None:
                # Holder could have exited before the independent query ended.
                return "NO_MARKER", "UNKNOWN", "NOT_EXECUTED", "HOLDER_NOT_READY"
            return ready, visible, diagnostic, detail
        finally:
            if proc.poll() is None:
                proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)


def classify(before: str, holder: str, during: str, after: str) -> str:
    if holder == "SERVICE_OPEN" and before == "ABSENT" and during in {"STOPPED", "RUNNING"}:
        return "VISIBLE_ONLY_WITH_HOLDER" if after == "ABSENT" else "INCONSISTENT"
    if holder == "SERVICE_OPEN" and before == "ABSENT" and during == "ABSENT":
        return "STILL_ABSENT_WITH_HOLDER"
    return "UNRESOLVED"


def inspect(wine: Path, prefix: Path, exe: Path, prior: Path) -> dict:
    if os.name == "nt" or any(x.is_symlink() for x in (wine, prefix, exe, prior)):
        raise ValueError("Only disposable Wine service fixture")
    try:
        wine, prefix, exe, prior = (x.resolve(strict=True) for x in (wine, prefix, exe, prior))
    except OSError as exc:
        raise ValueError("Original isolated inputs missing") from exc
    validate_prefix(prefix)
    if not wine.is_file() or not os.access(wine, os.X_OK) or not exe.is_file() or exe.name.casefold() != EXE_NAME:
        raise ValueError("Unexpected Wine or original service executable")
    if not prior.is_file() or prior.stat().st_size > 8192:
        raise ValueError("Invalid original SCM coherence report")
    previous = json.loads(prior.read_text(encoding="ascii"))
    if not validate_prior(previous):
        raise ValueError("Invalid preceding same-SCM-connection trial")
    eligible = (
        previous["trial"] == "MEASURED"
        and previous["registry_after"] == "PRESENT"
        and previous["outcome"] in {
            "CROSS_PROCESS_DISAGREEMENT", "EXISTS_BUT_INVISIBLE",
            "NEW_REGISTRATION_VISIBLE", "UNRESOLVED",
        }
    )
    r = {
        "schema": 1, "scope": SCOPE,
        "trial": "MEASURED" if eligible else "NOT_APPLICABLE",
        "binary": "NOT_RUN", "registry": "UNAVAILABLE", "scm_before": "UNKNOWN",
        "holder": "NOT_RUN", "scm_while_held": "UNKNOWN", "scm_after": "UNKNOWN",
        "diagnostic_before": "NOT_RUN", "diagnostic_while_held": "NOT_RUN",
        "diagnostic_after": "NOT_RUN",
        "detail_before": "NOT_RUN", "detail_while_held": "NOT_RUN", "detail_after": "NOT_RUN",
        "outcome": "NOT_APPLICABLE", "native_microsoft_clr": False,
        "solidworks_compatibility": "NOT_DEMONSTRATED",
    }
    if not eligible:
        return r
    r["binary"] = binary_state(prefix, exe)
    r["registry"] = service_registry(wine, prefix)
    if r["binary"] != "PRESENT_MATCH" or r["registry"] != "PRESENT":
        raise ValueError("Original MSI-installed service not independently verified")
    r["scm_before"], r["diagnostic_before"], r["detail_before"] = query_with_diagnostic(wine, prefix, exe)
    r["holder"], r["scm_while_held"], r["diagnostic_while_held"], r["detail_while_held"] = during_holder(wine, prefix, exe)
    r["scm_after"], r["diagnostic_after"], r["detail_after"] = query_with_diagnostic(wine, prefix, exe)
    r["outcome"] = classify(r["scm_before"], r["holder"], r["scm_while_held"], r["scm_after"])
    return r


def validate(r: dict) -> bool:
    if type(r) is not dict or set(r) != {
        "schema", "scope", "trial", "binary", "registry", "scm_before",
        "holder", "scm_while_held", "scm_after", "outcome",
        "diagnostic_before", "diagnostic_while_held", "diagnostic_after",
        "detail_before", "detail_while_held", "detail_after",
        "native_microsoft_clr", "solidworks_compatibility",
    }:
        return False
    if (type(r["schema"]) is not int or r["schema"] != 1 or r["scope"] != SCOPE
            or r["trial"] not in {"MEASURED", "NOT_APPLICABLE"}
            or r["binary"] not in {"NOT_RUN", "PRESENT_MATCH"}
            or r["registry"] not in {"PRESENT", "UNAVAILABLE"}
            or r["holder"] not in HOLDER
            or any(r[x] not in SERVICE_STATES for x in (
                "scm_before", "scm_while_held", "scm_after"))
            or any(r[k] not in QUERY_DIAGNOSTICS for k in (
                "diagnostic_before", "diagnostic_while_held", "diagnostic_after"))
            or any(r[k] not in PROTOCOL_DETAILS for k in (
                "detail_before", "detail_while_held", "detail_after"))
            or r["outcome"] not in CONCLUSIONS
            or r["native_microsoft_clr"] is not False
            or r["solidworks_compatibility"] != "NOT_DEMONSTRATED"):
        return False
    if r["trial"] == "NOT_APPLICABLE":
        return (
            r["binary"] == "NOT_RUN" and r["registry"] == "UNAVAILABLE"
            and r["holder"] == "NOT_RUN" and r["outcome"] == "NOT_APPLICABLE"
            and all(r[key] == "UNKNOWN" for key in (
                "scm_before", "scm_while_held", "scm_after"))
            and all(r[key] == "NOT_RUN" for key in (
                "diagnostic_before", "diagnostic_while_held", "diagnostic_after",
                "detail_before", "detail_while_held", "detail_after"))
        )
    if any(r[k] == "NOT_RUN" for k in ("diagnostic_before", "diagnostic_after")):
        return False
    for state, diagnostic in (
        ("scm_before", "diagnostic_before", "detail_before"),
        ("scm_while_held", "diagnostic_while_held", "detail_while_held"),
        ("scm_after", "diagnostic_after", "detail_after"),
    ):
        if (r[state] != "UNKNOWN") != (r[diagnostic] == "PARSED"):
            return False
        if (r[diagnostic] == "PARSED") != (r[detail] == "VALID"):
            return False
        if r[diagnostic] == "NOT_EXECUTED" and r[detail] != "HOLDER_NOT_READY":
            return False
        if r[diagnostic] == "MALFORMED" and r[detail] not in {
            "NUL_BYTE", "INVALID_MARKER", "DUPLICATE_MARKER",
            "MISSING_MARKER", "WRONG_PHASE", "UNRECOGNIZED_STATUS",
        }:
            return False
    return (r["binary"] == "PRESENT_MATCH" and r["registry"] == "PRESENT"
            and r["outcome"] == classify(r["scm_before"], r["holder"],
                                          r["scm_while_held"], r["scm_after"]))


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Independent SCM query with retained Wine SCM handles")
    for key in ("wine", "prefix", "exe", "prior", "output"):
        p.add_argument("--" + key, type=Path, required=True)
    p.add_argument("--agree-disposable-prefix", action="store_true", required=True)
    a = p.parse_args(argv)
    try:
        if a.output.is_symlink() or a.output.resolve() in {
            x.resolve() for x in (a.wine, a.prefix, a.exe, a.prior)
        }:
            raise ValueError("Output overlaps input")
        r = inspect(a.wine, a.prefix, a.exe, a.prior)
        if not validate(r):
            raise ValueError("Invalid Wine SCM lifetime report")
        a.output.parent.mkdir(parents=True, exist_ok=True)
        a.output.write_text(json.dumps(r, indent=2) + "\n", encoding="ascii")
    except (OSError, ValueError, json.JSONDecodeError):
        p.error("Isolated read-only SCM holder experiment failed")
    for key in ("trial", "binary", "registry", "scm_before", "diagnostic_before",
                "detail_before", "holder", "scm_while_held", "diagnostic_while_held",
                "detail_while_held", "scm_after", "diagnostic_after", "detail_after", "outcome"):
        print("Original MSI SCM connection-lifetime differential", key, r[key])
    print("Native Microsoft CLR and SOLIDWORKS: NOT DEMONSTRATED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
