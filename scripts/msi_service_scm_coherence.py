"""Compare OpenServiceW and CreateServiceW using one retained SCM handle.

This intentionally probes only the self-authored MSI service in a disposable
Wine prefix after real cross-process CreateServiceW reported ALREADY_EXISTS
while OpenServiceW returned ABSENT. No broad API interception or vendor media.
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
from scripts.msi_service_action_trial import EXE_NAME, binary_state, installed_binary, _env
from scripts.msi_service_scm_api_reconcile import validate as validate_prior
from scripts.msi_service_registry_observation import service_registry
from swcompat.wine_paths import windows_media_path

SCOPE = "ORIGINAL_MSI_SERVICE_SAME_SCM_CONNECTION_DIFFERENTIAL_NOT_SOLIDWORKS"
FIELDS = {
    "BEFORE": {"PRESENT", "ABSENT", "OTHER"},
    "CREATE": {"NOT_RUN", "CREATED", "ALREADY_EXISTS", "DATABASE_LOCKED", "ACCESS_DENIED", "OTHER"},
    "AFTER": {"PRESENT", "ABSENT", "OTHER"},
    "COMPLETE": {"YES"},
}
LINE = re.compile(rb"SWCOMPAT_COHERENCE_([A-Z]+)=([A-Z_]+)\Z")
OUTCOMES = {"NOT_APPLICABLE", "EXISTS_BUT_INVISIBLE", "CROSS_PROCESS_DISAGREEMENT",
            "NEW_REGISTRATION_VISIBLE", "UNRESOLVED"}


def parse(raw: bytes, rc: int) -> dict | None:
    if rc != 0 or len(raw) > 2048 or b"\0" in raw:
        return None
    pairs = {}
    for line in raw.splitlines():
        if not line.startswith(b"SWCOMPAT_COHERENCE_"):
            continue
        match = LINE.fullmatch(line.strip())
        if match is None:
            return None
        key, val = (x.decode("ascii") for x in match.groups())
        if key not in FIELDS or val not in FIELDS[key] or key in pairs:
            return None
        pairs[key] = val
    return pairs if set(pairs) == set(FIELDS) else None


def verdict(before: str, creation: str, after: str) -> str:
    if before == "ABSENT" and creation == "ALREADY_EXISTS" and after == "ABSENT":
        return "EXISTS_BUT_INVISIBLE"
    if before == "PRESENT" and creation == "NOT_RUN" and after == "PRESENT":
        return "CROSS_PROCESS_DISAGREEMENT"
    if before == "ABSENT" and creation == "CREATED" and after == "PRESENT":
        return "NEW_REGISTRATION_VISIBLE"
    return "UNRESOLVED"


def inspect(wine: Path, prefix: Path, exe: Path, prior: Path) -> dict:
    if os.name == "nt" or any(p.is_symlink() for p in (wine, prefix, exe, prior)):
        raise ValueError("Only isolated self-authored Wine SCM test")
    try:
        wine, prefix, exe, prior = (p.resolve(strict=True) for p in (wine, prefix, exe, prior))
    except OSError as exc:
        raise ValueError("Missing isolated SCM fixture") from exc
    validate_prefix(prefix)
    if not wine.is_file() or not os.access(wine, os.X_OK) or exe.name.casefold() != EXE_NAME:
        raise ValueError("Unexpected self-authored fixture")
    if not prior.is_file() or prior.stat().st_size > 8192:
        raise ValueError("Invalid prior result")
    previous = json.loads(prior.read_text(encoding="ascii"))
    if not validate_prior(previous):
        raise ValueError("Invalid real SCM API differential")
    eligible = (
        previous["trial"] == "MEASURED"
        and previous["installed_binary"] == "PRESENT_MATCH"
        and previous["api_register"] == "ALREADY_EXISTS"
        and previous["scm_after_register"] == "ABSENT"
        and previous["registry_final"] == "PRESENT"
    )
    report = {
        "schema": 1, "scope": SCOPE, "trial": "MEASURED" if eligible else "NOT_APPLICABLE",
        "first_lookup": "NOT_RUN", "create": "NOT_RUN", "second_lookup": "NOT_RUN",
        "registry_after": "UNAVAILABLE", "outcome": "NOT_APPLICABLE",
        "native_microsoft_clr": False, "solidworks_compatibility": "NOT_DEMONSTRATED",
    }
    if not eligible:
        return report
    if binary_state(prefix, exe) != "PRESENT_MATCH":
        raise ValueError("Original installed binary bytes changed")
    if service_registry(wine, prefix) != "PRESENT":
        raise ValueError("Original MSI service registry disappeared")
    winpath = windows_media_path(wine, prefix, installed_binary(prefix))
    with tempfile.TemporaryFile() as out:
        try:
            proc = subprocess.run(
                [str(wine), str(exe), "coherence", winpath],
                cwd=exe.parent, env=_env(prefix), stdin=subprocess.DEVNULL,
                stdout=out, stderr=subprocess.DEVNULL, timeout=35, check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ValueError("Single-handle original Win32 probe not completed") from exc
        out.seek(0)
        parsed = parse(out.read(2049), proc.returncode)
    if parsed is None:
        raise ValueError("Invalid original SCM coherence marker protocol")
    report["first_lookup"] = parsed["BEFORE"]
    report["create"] = parsed["CREATE"]
    report["second_lookup"] = parsed["AFTER"]
    report["registry_after"] = service_registry(wine, prefix)
    report["outcome"] = verdict(report["first_lookup"], report["create"], report["second_lookup"])
    return report


def validate(r: dict) -> bool:
    if type(r) is not dict or set(r) != {
        "schema", "scope", "trial", "first_lookup", "create", "second_lookup",
        "registry_after", "outcome", "native_microsoft_clr", "solidworks_compatibility"
    }:
        return False
    if (type(r["schema"]) is not int or r["schema"] != 1 or r["scope"] != SCOPE
            or r["trial"] not in {"MEASURED", "NOT_APPLICABLE"}
            or r["first_lookup"] not in FIELDS["BEFORE"] | {"NOT_RUN"}
            or r["second_lookup"] not in FIELDS["AFTER"] | {"NOT_RUN"}
            or r["create"] not in FIELDS["CREATE"]
            or r["registry_after"] not in {"UNAVAILABLE", "PRESENT", "ABSENT"}
            or r["outcome"] not in OUTCOMES
            or r["native_microsoft_clr"] is not False
            or r["solidworks_compatibility"] != "NOT_DEMONSTRATED"):
        return False
    if r["trial"] == "NOT_APPLICABLE":
        return (r["first_lookup"] == r["create"] == r["second_lookup"] == "NOT_RUN"
                and r["registry_after"] == "UNAVAILABLE" and r["outcome"] == "NOT_APPLICABLE")
    if (r["first_lookup"] == "NOT_RUN" or r["second_lookup"] == "NOT_RUN"
            or r["outcome"] == "NOT_APPLICABLE"):
        return False
    if r["first_lookup"] != "ABSENT" and r["create"] != "NOT_RUN":
        return False
    return r["outcome"] == verdict(r["first_lookup"], r["create"], r["second_lookup"])


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Single-connection original SCM service coherence")
    for name in ("wine", "prefix", "exe", "prior", "output"):
        p.add_argument("--" + name, required=True, type=Path)
    p.add_argument("--agree-disposable-prefix", action="store_true", required=True)
    a = p.parse_args(argv)
    try:
        if a.output.is_symlink() or a.output.resolve() in {
            x.resolve() for x in (a.wine, a.prefix, a.exe, a.prior)
        }:
            raise ValueError("Output overlaps input")
        r = inspect(a.wine, a.prefix, a.exe, a.prior)
        if not validate(r):
            raise ValueError("Invalid original service report")
        a.output.parent.mkdir(parents=True, exist_ok=True)
        a.output.write_text(json.dumps(r, indent=2) + "\n", encoding="ascii")
    except (ValueError, OSError, json.JSONDecodeError):
        p.error("Original service SCM coherence experiment refused")
    for name in ("trial", "first_lookup", "create", "second_lookup", "registry_after", "outcome"):
        print("Same SCM connection after original MSI", name, r[name])
    print("Native Microsoft CLR and SOLIDWORKS: NOT DEMONSTRATED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
