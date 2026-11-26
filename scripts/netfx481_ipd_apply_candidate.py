"""Host-side guarded execution and verification for the separate IPD candidate.

No automatic enabling: the caller must supply a verified package-local
preflight report and opt in on a fresh, authenticated CLR4 CI prefix.
An experimental transaction success is not proof of installed .NET 4.8.1.
"""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

from scripts.netfx481_catalog_wusa import verify_package
from scripts.netfx481_ipd_stage import inventory, digest_tree
from scripts.netfx481_native_delta_gate import EXPECTED_COUNT, EXPECTED_TREE_SHA256
from scripts.netfx481_trial import validate_prefix, probe, wineboot_restart
from scripts.netfx40_msxml3_restart import validate as valid_native40
from scripts.netfx481_payload_audit import snapshot, compare
from scripts.netfx481_clr_load import run as load_clr
from scripts.netfx40_legacy import _terminate_private_setup_wineserver
from scripts.netfx481_ipd_wusa_dryrun import CATEGORIES, windows_path, parse_packet

EXPECTED = {
    "component_file_failures": 0, "component_registry_failures": 0,
    "missing_file": 0, "expression": 0, "registry_type": 0, "cycle": 0,
    "extraction": 0, "load_failure": 0, "unsafe_relative_file_names": 0,
    "exact_dependencies": 1410, "version_only_dependencies": 1,
    "absent_resource_prerequisites": 141, "absent_other_dependencies": 0,
    "neutral_deferred_resources": 141, "package_local_wcf_uses": 1,
    "package_local_trial_attempted": 1, "package_local_graph_passed": 1,
    "package_local_preflight_passed": 1,
}


def preflight_ready(report: object) -> bool:
    if type(report) is not dict or set(report) != {
        "dryrun", "ipd_substitutions", "events", "servicing_performed"
    }:
        return False
    events = report["events"]
    return (
        report["dryrun"] == "FAIL" and report["servicing_performed"] is False
        and type(report["ipd_substitutions"]) is int and report["ipd_substitutions"] == 1
        and type(events) is dict and set(events) == set(CATEGORIES)
        and all(type(v) is int and 0 <= v <= 1000000 for v in events.values())
        and all(events[k] == v for k, v in EXPECTED.items())
    )


def parse_apply(raw: bytes, code: int) -> dict:
    if len(raw) > 4096 or code not in (0, 1):
        raise ValueError("Invalid experimental apply result")
    match = re.match(
        rb"SWCOMPAT_IPD_APPLY_SCHEMA=1\r?\nSWCOMPAT_IPD_APPLY_STARTED=([01])\r?\n"
        rb"SWCOMPAT_IPD_APPLY_COMPLETED=([01])\r?\n", raw)
    if not match:
        raise ValueError("Missing apply result")
    started, completed = (v == b"1" for v in match.groups())
    if completed and not started or (code == 0) != completed:
        raise ValueError("Inconsistent apply result")
    # The candidate prints the original strict dry-run result, not an
    # installation success disguised as strict compatibility.
    preflight = parse_packet(raw[match.end():], 1)
    if completed and not preflight_ready(preflight):
        raise ValueError("Missing package-local apply invariants")
    return {"started": started, "completed": completed, "preflight": preflight}


def inspect(wine: Path, prefix: Path, fixture: Path, package: Path, digest: Path,
            stage: Path, loader: Path, managed: Path, baseline: dict, preflight: dict) -> dict:
    runner = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
    if os.name == "nt" or any(p.is_symlink() for p in (
        wine, prefix, fixture, package, digest, stage, loader, managed
    )):
        raise ValueError("Only private Apple Silicon servicing experiment")
    wine, prefix, fixture, package, digest, stage, loader, managed = (
        p.resolve(strict=True) for p in (wine, prefix, fixture, package, digest, stage, loader, managed)
    )
    if (prefix.parent != runner or prefix.name != "netfx40-msxml3-prefix"
            or stage.parent != runner or stage.name != "netfx481-ipd-stage"
            or fixture.name != "swcompat-wusa-ipd-apply-candidate.exe"
            or loader.name != "netfx481_clr_load.exe"
            or managed.name != "netfx481_runtime_probe.exe"):
        raise ValueError("Unexpected private servicing paths")
    validate_prefix(prefix)
    if (prefix / "drive_c").is_symlink():
        raise ValueError("Linked prefix drive")
    z = prefix / "dosdevices/z:"
    if not z.is_symlink() or z.resolve() != Path("/"):
        raise ValueError("Unexpected private Wine drive map")
    verify_package(package, digest)
    members = inventory(stage)
    if len(members) != EXPECTED_COUNT or digest_tree(members) != EXPECTED_TREE_SHA256:
        raise ValueError("Unverified staging tree")
    if not preflight_ready(preflight):
        raise ValueError("Full independent package-local preflight not verified")
    if not valid_native40(baseline) or not baseline["persistent_native_managed"]:
        raise ValueError("Native CLR4 baseline not independently verified")
    initial = probe(wine, prefix, managed, override="native_only")
    before = snapshot(prefix)
    if (initial["managed"] != "PASS" or initial["clr_family"] != "MICROSOFT_CLR_CANDIDATE"
            or initial["registry"] == "AT_LEAST_481" or before["CLR64"][0] != "PE_AMD64"
            or load_clr(wine, prefix, loader) != "LOADED"):
        raise ValueError("Native CLR4 baseline no longer valid")
    result = {"experimental": True, "strict_cbs_equivalence": False,
              "transaction": "NOT_RUN", "restart": "NOT_RUN",
              "framework481_confirmed": False, "solidworks_compatibility": "NOT_DEMONSTRATED"}
    env = os.environ.copy()
    env.update(WINEPREFIX=str(prefix), WINEARCH="win64", WINEDEBUG="-all")
    env.pop("WINEDLLOVERRIDES", None)
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        try:
            run = subprocess.run(
                [str(wine), str(fixture), windows_path(package), windows_path(stage),
                 "--experimental-apply"],
                env=env, cwd=prefix, stdin=subprocess.DEVNULL, stdout=out,
                stderr=err, timeout=600, check=False)
        except subprocess.TimeoutExpired:
            reaped = _terminate_private_setup_wineserver(wine, prefix)
            result["transaction"] = "TIMEOUT_REAPED" if reaped else "TIMEOUT_UNREAPED"
            return result
        except OSError:
            result["transaction"] = "START_FAILED"
            return result
        out.seek(0)
        try:
            packet = parse_apply(out.read(4097), run.returncode)
        except (ValueError, UnicodeError):
            result["transaction"] = "BAD_PACKET"
            return result
    result["transaction"] = ("COMPLETED" if packet["completed"] else
                             "PARTIAL_OR_FAILED" if packet["started"] else "PREFLIGHT_REJECTED")
    if not packet["completed"]:
        return result
    result["restart"] = wineboot_restart(wine, prefix, timeout=120)
    if result["restart"] != "COMPLETED":
        return result
    payload = compare(before, snapshot(prefix))
    measured = probe(wine, prefix, managed, override="native_only")
    loaded = load_clr(wine, prefix, loader)
    result.update(payload=payload, loader=loaded, registry=measured["registry"],
                  runtime_family=measured["clr_family"], managed=measured["managed"])
    result["framework481_confirmed"] = (
        payload["status"] == "MEASURED"
        and payload["changes"]["CLR64"] == "CHANGED"
        and payload["after"]["CLR64"] == payload["after"]["MSCORLIB64"] == "PE_AMD64"
        and loaded == "LOADED" and measured["registry"] == "AT_LEAST_481"
        and measured["clr_family"] == "MICROSOFT_CLR_CANDIDATE" and measured["managed"] == "PASS")
    return result


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    for name in ("wine", "prefix", "fixture", "package", "sha256-file", "stage",
                 "loader", "managed", "native40-report", "preflight-report", "output"):
        p.add_argument("--" + name, type=Path, required=True)
    p.add_argument("--agree-disposable-experimental-servicing", action="store_true", required=True)
    a = p.parse_args()
    if a.output.exists() or a.output.is_symlink() or a.output.resolve().is_relative_to(a.prefix.resolve()):
        raise ValueError("Report must be fresh and outside prefix")
    r = inspect(a.wine, a.prefix, a.fixture, a.package, a.sha256_file, a.stage,
                a.loader, a.managed, json.loads(a.native40_report.read_text(encoding="ascii")),
                json.loads(a.preflight_report.read_text(encoding="ascii")))
    a.output.write_text(json.dumps(r, sort_keys=True), encoding="ascii")
    print("Experimental IPD servicing", json.dumps(r, sort_keys=True))
