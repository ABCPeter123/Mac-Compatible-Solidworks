"""Require experimental original CLR 4.8.1 evidence before licensed setup.

Only the explicitly dispatched private trial calls this gate. A passing
gate does not establish CBS equivalence or SOLIDWORKS compatibility.
"""
import argparse
import json
import os
from pathlib import Path

from scripts.netfx481_trial import probe, runtime_ready, validate_prefix
from scripts.netfx481_ipd_apply_candidate import verified_runtime_payloads
from scripts.netfx481_ipd_stage import inventory, digest_tree
from scripts.netfx481_native_delta_gate import EXPECTED_COUNT, EXPECTED_TREE_SHA256
from scripts.netfx481_payload_audit import snapshot
from scripts.netfx481_ipd_gac import registration_complete, registration_sources, cached_sources


def ready(report: object) -> bool:
    if not isinstance(report, dict):
        return False
    if not (
        report.get("experimental") is True
        and report.get("strict_cbs_equivalence") is False
        and report.get("framework481_confirmed") is True
        and report.get("transaction") == "COMPLETED"
        and report.get("restart") == "COMPLETED"
        and report.get("gac_restart") == "COMPLETED"
        and report.get("deferred_verified") is True
        and report.get("registry") == "AT_LEAST_481"
        and report.get("runtime_family") == "MICROSOFT_CLR_CANDIDATE"
        and report.get("managed") == "PASS"
        and report.get("loader") == "LOADED"
    ):
        return False
    gac = report.get("gac_registration")
    writes = report.get("writes")
    provenance = report.get("original_runtime_payloads")
    return (
        registration_complete(gac)
        and isinstance(writes, dict)
        and writes.get("assemblies") == 1387
        and writes.get("first_failure_phase") == "NONE"
        and writes.get("win32_error") == "00000000"
        and type(writes.get("files")) is int and 0 <= writes["files"] <= 1044
        and type(writes.get("deferred")) is int and 0 <= writes["deferred"] <= 1044
        and writes["files"] + writes["deferred"] == 1044
        and writes.get("values") == 11125
        and isinstance(provenance, dict)
        and set(provenance) == {"CLR32", "CLR64", "MSCORLIB32", "MSCORLIB64"}
        and all(isinstance(v, dict) and v.get("matches_original") is True
                for v in provenance.values())
    )


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--report", type=Path, required=True)
    for arg in ("wine", "prefix", "managed"):
        p.add_argument("--" + arg, type=Path)
    a = p.parse_args()
    if a.report.stat().st_size > 65536 or not ready(json.loads(a.report.read_text(encoding="ascii"))):
        print("SOLIDWORKS native framework prerequisite: NOT_READY")
        return 1
    if any((a.wine, a.prefix, a.managed)):
        if not all((a.wine, a.prefix, a.managed)):
            p.error("All live verification paths are required")
        validate_prefix(a.prefix)
        runner = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
        if (a.prefix.is_symlink() or a.prefix.resolve() != runner / "netfx40-msxml3-prefix"
                or a.managed.is_symlink() or a.managed.name != "netfx481_runtime_probe.exe"):
            p.error("Unexpected private native framework verification paths")
        members = inventory(runner / "netfx481-ipd-stage")
        if len(members) != EXPECTED_COUNT or digest_tree(members) != EXPECTED_TREE_SHA256:
            raise ValueError("Unauthenticated stage")
        provenance = verified_runtime_payloads(members, snapshot(a.prefix))
        # Recheck original GAC bytes after restart and before each licensed launch.
        # A historical successful Fusion HRESULT is not live cache evidence.
        entries = registration_sources(members)
        if (len(cached_sources(a.prefix, entries)) != 274
                or not all(item["matches_original"] for item in provenance.values())):
            print("SOLIDWORKS live original payload prerequisite: NOT_READY")
            return 1
        if not runtime_ready(
                probe(a.wine.resolve(strict=True), a.prefix.resolve(strict=True),
                      a.managed.resolve(strict=True), override="native_only")):
            print("SOLIDWORKS live native framework prerequisite: NOT_READY")
            return 1
    print("SOLIDWORKS native framework prerequisite: READY")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
