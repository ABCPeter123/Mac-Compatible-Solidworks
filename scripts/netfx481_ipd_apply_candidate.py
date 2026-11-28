"""Host-side guarded execution and verification for the separate IPD candidate.

No automatic enabling: the caller must supply a verified package-local
preflight report and opt in on a fresh, authenticated CLR4 CI prefix.
An experimental transaction success is not proof of installed .NET 4.8.1.
"""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path, PureWindowsPath
import re
import subprocess
import tempfile

from scripts.netfx481_catalog_wusa import verify_package
from scripts.netfx481_ipd_stage import inventory, digest_tree, digest_file
from scripts.netfx481_native_delta_gate import EXPECTED_COUNT, EXPECTED_TREE_SHA256
from scripts.netfx481_trial import validate_prefix, probe, wineboot_restart, parse_probe, MAX_PROBE_OUTPUT, NETFX_FULL_KEY
from scripts.netfx40_msxml3_restart import validate as valid_native40
from scripts.netfx481_payload_audit import snapshot, compare, pe_type, ITEMS, MIN_BYTES, MAX_BYTES
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
        rb"SWCOMPAT_IPD_APPLY_SCHEMA=3\r?\nSWCOMPAT_IPD_APPLY_STARTED=([01])\r?\n"
        rb"SWCOMPAT_IPD_APPLY_COMPLETED=([01])\r?\n"
        rb"SWCOMPAT_IPD_APPLY_PHASE=([0-4])\r?\n"
        rb"SWCOMPAT_IPD_APPLY_WIN32=([0-9A-F]{8})\r?\n"
        rb"SWCOMPAT_IPD_APPLY_FILES=([0-9]{1,7})\r?\n"
        rb"SWCOMPAT_IPD_APPLY_DEFERRED=([0-9]{1,7})\r?\n"
        rb"SWCOMPAT_IPD_APPLY_KEYS=([0-9]{1,7})\r?\n"
        rb"SWCOMPAT_IPD_APPLY_VALUES=([0-9]{1,7})\r?\n"
        rb"SWCOMPAT_IPD_APPLY_ASSEMBLIES=([0-9]{1,7})\r?\n", raw)
    if not match:
        raise ValueError("Missing apply result")
    started, completed = (v == b"1" for v in match.groups()[:2])
    phase = ("NONE", "CREATE_PARENT", "COPY_FILE", "CREATE_REGISTRY_KEY", "SET_REGISTRY_VALUE")[int(match[3])]
    counts = dict(zip(("files", "deferred", "keys", "values", "assemblies"), map(int, match.groups()[4:])))
    error = match[4].decode("ascii")
    if any(v > 1000000 for v in counts.values()) or counts["deferred"] > 1044:
        raise ValueError("Write count out of range")
    if (not started and (phase != "NONE" or error != "00000000" or any(counts.values()))
            or completed and (phase != "NONE" or error != "00000000")
            or phase == "NONE" and error != "00000000"):
        raise ValueError("Inconsistent write observation")
    if completed and not started or (code == 0) != completed:
        raise ValueError("Inconsistent apply result")
    # The candidate prints the original strict dry-run result, not an
    # installation success disguised as strict compatibility.
    preflight = parse_packet(raw[match.end():], 1)
    if completed and not preflight_ready(preflight):
        raise ValueError("Missing package-local apply invariants")
    return {"started": started, "completed": completed, "preflight": preflight,
            "writes": {"first_failure_phase": phase, "win32_error": error, **counts}}


def verified_runtime_payloads(members: dict[str, Path], after: dict) -> dict:
    """Require post-restart files to be byte-identical to a genuine staged PE.

    The enclosing caller must have verified the complete pinned stage first.
    Only match booleans and candidate counts leave this function.
    """
    result = {}
    for key, parts in ITEMS.items():
        machine = "PE_AMD64" if key.endswith("64") else "PE_I386"
        basename = parts[-1].casefold()
        state, digest = after[key]
        hashes = set()
        for name, path in members.items():
            if name.rsplit("/", 1)[-1] != basename:
                continue
            if path.is_symlink() or not path.is_file():
                raise ValueError("Unsafe original runtime payload")
            if not MIN_BYTES <= path.stat().st_size <= MAX_BYTES:
                continue
            with path.open("rb") as f:
                if pe_type(f.read(8192)) != machine:
                    continue
            hashes.add(digest_file(path).hex())
        result[key] = {"candidates": len(hashes),
                       "matches_original": state == machine and digest in hashes}
    return result


def private_windows_path(raw: str, prefix: Path) -> Path:
    """Resolve only canonical local C: targets with no linked components."""
    path = PureWindowsPath(raw)
    if path.drive.casefold() != "c:" or not path.is_absolute() or len(path.parts) < 2:
        raise ValueError("Nonlocal deferred target")
    parts = path.parts[1:]
    if any(p in (".", "..") or p.endswith((".", " ")) or any(c in p for c in ':*?"<>|') for p in parts):
        raise ValueError("Unsafe deferred target")
    target = prefix / "drive_c"
    for part in parts:
        target = target / part
        if target.is_symlink():
            raise ValueError("Linked deferred target")
    if not target.resolve().is_relative_to((prefix / "drive_c").resolve()):
        raise ValueError("Deferred target escaped prefix")
    return target


def deferred_journal(prefix: Path, stage: Path, members: dict[str, Path], count: int) -> list:
    """Authenticate all queued source bytes and private reboot destinations.

    Read this only after a completed transaction and before reboot. Journal
    paths and hashes never leave the runner.
    """
    root = prefix / "drive_c" / "swcompat-ipd-pending"
    journal = root / "queue.bin"
    if root.is_symlink() or not root.is_dir():
        raise ValueError("Invalid private pending directory")
    if not count:
        if any(root.iterdir()):
            raise ValueError("Unexpected pending files")
        return []
    if not 1 <= count <= 1044 or journal.is_symlink() or not journal.is_file():
        raise ValueError("Missing private deferred journal")
    if journal.stat().st_size > 4 * 1024 * 1024:
        raise ValueError("Oversized deferred journal")
    data = journal.read_bytes().decode("utf-16-le").split("\0")
    if len(data) != count * 3 + 1 or data[-1]:
        raise ValueError("Invalid deferred journal length")
    result = []
    used = set()
    temps = set()
    stage_root = windows_path(stage).rstrip("\\").casefold() + "\\"
    for i in range(count):
        source, dest, temporary = data[i * 3:i * 3 + 3]
        if not source.casefold().startswith(stage_root):
            raise ValueError("Deferred source outside authenticated stage")
        key = source[len(stage_root):].replace("\\", "/").casefold()
        if key not in members:
            raise ValueError("Unknown deferred source")
        target = private_windows_path(dest, prefix)
        temp = private_windows_path(temporary, prefix)
        if (target.is_relative_to(root) or target in used or temp in temps
                or temp.parent != root or not re.fullmatch(r"ipd[0-9a-f]+\.tmp", temp.name, re.I)
                or not temp.is_file() or temp.is_symlink()):
            raise ValueError("Unsafe or duplicate deferred replacement")
        expected = digest_file(members[key])
        if digest_file(temp) != expected:
            raise ValueError("Deferred bytes differ from original payload")
        used.add(target)
        temps.add(temp)
        result.append((target, temp, expected))
    if set(root.iterdir()) != temps | {journal}:
        raise ValueError("Untracked private deferred files")
    return result


def deferred_status(queue: list) -> dict:
    """Distinguish an unconsumed queue from a consumed but incorrect target."""
    counts = dict.fromkeys(("verified", "pending", "pending_target_matches",
                            "consumed_target_mismatch", "missing_target", "unsafe"), 0)
    # Known framework names only, no arbitrary paths or private file names.
    classes = dict.fromkeys(("clr", "mscorlib", "mscoree", "fusion", "msxml",
                             "ngen", "other"), 0)
    for target, temp, expected in queue:
        if target.is_symlink() or temp.is_symlink():
            counts["unsafe"] += 1
            continue
        match = target.is_file() and digest_file(target) == expected
        if temp.exists():
            counts["pending_target_matches" if match else "pending"] += 1
        elif match:
            counts["verified"] += 1
            continue
        elif not target.is_file():
            counts["missing_target"] += 1
        else:
            counts["consumed_target_mismatch"] += 1
        name = target.name.casefold()
        stem = target.stem.casefold()
        kind = stem if stem in {"clr", "mscorlib", "mscoree", "fusion", "ngen"} else (
            "msxml" if name.startswith("msxml") and name.endswith(".dll") else "other")
        classes[kind] += 1
    return {"counts": counts, "failed_classes": classes}


def verify_deferred(queue: list) -> bool:
    return deferred_status(queue)["counts"]["verified"] == len(queue)


def managed_failure_controls(wine: Path, prefix: Path, managed: Path) -> dict:
    """Measure independent release registration and native host activation.

    Native-image suppression is a process-only diagnostic; never use the
    differential to promote framework481_confirmed.
    """
    env = os.environ.copy()
    env.update(WINEPREFIX=str(prefix), WINEARCH="win64", WINEDEBUG="-all")
    env.pop("WINEDLLOVERRIDES", None)
    env.pop("COMPlus_ZapDisable", None)
    result = {}
    for view in ("64", "32"):
        try:
            with tempfile.TemporaryFile() as out:
                proc = subprocess.run([str(wine), "reg.exe", "query", NETFX_FULL_KEY,
                                       "/v", "Release", "/reg:" + view],
                                      env=env, cwd=prefix, stdin=subprocess.DEVNULL,
                                      stdout=out, stderr=subprocess.DEVNULL,
                                      timeout=30, check=False)
                out.seek(0)
                raw = out.read(4097)
            matches = re.findall(rb"(?im)^\s*Release\s+REG_DWORD\s+0x([0-9a-f]{1,8})\s*$", raw)
            result["registry" + view] = (
                "AT_LEAST_481" if int(matches[0], 16) >= 533320 else "BELOW_481"
            ) if proc.returncode == 0 and len(raw) <= 4096 and len(matches) == 1 else "NOT_VERIFIED"
        except (OSError, subprocess.TimeoutExpired):
            result["registry" + view] = "NOT_VERIFIED"
    fixture = managed.with_name("netfx48_host_activation.exe")
    dll = managed.with_name("netfx48_managed_host_check.dll")
    if (fixture.is_file() and dll.is_file() and not fixture.is_symlink()
            and not dll.is_symlink() and not fixture.resolve().is_relative_to(prefix)
            and not dll.resolve().is_relative_to(prefix)):
        from scripts.netfx40_host_api_diagnostic import execute
        result["native_host"] = execute(wine, prefix, fixture, dll, "n")
        result["native_host_il_only"] = execute(wine, prefix, fixture, dll, "n", disable_native_images=True)
    else:
        result["native_host"] = result["native_host_il_only"] = "NOT_RUN"
    # Check actual CLR4 managed executable entry as well as native hosting.
    env.update(WINEDLLOVERRIDES="mscoree=n;clr=n", COMPlus_ZapDisable="1")
    try:
        with tempfile.TemporaryFile() as out:
            proc = subprocess.run([str(wine), str(managed)], env=env, cwd=managed.parent,
                                  stdin=subprocess.DEVNULL, stdout=out,
                                  stderr=subprocess.STDOUT, timeout=75, check=False)
            out.seek(0)
            raw = out.read(MAX_PROBE_OUTPUT + 1)
        result["managed_il_only"] = parse_probe(raw, proc.returncode)
    except (OSError, subprocess.TimeoutExpired):
        result["managed_il_only"] = parse_probe(b"", 124)
    return result


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
    # Stop the exact marked private session after baseline verification.
    # Old CLR/NGen processes must not retain file locks across servicing.
    if not _terminate_private_setup_wineserver(wine, prefix):
        result["transaction"] = "BLOCKED_SESSION_CLEANUP"
        return result
    result["session_quiesced"] = True
    if snapshot(prefix) != before:
        result["transaction"] = "BASELINE_CHANGED_DURING_CLEANUP"
        return result
    pending = prefix / "drive_c" / "swcompat-ipd-pending"
    if pending.exists() or pending.is_symlink():
        raise ValueError("Pending directory must be fresh")
    pending.mkdir(mode=0o700)
    env = os.environ.copy()
    env.update(WINEPREFIX=str(prefix), WINEARCH="win64", WINEDEBUG="-all")
    # WUSA's CLSID_DOMDocument parser passed in clean Wine. Winetricks
    # installs a native MSXML3 override into the persistent CLR4 prefix.
    # Isolate WUSA's COM parser without changing the prefix's overrides
    # or the independently measured native CLR baseline.
    env["WINEDLLOVERRIDES"] = "msxml,msxml2,msxml3,msxml4,msxml6=b"
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
    result["writes"] = packet["writes"]
    result["apply_events"] = packet["preflight"]["events"]
    if not packet["completed"]:
        result["partial_payload"] = compare(before, snapshot(prefix))
        return result
    try:
        queue = deferred_journal(prefix, stage, members, packet["writes"]["deferred"])
    except (ValueError, OSError, UnicodeError):
        result["transaction"] = "DEFERRED_JOURNAL_REJECTED"
        return result
    # A queued rename is not an installed file. Require reboot to apply it.
    result["deferred_verified"] = False
    # Wine's restart-only path does not kill processes. Stop the whole
    # marked private session before boot so COM servers and framework
    # services cannot hold the eight deferred targets open.
    result["pre_restart_quiesced"] = _terminate_private_setup_wineserver(wine, prefix)
    if not result["pre_restart_quiesced"]:
        result["restart"] = "BLOCKED_SESSION_CLEANUP"
        return result
    # The new session may process pending renames as part of startup;
    # preserve exact measurements regardless of wineboot's return code.
    result["restart"] = wineboot_restart(wine, prefix, timeout=120)
    if result["restart"] != "COMPLETED":
        return result
    result["deferred_status"] = deferred_status(queue)
    result["deferred_verified"] = verify_deferred(queue)
    after = snapshot(prefix)
    payload = compare(before, after)
    provenance = verified_runtime_payloads(members, after)
    measured = probe(wine, prefix, managed, override="native_only")
    loaded = load_clr(wine, prefix, loader)
    result.update(payload=payload, original_runtime_payloads=provenance,
                  loader=loaded, registry=measured["registry"],
                  runtime_family=measured["clr_family"], managed=measured["managed"])
    # A working minimal managed probe does not establish complete GAC servicing.
    # Always measure and finish the original GAC directives on a verified transaction.
    if result["deferred_verified"]:
        from scripts.netfx481_ipd_gac import register, registration_complete
        gac_fixture = runner / "swcompat-netfx481-ipd-gac.exe"
        if gac_fixture.is_file() and not gac_fixture.is_symlink():
            try:
                result["gac_registration"] = register(wine, prefix, gac_fixture, members)
            except (ValueError, OSError, UnicodeError):
                result["gac_registration"] = {"transport": "REJECTED"}
            if (result["gac_registration"].get("attempted", 0)
                    or registration_complete(result["gac_registration"])):
                result["pre_gac_managed"] = measured["managed"]
                result["gac_restart"] = (
                    wineboot_restart(wine, prefix, timeout=120)
                    if _terminate_private_setup_wineserver(wine, prefix)
                    else "BLOCKED_SESSION_CLEANUP")
                if result["gac_restart"] == "COMPLETED":
                    after = snapshot(prefix)
                    payload = compare(before, after)
                    provenance = verified_runtime_payloads(members, after)
                    measured = probe(wine, prefix, managed, override="native_only")
                    loaded = load_clr(wine, prefix, loader)
                    result["deferred_verified"] = verify_deferred(queue)
                    result.update(payload=payload, original_runtime_payloads=provenance,
                                  loader=loaded, registry=measured["registry"],
                                  runtime_family=measured["clr_family"], managed=measured["managed"])
    if measured["managed"] != "PASS":
        result["managed_failure_controls"] = managed_failure_controls(wine, prefix, managed)
    result["framework481_confirmed"] = (
        result["deferred_verified"] and payload["status"] == "MEASURED"
        and payload["changes"]["CLR64"] == "CHANGED"
        and provenance["CLR64"]["matches_original"] and provenance["MSCORLIB64"]["matches_original"]
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
