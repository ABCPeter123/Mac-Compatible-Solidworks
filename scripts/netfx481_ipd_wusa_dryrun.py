"""Run the Wine-derived WUSA preflight against the original MSU and verified stage.

This executable has no install mode. Only fixed counters leave the process.
The prefix is disposable; no Microsoft content is uploaded.
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
from scripts.netfx481_trial import validate_prefix

CATEGORIES = ("missing_assembly", "missing_file", "expression", "registry_type",
              "cycle", "no_updates", "extraction", "version_difference",
              "unsupported_manifest", "load_failure", "other")


def parse_packet(raw: bytes, code: int) -> dict:
    if len(raw) > 4096 or code not in (0, 1):
        raise ValueError("Missing WUSA dry-run packet")
    lines = raw.decode("ascii").splitlines()
    packet = {}
    for line in lines:
        m = re.fullmatch(r"SWCOMPAT_IPD_DRYRUN_([A-Z0-9]+)=([A-Z0-9]+)", line)
        if not m or m[1] in packet:
            raise ValueError("Invalid WUSA dry-run packet")
        packet[m[1]] = m[2]
    if set(packet) != {"SCHEMA", "RESULT", "IPD", *(f"C{i}" for i in range(len(CATEGORIES)))}:
        raise ValueError("Incomplete WUSA dry-run packet")
    if packet["SCHEMA"] != "1" or packet["RESULT"] != ("PASS" if code == 0 else "FAIL"):
        raise ValueError("Inconsistent WUSA dry-run result")
    counts = {}
    for key in ("IPD", *(f"C{i}" for i in range(len(CATEGORIES)))):
        if not re.fullmatch(r"[0-9]{1,7}", packet[key]) or int(packet[key]) > 1000000:
            raise ValueError("Invalid dry-run count")
        counts[key] = int(packet[key])
    if counts["IPD"] > 1 or (code == 0 and counts["IPD"] != 1):
        raise ValueError("Invalid IPD substitution count")
    return {"dryrun": packet["RESULT"], "ipd_substitutions": counts["IPD"],
            "events": {name: counts[f"C{i}"] for i, name in enumerate(CATEGORIES)},
            "servicing_performed": False}


def windows_path(path: Path) -> str:
    return "Z:" + str(path.resolve(strict=True)).replace("/", "\\")


def inspect(wine: Path, prefix: Path, fixture: Path, package: Path,
            digest: Path, stage: Path) -> dict:
    runner = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
    if (os.name == "nt" or prefix.is_symlink() or stage.is_symlink()
            or prefix.resolve().parent != runner or prefix.name != "netfx40-msxml3-prefix"
            or stage.resolve().parent != runner or stage.name != "netfx481-ipd-stage"
            or fixture.is_symlink() or fixture.name != "swcompat-wusa-ipd-dryrun.exe"):
        raise ValueError("Only isolated native Mac WUSA experiment")
    validate_prefix(prefix)
    z = prefix / "dosdevices/z:"
    if not z.is_symlink() or z.resolve() != Path("/"):
        raise ValueError("Expected private Wine Z: mapping")
    verify_package(package, digest)
    members = inventory(stage)
    if len(members) != EXPECTED_COUNT or digest_tree(members) != EXPECTED_TREE_SHA256:
        raise ValueError("Unverified staging tree")
    env = os.environ.copy()
    env.update(WINEPREFIX=str(prefix.resolve()), WINEARCH="win64", WINEDEBUG="-all")
    env.pop("WINEDLLOVERRIDES", None)
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        try:
            result = subprocess.run([str(wine.resolve(strict=True)), str(fixture.resolve(strict=True)),
                                     windows_path(package), windows_path(stage)],
                                    env=env, cwd=prefix, stdin=subprocess.DEVNULL,
                                    stdout=out, stderr=err, timeout=180, check=False)
        except (OSError, subprocess.TimeoutExpired):
            return {"dryrun": "PROCESS_FAILED", "ipd_substitutions": 0,
                    "events": {}, "servicing_performed": False}
        out.seek(0)
        try:
            return parse_packet(out.read(4097), result.returncode)
        except (ValueError, UnicodeError):
            return {"dryrun": "BAD_PACKET", "ipd_substitutions": 0,
                    "events": {}, "servicing_performed": False}


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    for name in ("wine", "prefix", "fixture", "package", "sha256-file", "stage", "output"):
        p.add_argument("--" + name, type=Path, required=True)
    a = p.parse_args()
    if a.output.exists() or a.output.is_symlink():
        raise ValueError("Report must be fresh")
    r = inspect(a.wine, a.prefix, a.fixture, a.package, a.sha256_file, a.stage)
    a.output.write_text(json.dumps(r, sort_keys=True), encoding="ascii")
    print("WUSA verified IPD preflight", json.dumps(r, sort_keys=True))
    # A diagnostic failure still produces useful evidence. Do not conflate
    # successful process execution with a successful dependency preflight.
    raise SystemExit(0 if r["dryrun"] in {"PASS", "FAIL"} else 1)
