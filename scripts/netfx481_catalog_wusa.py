"""Independent genuine Microsoft KB5011048 MSU transaction through Wine WUSA.

Only an unmodified, catalog-pinned update is permitted. No CAB members are
copied into Windows directories by this harness; Wine's installer performs
the transaction. Never publish private logs or vendor files.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil

from scripts.netfx40_legacy import _terminate_private_setup_wineserver
from scripts.netfx40_msxml3_restart import validate as valid_native40
from scripts.netfx40_to_48_signed_msi import private_run
from scripts.netfx481_trial import validate_prefix, wineboot_restart, probe
from scripts.netfx481_clr_load import run as load_clr, STATUSES as LOAD_STATES
from scripts.netfx481_payload_audit import snapshot, compare, blank as blank_payload, validate as valid_payload

PACKAGE = "KB5011048.msu"
SHA1 = "411d40ab5705c99f2bdb576ad3dc3e6ec0f3902e"
SIZE = 71059034
TARGET = "swcompat-netfx481-catalog"
FIXTURE = "netfx481_catalog_wusa.exe"
OUTCOMES = {"NOT_RUN", "START_FAILED", "EXIT_NONZERO", "BAD_PACKET",
            "EXIT_CAPTURED", "TIMED_OUT_PREFIX_REAPED", "TIMED_OUT_CLEANUP_DENIED"}
RESTARTS = {"NOT_RUN", "COMPLETED", "TIMED_OUT", "START_FAILED", "EXIT_NONZERO"}


def verify_package(package: Path, manifest: Path) -> None:
    if (package.is_symlink() or manifest.is_symlink() or package.name != PACKAGE
            or not package.is_file() or not manifest.is_file()
            or package.stat().st_size != SIZE):
        raise ValueError("Unexpected original catalog package")
    expected = manifest.read_text(encoding="ascii").strip().lower()
    if not re.fullmatch(r"[0-9a-f]{64}", expected):
        raise ValueError("Invalid catalog digest")
    sha1, sha256 = hashlib.sha1(), hashlib.sha256()
    with package.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            sha1.update(block)
            sha256.update(block)
    if sha1.hexdigest() != SHA1 or sha256.hexdigest() != expected:
        raise ValueError("Original catalog package digest mismatch")


def parse_packet(raw: bytes, selftest: bool = False) -> str | None:
    if len(raw) > 256:
        return None
    try:
        text = raw.decode("ascii")
    except UnicodeError:
        return None
    m = re.fullmatch(
        r"SWCOMPAT_WUSA_SCHEMA=1\r?\nSWCOMPAT_WUSA_STATUS=(EXIT|SELFTEST)\r?\n"
        r"SWCOMPAT_WUSA_EXIT=([0-9A-F]{8})\r?\n", text)
    if not m or m[1] != ("SELFTEST" if selftest else "EXIT"):
        return None
    if selftest and m[2] != "00000BC2":
        return None
    return m[2]


def blank() -> dict:
    return {"original_package_verified": False, "native40_persistent": False,
            "wusa": "NOT_RUN", "exit_hex": "NOT_CAPTURED",
            "restart": "NOT_RUN", "payload": blank_payload(),
            "loader": "NOT_VERIFIED", "registry": "NOT_VERIFIED",
            "runtime_family": "NOT_VERIFIED", "native_only_managed": "NOT_VERIFIED",
            "framework481_confirmed": False,
            "solidworks_compatibility": "NOT_DEMONSTRATED"}


def ready(r: dict) -> bool:
    p = r["payload"]
    return (r["original_package_verified"] and r["native40_persistent"]
            and r["wusa"] == "EXIT_CAPTURED"
            and r["exit_hex"] in {"00000000", "00000BC2"}
            and r["restart"] == "COMPLETED"
            and p["status"] == "MEASURED"
            and p["before"]["CLR64"] == "PE_AMD64"
            and p["changes"]["CLR64"] == "CHANGED"
            and p["after"]["CLR64"] == p["after"]["MSCORLIB64"] == "PE_AMD64"
            and r["loader"] == "LOADED" and r["registry"] == "AT_LEAST_481"
            and r["runtime_family"] == "MICROSOFT_CLR_CANDIDATE"
            and r["native_only_managed"] == "PASS")


def valid(r: object) -> bool:
    if type(r) is not dict or set(r) != set(blank()):
        return False
    if (any(type(r[k]) is not bool for k in ("original_package_verified", "native40_persistent", "framework481_confirmed"))
            or r["wusa"] not in OUTCOMES or r["restart"] not in RESTARTS
            or not valid_payload(r["payload"])
            or r["loader"] not in LOAD_STATES
            or r["registry"] not in {"NOT_VERIFIED", "NOT_FOUND", "AT_LEAST_481", "BELOW_481", "UNAVAILABLE"}
            or r["runtime_family"] not in {"NOT_VERIFIED", "UNKNOWN", "MONO", "MICROSOFT_CLR_CANDIDATE"}
            or r["native_only_managed"] not in {"NOT_VERIFIED", "PASS", "FAIL"}
            or r["solidworks_compatibility"] != "NOT_DEMONSTRATED"
            or type(r["exit_hex"]) is not str):
        return False
    if r["wusa"] == "EXIT_CAPTURED":
        if not re.fullmatch(r"[0-9A-F]{8}", r["exit_hex"]):
            return False
    elif r["exit_hex"] != "NOT_CAPTURED":
        return False
    if r["wusa"] != "NOT_RUN" and not (r["native40_persistent"] and r["original_package_verified"]):
        return False
    if r["restart"] != "NOT_RUN" and (r["wusa"] != "EXIT_CAPTURED" or r["exit_hex"] not in {"00000000", "00000BC2"}):
        return False
    if r["restart"] != "COMPLETED" and r["payload"] != blank_payload():
        return False
    return r["framework481_confirmed"] is bool(ready(r))


def inspect(wine: Path, prefix: Path, package: Path, manifest: Path,
            fixture: Path, loader: Path, managed: Path, baseline: dict) -> dict:
    if os.name == "nt" or any(p.is_symlink() for p in (wine, prefix, package, manifest, fixture, loader, managed)):
        raise ValueError("Only isolated Wine catalog experiment")
    wine, prefix, package, manifest, fixture, loader, managed = (
        p.resolve(strict=True) for p in (wine, prefix, package, manifest, fixture, loader, managed))
    validate_prefix(prefix)
    runner = os.environ.get("RUNNER_TEMP")
    if not runner or prefix.parent != Path(runner).resolve() or prefix.name != "netfx40-msxml3-prefix":
        raise ValueError("Catalog servicing requires the marked ephemeral CI prefix")
    if (fixture.name != FIXTURE or loader.name != "netfx481_clr_load.exe"
            or managed.name != "netfx481_runtime_probe.exe"):
        raise ValueError("Unexpected self-authored fixture")
    verify_package(package, manifest)
    r = blank()
    r["original_package_verified"] = True
    if not valid_native40(baseline) or not baseline["persistent_native_managed"]:
        return r
    before = snapshot(prefix)
    initial = probe(wine, prefix, managed, override="native_only")
    if (before["CLR64"][0] != "PE_AMD64" or load_clr(wine, prefix, loader) != "LOADED"
            or initial["managed"] != "PASS" or initial["clr_family"] != "MICROSOFT_CLR_CANDIDATE"
            or initial["registry"] == "AT_LEAST_481"):
        return r
    r["native40_persistent"] = True
    env = os.environ.copy()
    env.update(WINEPREFIX=str(prefix), WINEARCH="win64", WINEDEBUG="-all")
    env.pop("WINEDLLOVERRIDES", None)
    packets = []
    outcome = private_run([str(wine), str(fixture), "--selftest"], env, prefix, 30,
                          on_diagnostic=packets.append)
    if outcome != "SUCCESS" or not packets or parse_packet(packets[-1], selftest=True) != "00000BC2":
        r["wusa"] = "BAD_PACKET"
        return r
    target = prefix / "drive_c" / TARGET
    if (prefix / "drive_c").is_symlink() or target.exists() or target.is_symlink():
        raise ValueError("Unsafe catalog staging directory")
    target.mkdir(mode=0o700)
    shutil.copyfile(package, target / PACKAGE)
    verify_package(target / PACKAGE, manifest)
    packets.clear()
    outcome = private_run([str(wine), str(fixture), "--apply-catalog-481"], env, prefix, 600,
                          on_diagnostic=packets.append)
    if outcome.startswith("TIMED_OUT"):
        reaped = _terminate_private_setup_wineserver(wine, prefix)
        r["wusa"] = "TIMED_OUT_PREFIX_REAPED" if reaped else "TIMED_OUT_CLEANUP_DENIED"
        return r
    if outcome != "SUCCESS":
        r["wusa"] = outcome if outcome in OUTCOMES else "BAD_PACKET"
        return r
    exit_hex = parse_packet(packets[-1]) if packets else None
    if exit_hex is None:
        r["wusa"] = "BAD_PACKET"
        return r
    r.update(wusa="EXIT_CAPTURED", exit_hex=exit_hex)
    if exit_hex not in {"00000000", "00000BC2"}:
        return r
    r["restart"] = wineboot_restart(wine, prefix, timeout=120)
    if r["restart"] == "COMPLETED":
        r["payload"] = compare(before, snapshot(prefix))
        measured = probe(wine, prefix, managed, override="native_only")
        r.update(loader=load_clr(wine, prefix, loader), registry=measured["registry"],
                 runtime_family=measured["clr_family"], native_only_managed=measured["managed"])
    r["framework481_confirmed"] = bool(ready(r))
    return r


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    for key in ("wine", "prefix", "package", "sha256-file", "fixture", "loader",
                "managed", "native40-report", "output"):
        p.add_argument("--" + key, required=True, type=Path)
    a = p.parse_args()
    if a.output.is_symlink() or a.output.resolve().is_relative_to(a.prefix.resolve()):
        p.error("Report must remain outside disposable Wine prefix")
    r = inspect(a.wine, a.prefix, a.package, a.sha256_file, a.fixture, a.loader,
                a.managed, json.loads(a.native40_report.read_text(encoding="ascii")))
    if not valid(r):
        raise ValueError("Invalid catalog servicing report")
    a.output.write_text(json.dumps(r, sort_keys=True), encoding="ascii")
    for key in ("wusa", "exit_hex", "restart", "loader", "registry", "runtime_family",
                "native_only_managed", "framework481_confirmed"):
        print("Original KB5011048", key, r[key])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
