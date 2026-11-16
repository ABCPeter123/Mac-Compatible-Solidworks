"""Read only Wine OS compatibility probes, then publish finite categories.

Windows 10 manifest is attached only to our self-authored probe.
This does not patch or impersonate a Microsoft .NET installer.
"""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
from scripts.netfx481_trial import validate_prefix

CATEGORIES = {"WIN10_SUPPORTED", "WIN11_SUPPORTED", "WIN10_TOO_OLD",
              "BELOW_WIN10", "NOT_VERIFIED"}
ARCH = {"AMD64", "X86", "ARM64", "UNKNOWN"}
SERVICE_PACK = {"NOT_VERIFIED", "NOT_WIN7", "MISSING_SP1", "SP1_OR_LATER"}
FIELDS = {"SCHEMA", "WINAPI", "NTDLL", "REGISTRY", "ARCH",
          "SP_API", "SP_NTDLL"}
RE = re.compile(r"^SWCOMPAT_OS_([A-Z_]+)=([A-Z0-9_]+)$")


def decode(raw: bytes, rc: int) -> dict:
    empty = {"status": "INVALID", "winapi": "NOT_VERIFIED",
             "ntdll": "NOT_VERIFIED", "registry": "NOT_VERIFIED", "arch": "UNKNOWN",
             "sp_api": "NOT_VERIFIED", "sp_ntdll": "NOT_VERIFIED"}
    if rc != 0 or len(raw) > 2048 or b"\x00" in raw:
        return empty
    try:
        lines = raw.decode("ascii").splitlines()
    except UnicodeDecodeError:
        return empty
    values = {}
    for line in lines:
        m = RE.fullmatch(line.strip())
        if m:
            if m[1] in values:
                return empty
            values[m[1]] = m[2]
        elif line.startswith("SWCOMPAT_OS_"):
            return empty
    if set(values) != FIELDS or values["SCHEMA"] != "1":
        return empty
    if (any(values[x] not in CATEGORIES for x in ("WINAPI", "NTDLL", "REGISTRY"))
            or values["ARCH"] not in ARCH
            or any(values[k] not in SERVICE_PACK for k in ("SP_API", "SP_NTDLL"))):
        return empty
    return {"status": "MEASURED", "winapi": values["WINAPI"],
            "ntdll": values["NTDLL"], "registry": values["REGISTRY"],
            "arch": values["ARCH"],
            "sp_api": values["SP_API"], "sp_ntdll": values["SP_NTDLL"]}


def verify(result: dict) -> bool:
    if type(result) is not dict or set(result) != set(decode(b"", 1)):
        return False
    return (result["status"] in {"MEASURED", "INVALID"}
            and all(result[k] in CATEGORIES for k in ("winapi", "ntdll", "registry"))
            and result["arch"] in ARCH
            and result["sp_api"] in SERVICE_PACK
            and result["sp_ntdll"] in SERVICE_PACK
            and (result["status"] == "MEASURED"
                 or result == decode(b"", 1)))


def run(wine: Path, prefix: Path, bare: Path, manifested: Path) -> dict:
    if os.name == "nt" or any(p.is_symlink() for p in (wine, prefix, bare, manifested)):
        raise ValueError("Only real isolated Wine prefixes are supported")
    wine, prefix, bare, manifested = (
        p.resolve(strict=True) for p in (wine, prefix, bare, manifested))
    validate_prefix(prefix)
    if (not wine.is_file() or not os.access(wine, os.X_OK)
            or bare.name != "winver_481_bare.exe"
            or manifested.name != "winver_481_supported.exe"):
        raise ValueError("Invalid signed-reference test harness")
    env = os.environ.copy()
    env.pop("WINEDLLOVERRIDES", None)
    env.update({"WINEPREFIX": str(prefix), "WINEARCH": "win64", "WINEDEBUG": "-all"})
    outcome = {}
    for key, path in (("bare", bare), ("manifested", manifested)):
        try:
            completed = subprocess.run([str(wine), str(path)],
                                       cwd=prefix, env=env,
                                       stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                       stdin=subprocess.DEVNULL, timeout=35, check=False)
            outcome[key] = decode(completed.stdout[:2049], completed.returncode)
        except (OSError, subprocess.TimeoutExpired):
            outcome[key] = decode(b"", 1)
    return outcome


def main() -> int:
    p = argparse.ArgumentParser(description="Manifest-sensitive Windows version experiment")
    for arg in ("wine", "prefix", "bare", "manifested", "output"):
        p.add_argument("--" + arg, type=Path, required=True)
    p.add_argument("--agree-disposable-prefix", action="store_true", required=True)
    args = p.parse_args()
    report = run(args.wine, args.prefix, args.bare, args.manifested)
    assert set(report) == {"bare", "manifested"}
    assert all(verify(v) for v in report.values())
    if args.output.is_symlink():
        raise ValueError("Linked output")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, sort_keys=True), encoding="ascii")
    for k in ("bare", "manifested"):
        print("Wine version check", k, report[k])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
