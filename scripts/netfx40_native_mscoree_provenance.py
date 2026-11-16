"""Classify genuine .NET 4.0 hosting DLL provenance in a verified Wine prefix.

Run only after the original Microsoft .NET 4.0 native managed probe passed
AND survived Wine restart. The Wine +loaddll stream is kept only in a private
temporary file. The exported result uses fixed statuses, never vendor bytes,
paths, hashes, original logs or registry contents. No installation or edits.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

from scripts.netfx40_msxml3_restart import validate as validate_native40
from scripts.netfx481_trial import validate_prefix, parse_probe

MAX_OUTPUT = 8 * 1024 * 1024
MAX_LINES = 100000
SOURCES = {"NOT_RUN", "NATIVE_ONLY", "BUILTIN_ONLY", "MIXED", "NOT_OBSERVED", "TOO_LARGE"}
PROCESSES = {"NOT_RUN", "EXIT_ZERO", "EXIT_NONZERO", "SPAWN_ERROR", "TIMEOUT"}
STATES = {"NOT_ELIGIBLE", "MEASURED"}
LOADED = re.compile(
    r'\bLoaded\s+L?"([^"\r\n]{1,1024})"\s+at\s+0x?[0-9a-fA-F]+:\s+(native|builtin)\b',
    re.IGNORECASE,
)
FIELDS = {"mscoree.dll": "mscoree", "clr.dll": "clr"}


def blank() -> dict:
    return {
        "status": "NOT_ELIGIBLE", "process": "NOT_RUN",
        "native40_persistent": False,
        "mscoree": "NOT_RUN", "clr": "NOT_RUN",
        "managed": "NOT_VERIFIED", "family": "NOT_VERIFIED",
        "native_host_confirmed": False,
        "framework48_installed": False,
    }


def valid(report: object) -> bool:
    if type(report) is not dict or set(report) != set(blank()):
        return False
    if (report["status"] not in STATES or report["process"] not in PROCESSES
            or report["mscoree"] not in SOURCES or report["clr"] not in SOURCES
            or report["managed"] not in {"NOT_VERIFIED", "PASS", "FAIL"}
            or report["family"] not in {
                "NOT_VERIFIED", "MONO", "MICROSOFT_CLR_CANDIDATE", "UNKNOWN"}
            or type(report["native40_persistent"]) is not bool
            or type(report["native_host_confirmed"]) is not bool
            or report["framework48_installed"] is not False):
        return False
    if report["status"] == "NOT_ELIGIBLE":
        return report == blank()
    if not report["native40_persistent"] or report["process"] == "NOT_RUN":
        return False
    expected = (report["mscoree"] == "NATIVE_ONLY"
                and report["clr"] == "NATIVE_ONLY"
                and report["managed"] == "PASS"
                and report["family"] == "MICROSOFT_CLR_CANDIDATE"
                and report["process"] == "EXIT_ZERO")
    return report["native_host_confirmed"] == expected


def classify_loads(raw: bytes) -> dict[str, str]:
    if len(raw) > MAX_OUTPUT:
        return {"mscoree": "TOO_LARGE", "clr": "TOO_LARGE"}
    try:
        lines = raw.decode("utf-8", errors="replace").splitlines()
    except (ValueError, TypeError):
        return {"mscoree": "NOT_OBSERVED", "clr": "NOT_OBSERVED"}
    if len(lines) > MAX_LINES:
        return {"mscoree": "TOO_LARGE", "clr": "TOO_LARGE"}
    found: dict[str, set[str]] = {"mscoree": set(), "clr": set()}
    for line in lines:
        if ":loaddll:" not in line.casefold():
            continue
        match = LOADED.search(line)
        if match is None:
            continue
        # Never return or print the private loader path.
        base = match.group(1).replace("/", "\\").rsplit("\\", 1)[-1].casefold()
        field = FIELDS.get(base)
        if field is not None:
            found[field].add(match.group(2).upper())
    out = {}
    for key, sources in found.items():
        out[key] = ("NOT_OBSERVED" if not sources else
                    "NATIVE_ONLY" if sources == {"NATIVE"} else
                    "BUILTIN_ONLY" if sources == {"BUILTIN"} else "MIXED")
    return out


def managed_only(raw: bytes, code: int) -> dict[str, str]:
    """Pass the independent managed fixture's exact four fields to its parser."""
    if len(raw) > MAX_OUTPUT:
        return {"clr_family": "NOT_VERIFIED", "managed": "NOT_VERIFIED"}
    probe_lines = []
    for line in raw.splitlines():
        if line.startswith(b"SWCOMPAT_NETFX481_"):
            probe_lines.append(line)
    if len(probe_lines) != 4:
        return {"clr_family": "NOT_VERIFIED", "managed": "NOT_VERIFIED"}
    parsed = parse_probe(b"\n".join(probe_lines) + b"\n", code)
    return {"clr_family": parsed["clr_family"], "managed": parsed["managed"]}


def audit(wine: Path, prefix: Path, fixture: Path, native40: dict) -> dict:
    validate_prefix(prefix)
    if not validate_native40(native40):
        raise ValueError("Original native Microsoft 4.0 restart result invalid")
    if (not native40["persistent_native_managed"]
            or native40["native_only_managed"] != "PASS"):
        return blank()
    if (wine.is_symlink() or not wine.is_file() or not os.access(wine, os.X_OK)
            or fixture.is_symlink() or fixture.name != "netfx481_runtime_probe.exe"
            or not fixture.is_file() or
            fixture.resolve().is_relative_to(prefix.resolve())):
        raise ValueError("Unsafe original native hosting provenance inputs")
    prefix = prefix.resolve(strict=True)
    fixture = fixture.resolve(strict=True)
    wine = wine.resolve(strict=True)
    result = blank()
    result.update(status="MEASURED", native40_persistent=True)
    env = os.environ.copy()
    env.pop("WINEDLLOVERRIDES", None)
    env.update({
        "WINEPREFIX": str(prefix), "WINEARCH": "win64",
        "WINEDLLOVERRIDES": "mscoree=n;clr=n",
        "WINEDEBUG": "-all,+loaddll",
    })
    with tempfile.TemporaryFile() as out:
        try:
            proc = subprocess.run(
                [str(wine), str(fixture)], cwd=fixture.parent,
                env=env, stdin=subprocess.DEVNULL,
                stdout=out, stderr=subprocess.STDOUT,
                timeout=85, check=False)
            code = proc.returncode
            result["process"] = "EXIT_ZERO" if code == 0 else "EXIT_NONZERO"
        except subprocess.TimeoutExpired:
            result["process"] = "TIMEOUT"
            code = 124
        except OSError:
            result["process"] = "SPAWN_ERROR"
            code = 124
        out.seek(0)
        raw = out.read(MAX_OUTPUT + 1)
    sources = classify_loads(raw)
    state = managed_only(raw, code)
    result.update(mscoree=sources["mscoree"], clr=sources["clr"],
                  managed=state["managed"], family=state["clr_family"])
    result["native_host_confirmed"] = (
        result["mscoree"] == "NATIVE_ONLY"
        and result["clr"] == "NATIVE_ONLY"
        and result["managed"] == "PASS"
        and result["family"] == "MICROSOFT_CLR_CANDIDATE"
        and result["process"] == "EXIT_ZERO")
    assert valid(result)
    return result


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    for name in ("wine", "prefix", "fixture", "native40_report", "output"):
        ap.add_argument("--" + name.replace("_", "-"), type=Path, required=True)
    ap.add_argument("--agree-disposable-prefix", action="store_true", required=True)
    args = ap.parse_args(argv)
    if (args.output.is_symlink() or args.output.resolve().is_relative_to(
            args.prefix.resolve())):
        ap.error("Report must be outside the marked disposable Wine prefix")
    native40 = json.loads(args.native40_report.read_text(encoding="utf-8"))
    report = audit(args.wine, args.prefix, args.fixture, native40)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, sort_keys=True), encoding="utf-8")
    print("AUTHENTIC_NETFX40_MSCOREE_PROVENANCE",
          report["status"], report["mscoree"], report["clr"],
          report["managed"], report["family"], report["native_host_confirmed"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
