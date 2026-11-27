"""Bounded dual-architecture native .NET CAD prerequisite matrix.

Each mode executes independently; a GUI subsystem crash cannot hide the
other results. No user data, raw Wine diagnostics or vendor bytes are stored.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

from scripts.netfx481_trial import validate_prefix, NATIVE_DLL_OVERRIDES
from scripts.netfx481_solidworks_gate import ready

MODES = ("core", "winforms", "wpf", "wcf", "com")
BITS = (32, 64)


def parse(raw: bytes, rc: int, mode: str, bits: int) -> dict:
    bad = {"result": "INVALID_OUTPUT", "native": False, "hresult": "NOT_VERIFIED"}
    if mode not in MODES or bits not in BITS or len(raw) > 4096 or rc not in (0, 1):
        return bad
    match = re.fullmatch(
        rb"SWCOMPAT_CAD_SCHEMA=1\r?\nSWCOMPAT_CAD_MODE=([a-z]+)\r?\n"
        rb"SWCOMPAT_CAD_BITS=(32|64)\r?\nSWCOMPAT_CAD_NATIVE=(YES|NO)\r?\n"
        rb"SWCOMPAT_CAD_RESULT=(PASS|FAIL)\r?\nSWCOMPAT_CAD_HRESULT=([0-9A-F]{8})\r?\n",
        raw)
    if not match:
        return bad
    m, b, n, result, error = (x.decode("ascii") for x in match.groups())
    if m != mode or int(b) != bits or (result == "PASS") != (rc == 0):
        return bad
    if result == "PASS" and (n != "YES" or error != "00000000"):
        return bad
    return {"result": result, "native": n == "YES", "hresult": error}


WPF_STAGES = ("DISPATCH", "ENTER", "VISUAL", "DRAWN", "BITMAP", "RENDERED", "COPIED")
MAX_WPF_STDERR = 65536


def wpf_diagnostic(raw: bytes, rc: int | None) -> dict:
    # Exact self-authored markers only. Never return raw stderr or paths.
    result = {"last_stage": "NOT_OBSERVED", "managed_exception": False,
              "inner_hresult": "NOT_VERIFIED", "exit": "NOT_VERIFIED"}
    if rc is not None:
        result["exit"] = ("ZERO" if rc == 0 else "ONE" if rc == 1
                          else "NONZERO" if rc > 0 else "SIGNALLED")
    if len(raw) > MAX_WPF_STDERR:
        result["last_stage"] = "TRUNCATED"
        return result
    seen = []
    exception = False
    inner = None
    for line in raw.splitlines():
        match = re.fullmatch(rb"SWCOMPAT_WPF_STAGE=([A-Z_]+)", line)
        if match:
            stage = match.group(1).decode("ascii")
            if stage == "MANAGED_EXCEPTION" and seen and not exception:
                exception = True
            elif (not exception and len(seen) < len(WPF_STAGES)
                  and stage == WPF_STAGES[len(seen)]):
                seen.append(stage)
            else:
                result["last_stage"] = "INVALID_MARKERS"
                return result
        match = re.fullmatch(rb"SWCOMPAT_WPF_INNER_HRESULT=([0-9A-F]{8})", line)
        if match and exception:
            if inner is not None:
                result["last_stage"] = "INVALID_MARKERS"
                return result
            inner = match.group(1).decode("ascii")
    result.update(last_stage=seen[-1] if seen else "NOT_OBSERVED",
                  managed_exception=exception,
                  inner_hresult=inner or "NOT_VERIFIED")
    return result


def execute(wine: Path, prefix: Path, fixture: Path, mode: str, bits: int,
            *, native_only: bool) -> dict:
    env = os.environ.copy()
    env.pop("WINEDLLOVERRIDES", None)
    env.update(WINEPREFIX=str(prefix), WINEARCH="win64", WINEDEBUG="-all")
    if native_only:
        env["WINEDLLOVERRIDES"] = NATIVE_DLL_OVERRIDES["native_only"]
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        rc = None
        try:
            p = subprocess.run([str(wine), str(fixture), mode], cwd=fixture.parent,
                               env=env, stdin=subprocess.DEVNULL, stdout=out,
                               stderr=err if mode == "wpf" else subprocess.DEVNULL,
                               timeout=35, check=False)
            rc = p.returncode
            out.seek(0)
            result = parse(out.read(4097), rc, mode, bits)
        except subprocess.TimeoutExpired:
            result = {"result": "TIMEOUT", "native": False, "hresult": "NOT_VERIFIED"}
        except OSError:
            result = {"result": "PROCESS_ERROR", "native": False, "hresult": "NOT_VERIFIED"}
        if mode == "wpf":
            err.seek(0)
            result["diagnostic"] = wpf_diagnostic(err.read(MAX_WPF_STDERR + 1), rc)
        return result


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    for key in ("wine", "prefix", "report", "fixture-dir", "output"):
        p.add_argument("--" + key, type=Path, required=True)
    a = p.parse_args()
    validate_prefix(a.prefix)
    runner = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
    if a.prefix.is_symlink() or a.prefix.resolve() != runner / "netfx40-msxml3-prefix":
        raise ValueError("Unexpected private prefix")
    if a.report.stat().st_size > 65536 or not ready(json.loads(a.report.read_text(encoding="ascii"))):
        raise ValueError("Native framework evidence not verified")
    wine = a.wine.resolve(strict=True)
    prefix = a.prefix.resolve(strict=True)
    result = {"schema": 1, "native_only": {}, "default_core": {},
              "solidworks_compatibility": "NOT_DEMONSTRATED"}
    for bits in BITS:
        fixture = a.fixture_dir / ("netfx481_cad_prerequisites_x%d.exe" % (86 if bits == 32 else 64))
        if fixture.is_symlink() or not fixture.is_file():
            raise ValueError("Missing original CAD fixture")
        fixture = fixture.resolve(strict=True)
        if fixture.is_relative_to(prefix):
            raise ValueError("Fixture must be external to prefix")
        key = str(bits)
        result["default_core"][key] = execute(wine, prefix, fixture, "core", bits, native_only=False)
        result["native_only"][key] = {
            mode: execute(wine, prefix, fixture, mode, bits, native_only=True)
            for mode in MODES
        }
    result["both_native_cores_ready"] = all(
        result["native_only"][str(bits)]["core"]["result"] == "PASS" for bits in BITS)
    a.output.write_text(json.dumps(result, sort_keys=True) + "\n", encoding="ascii")
    print("Native CAD prerequisites " + json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
