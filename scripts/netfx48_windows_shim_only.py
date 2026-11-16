"""Windows-side control for original signed .NET 4.8 mscoreei.dll native loading.

Windows Authenticode publisher validation is completed by the invoking CI step.
The independent full SHA-256 must match before private MZZ extraction. No
original Microsoft file, filename, system path, exception or installer log is
published. This never installs or activates .NET.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile

from scripts.netfx48_isolated_loader_trial import parse_host, verify_original, exit_class
from scripts.netfx48_signed_mzz_dependency_staging import stage, valid as stage_valid

ALLOWED = {"NOT_RUN", "ORIGINAL_SHIM_ONLY_LOADED", "ORIGINAL_SHIM_MISSING",
           "ORIGINAL_SHIM_INVALID_INPUT", "ORIGINAL_SHIM_LOAD_FAILED",
           "ORIGINAL_SHIM_MISSING_DEPENDENCY", "ORIGINAL_SHIM_MISSING_EXPORT",
           "ORIGINAL_SHIM_BAD_IMAGE", "ORIGINAL_SHIM_INIT_FAILED",
           "ORIGINAL_SHIM_ACCESS_DENIED", "PROBE_ERROR", "TIMEOUT"}
PROCESS = {"NOT_RUN", "EXIT_ZERO", "EXIT_NONZERO", "TIMEOUT", "SPAWN_ERROR"}
SOURCE = {"NOT_RUN", "MZZ_ERROR", "NO_MATCH", "STAGED"}


def blank() -> dict:
    return {"schema": 1, "source": "NOT_RUN", "native_shim": "NOT_RUN",
            "process": "NOT_RUN", "original_runtime_installed": False}


def valid(report: object) -> bool:
    if type(report) is not dict or set(report) != set(blank()):
        return False
    if (type(report["schema"]) is not int or report["schema"] != 1
            or report["source"] not in SOURCE
            or report["native_shim"] not in ALLOWED
            or report["process"] not in PROCESS
            or report["original_runtime_installed"] is not False):
        return False
    if (report["source"] != "STAGED"
            and (report["native_shim"] != "NOT_RUN" or report["process"] != "NOT_RUN")):
        return False
    if ((report["native_shim"] == "NOT_RUN") != (report["process"] == "NOT_RUN")):
        return False
    if report["native_shim"] == "ORIGINAL_SHIM_ONLY_LOADED" and report["process"] != "EXIT_ZERO":
        return False
    return True


def evaluate(installer: Path, expected_sha: str, sevenzip: Path, fixture: Path) -> dict:
    verify_original(installer, expected_sha)
    if (fixture.name != "netfx48_host_activation.exe" or fixture.is_symlink()
            or not fixture.is_file() or sevenzip.is_symlink()
            or not sevenzip.is_file()):
        raise ValueError("Strict native shim control prerequisites not met")
    report = blank()
    with tempfile.TemporaryDirectory(prefix="swcompat-windows-shim-only-") as dirname:
        private = Path(dirname)
        archive_dir = private / "archives"
        archive_dir.mkdir()
        try:
            proc = subprocess.run(
                [str(sevenzip), "e", "-y", str(installer), "-ir!*.mzz",
                 "-o" + str(archive_dir)], cwd=private,
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, timeout=90, check=False)
        except (subprocess.TimeoutExpired, OSError):
            report["source"] = "MZZ_ERROR"
            return report
        if proc.returncode not in (0, 1):
            report["source"] = "MZZ_ERROR"
            return report
        staged = stage(private, sevenzip, ["mscoreei.dll"])
        assert stage_valid(staged)
        if staged["staged"] != 1:
            report["source"] = "NO_MATCH"
            return report
        report["source"] = "STAGED"
        env = os.environ.copy()
        env["SWCOMPAT_ORIGINAL_SHIM_PATH"] = str(private / "mscoreei.dll")
        env["SWCOMPAT_SHIM_ONLY"] = "1"
        env.pop("SWCOMPAT_CLR_PATH", None)
        with tempfile.TemporaryFile() as out:
            try:
                proc = subprocess.run([str(fixture.resolve(strict=True))],
                                      cwd=fixture.parent.resolve(), env=env,
                                      stdin=subprocess.DEVNULL, stdout=out,
                                      stderr=subprocess.DEVNULL, timeout=60,
                                      check=False)
            except subprocess.TimeoutExpired:
                report.update(native_shim="TIMEOUT", process="TIMEOUT")
                return report
            except OSError:
                report.update(native_shim="PROBE_ERROR", process="SPAWN_ERROR")
                return report
            if proc.returncode != 0:
                report.update(native_shim="PROBE_ERROR", process="EXIT_NONZERO")
                return report
            out.seek(0)
            state = parse_host(out.read(1201), 0)
            report.update(native_shim=state if state in ALLOWED else "PROBE_ERROR",
                          process="EXIT_ZERO")
    assert valid(report)
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    for name in ("installer", "sevenzip", "fixture", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--signed-sha256", required=True)
    a = parser.parse_args(argv)
    try:
        result = evaluate(a.installer, a.signed_sha256, a.sevenzip, a.fixture)
        assert valid(result)
        a.output.write_text(json.dumps(result, sort_keys=True), encoding="utf-8")
        print("AUTHENTIC_NETFX48_WINDOWS_NATIVE_SHIM",
              result["source"], result["native_shim"], result["process"])
        return 0
    except Exception:
        print("AUTHENTIC_NETFX48_WINDOWS_NATIVE_SHIM CONTROL_ERROR")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
