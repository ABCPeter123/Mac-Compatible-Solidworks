"""Run the self-authored CAD-like interactive WGL session on Apple Silicon Wine.

A single genuine Windows x64 process handles geometry selection, extrusion,
zoom and rotation, reads actual depth-tested framebuffer pixels, and saves
synthetic model data. An entirely separate Windows process reopens and
validates the saved model. No SOLIDWORKS executable or proprietary format.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile

from scripts.netfx481_trial import validate_prefix
from scripts.software_launch import environment, validate_prefix as validate_mesa

EXE_NAME = "live_cad_viewport.exe"
DOCUMENT = "swcompat-live-cad-model.bin"
WIN_DOC = "C:\\" + DOCUMENT
EXPECTED = struct.pack("<8s9I", b"SWCAD3D1", 1, 2, 12, 20, 30, 2, 1, 2, 15)
PASS_MARKERS = (
    "INITIAL_DEPTH", "EVENT_LOOP", "SELECTED_REDRAW",
    "EXTRUDE_REDRAW", "ZOOM_REDRAW", "ROTATION_REDRAW",
    "SAVE_REOPEN", "CLOSE",
)
REASONS = {
    "NOT_VERIFIED", "PROCESS_ERROR", "TIMEOUT", "BAD_REPORT",
    "REGISTER", "WINDOW", "CreateWindowButton", "SetWindowPos",
    "GetDC", "WGLPixelFormat", "WGLCreateContext", "InitialFramebuffer",
    "PostSyntheticInput", "MessageDispatch", "UpdatedFramebuffer",
    "ExtrudeAndFrame", "ZoomPost", "ZoomAndFrame", "RotationPost",
    "RotationAndFrame", "FileSaveReopen", "WindowClose",
}
FILE_STATES = {"ABSENT", "EXACT", "MISMATCH", "LINKED", "IO_ERROR"}
MAX_OUTPUT = 4096


def parse(raw: bytes, returncode: int, phase: str) -> dict[str, str]:
    blank = {"result": "UNVERIFIED", "reason": "BAD_REPORT"}
    if phase not in {"run", "verify"} or returncode not in {0, 1, 2} or (
            len(raw) > MAX_OUTPUT or b"\x00" in raw):
        return blank
    try:
        lines = raw.decode("ascii").splitlines()
    except UnicodeDecodeError:
        return blank
    found: dict[str, str] = {}
    for line in lines:
        if not line.startswith("SWCOMPAT_LIVE_"):
            continue
        if "=" not in line:
            return blank
        key, value = line[len("SWCOMPAT_LIVE_"):].split("=", 1)
        allowed = set(PASS_MARKERS) | {"RESULT", "STAGE", "INDEPENDENT_REOPEN"}
        if key not in allowed or key in found:
            return blank
        if key == "STAGE":
            if value not in REASONS:
                return blank
        elif value not in ({"PASS", "FAIL"} if key in {"RESULT", "INDEPENDENT_REOPEN"} else {"PASS"}):
            return blank
        found[key] = value
    if phase == "verify":
        if returncode == 0 and found == {"INDEPENDENT_REOPEN": "PASS"}:
            return {"result": "PASS", "reason": "NOT_VERIFIED"}
        if returncode == 1 and found == {"INDEPENDENT_REOPEN": "FAIL"}:
            return {"result": "FAIL", "reason": "NOT_VERIFIED"}
        return blank
    if returncode == 0 and (
            found == {**dict.fromkeys(PASS_MARKERS, "PASS"), "RESULT": "PASS"}):
        return {"result": "PASS", "reason": "NOT_VERIFIED"}
    if returncode == 1 and found.get("RESULT") == "FAIL" and (
            found.get("STAGE") in REASONS and
            all(key in PASS_MARKERS or key in {"RESULT", "STAGE"}
                for key in found)):
        return {"result": "FAIL", "reason": found["STAGE"]}
    return blank


def model_file_state(path: Path) -> str:
    if path.is_symlink():
        return "LINKED"
    if not path.exists():
        return "ABSENT"
    try:
        if not path.is_file() or path.stat().st_size != len(EXPECTED):
            return "MISMATCH"
        return "EXACT" if path.read_bytes() == EXPECTED else "MISMATCH"
    except OSError:
        return "IO_ERROR"


def process(wine: Path, fixture: Path, prefix: Path, phase: str, timeout: int) -> dict:
    with tempfile.TemporaryFile() as output:
        try:
            result = subprocess.run(
                [str(wine), str(fixture), phase, WIN_DOC],
                cwd=fixture.parent, env=environment(prefix),
                stdin=subprocess.DEVNULL, stdout=output,
                stderr=subprocess.DEVNULL, timeout=timeout, check=False,
            )
        except subprocess.TimeoutExpired:
            return {"result": "UNVERIFIED", "reason": "TIMEOUT"}
        except OSError:
            return {"result": "UNVERIFIED", "reason": "PROCESS_ERROR"}
        output.seek(0)
        raw = output.read(MAX_OUTPUT + 1)
    return parse(raw, result.returncode, phase)


def trial(wine: Path, prefix: Path, fixture: Path, timeout: int = 75) -> dict:
    if os.name == "nt" or any(p.is_symlink() for p in (wine, prefix, fixture)):
        raise ValueError("Only unlinked self-authored binaries in a disposable Wine prefix")
    try:
        wine, prefix, fixture = (
            p.resolve(strict=True) for p in (wine, prefix, fixture)
        )
    except OSError as exc:
        raise ValueError("Missing pinned Wine or self-authored Win32 fixture") from exc
    validate_prefix(prefix)
    validate_mesa(prefix)
    if (not wine.is_file() or not os.access(wine, os.X_OK) or
            not fixture.is_file() or fixture.name.casefold() != EXE_NAME):
        raise ValueError("Unexpected Windows self-authored fixture or Wine executable")
    doc = prefix / "drive_c" / DOCUMENT
    if model_file_state(doc) != "ABSENT":
        raise ValueError("Refuse preexisting CAD model path")
    run = {"result": "UNVERIFIED", "reason": "NOT_VERIFIED"}
    independent = {"result": "UNVERIFIED", "reason": "NOT_VERIFIED"}
    persisted = "ABSENT"
    removed = False
    try:
        run = process(wine, fixture, prefix, "run", timeout)
        persisted = model_file_state(doc)
        if run["result"] == "PASS" and persisted == "EXACT":
            independent = process(wine, fixture, prefix, "verify", timeout)
    finally:
        if not doc.is_symlink() and doc.is_file():
            try:
                doc.unlink()
            except OSError:
                pass
        removed = model_file_state(doc) == "ABSENT"
    passed = (run["result"] == "PASS" and persisted == "EXACT" and
              independent["result"] == "PASS" and removed)
    return {
        "schema": 1, "scope": "SYNTHETIC_3D_WIN32_WGL_NOT_SOLIDWORKS",
        "session": run, "independent_reopen": independent,
        "saved_model": persisted, "cleanup": "REMOVED" if removed else "FAILED",
        "synthetic_cad_session": passed,
        "native_solidworks_cad": False,
        "solidworks_compatibility": "NOT_DEMONSTRATED",
    }


def validate(report: dict) -> bool:
    if (type(report) is not dict or set(report) != {
            "schema", "scope", "session", "independent_reopen",
            "saved_model", "cleanup", "synthetic_cad_session",
            "native_solidworks_cad", "solidworks_compatibility"}):
        return False
    if (type(report["schema"]) is not int or report["schema"] != 1 or
            report["scope"] != "SYNTHETIC_3D_WIN32_WGL_NOT_SOLIDWORKS" or
            report["native_solidworks_cad"] is not False or
            report["solidworks_compatibility"] != "NOT_DEMONSTRATED" or
            type(report["synthetic_cad_session"]) is not bool or
            report["saved_model"] not in FILE_STATES or
            report["cleanup"] not in {"REMOVED", "FAILED"}):
        return False
    for name in ("session", "independent_reopen"):
        item = report[name]
        if (type(item) is not dict or set(item) != {"result", "reason"} or
                item["result"] not in {"PASS", "FAIL", "UNVERIFIED"} or
                item["reason"] not in REASONS):
            return False
    expected = (report["session"]["result"] == "PASS" and
                report["independent_reopen"]["result"] == "PASS" and
                report["saved_model"] == "EXACT" and report["cleanup"] == "REMOVED")
    return report["synthetic_cad_session"] == expected


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Synthetic Win32 WGL CAD session with separate-process model roundtrip")
    for key in ("wine", "prefix", "fixture", "output"):
        p.add_argument("--" + key, required=True, type=Path)
    p.add_argument("--timeout", default=75, type=int)
    p.add_argument("--agree-disposable-prefix", action="store_true", required=True)
    args = p.parse_args(argv)
    if not 30 <= args.timeout <= 120:
        p.error("Unbounded CAD process timeout")
    try:
        if (args.output.is_symlink() or args.output.resolve() in
                {x.resolve() for x in (args.wine, args.prefix, args.fixture)}):
            raise ValueError("Invalid output target")
        r = trial(args.wine, args.prefix, args.fixture, args.timeout)
        if not validate(r):
            raise ValueError("Unexpected CAD-style report")
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(r, indent=2) + "\n", encoding="ascii")
    except (ValueError, OSError):
        p.error("Refused unsafe synthetic CAD stage trial")
    for key in ("session", "independent_reopen"):
        print("Synthetic CAD", key, r[key]["result"], r[key]["reason"])
    print("Synthetic CAD saved model", r["saved_model"])
    print("Synthetic CAD session verified", r["synthetic_cad_session"])
    print("SOLIDWORKS functionality: NOT DEMONSTRATED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
