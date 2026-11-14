"""Test CAD-like OLE compound-document persistence in three Windows processes.

Runs an original MSVC x64 Win32/COM executable in a marked disposable Wine
prefix. It creates a nested structured-storage model, edits it in a second
process and validates the revision in a third. The document is entirely
synthetic, never an actual SOLIDWORKS part file or vendor API call.
Only enum values are emitted. The temporary document is always cleaned.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile

from scripts.netfx481_trial import validate_prefix

DOC_NAME = "swcompat-cad-ole-model.cfb"
EXE_NAME = "cad_ole_document.exe"
WIN_DOC_PATH = "C:\\" + DOC_NAME
CFB_MAGIC = bytes.fromhex("D0CF11E0A1B11AE1")
PHASES = ("CREATE", "EDIT", "VERIFY")
REASONS = {
    "OK", "ARGUMENT", "COM_INIT", "CREATE_ROOT", "CREATE_CHILD",
    "CREATE_STREAM", "OPEN_ROOT", "OPEN_CHILD", "OPEN_STREAM",
    "READ", "WRITE", "STREAM_COMMIT", "CHILD_COMMIT", "ROOT_COMMIT",
    "MODEL_MISMATCH", "SEEK", "BAD_REPORT", "PROCESS_ERROR", "TIMEOUT",
}
PHASE_STATES = {"PASS", "FAIL", "UNVERIFIED"}
FILE_STATES = {"PRESENT_CFB", "ABSENT", "INVALID", "LINKED", "IO_ERROR"}
MAX_OUTPUT = 2048


def parse(raw: bytes, code: int, phase: str) -> dict[str, str]:
    fail = {"result": "UNVERIFIED", "reason": "BAD_REPORT"}
    if (phase not in PHASES or len(raw) > MAX_OUTPUT or
            b"\x00" in raw or code not in (0, 1)):
        return fail
    try:
        lines = raw.decode("ascii").splitlines()
    except UnicodeDecodeError:
        return fail
    entries: dict[str, str] = {}
    for line in lines:
        if not line.startswith("SWCOMPAT_CAD_DOC_"):
            continue
        if "=" not in line:
            return fail
        name, val = line[len("SWCOMPAT_CAD_DOC_"):].split("=", 1)
        if name in entries or name not in {"SCHEMA", "PHASE", "RESULT", "REASON"}:
            return fail
        entries[name] = val
    if (set(entries) != {"SCHEMA", "PHASE", "RESULT", "REASON"} or
            entries["SCHEMA"] != "1" or entries["PHASE"] != phase or
            entries["RESULT"] not in {"PASS", "FAIL"} or
            entries["REASON"] not in REASONS):
        return fail
    if ((code == 0) != (entries["RESULT"] == "PASS") or
            (entries["REASON"] == "OK") != (entries["RESULT"] == "PASS")):
        return fail
    return {"result": entries["RESULT"], "reason": entries["REASON"]}


def file_state(doc: Path) -> str:
    if doc.is_symlink():
        return "LINKED"
    if not doc.exists():
        return "ABSENT"
    if not doc.is_file():
        return "INVALID"
    try:
        size = doc.stat().st_size
        if not 512 <= size <= 10 * 1024 * 1024:
            return "INVALID"
        with doc.open("rb") as f:
            return "PRESENT_CFB" if f.read(8) == CFB_MAGIC else "INVALID"
    except OSError:
        return "IO_ERROR"


def execute(wine: Path, prefix: Path, fixture: Path, phase: str,
            timeout: int = 45) -> dict[str, str]:
    env = os.environ.copy()
    env.pop("WINEDLLOVERRIDES", None)
    env.update({"WINEPREFIX": str(prefix), "WINEARCH": "win64", "WINEDEBUG": "-all"})
    with tempfile.TemporaryFile() as output:
        try:
            run = subprocess.run(
                [str(wine), str(fixture), phase.lower(), WIN_DOC_PATH],
                cwd=fixture.parent, env=env, stdin=subprocess.DEVNULL,
                stdout=output, stderr=subprocess.DEVNULL, timeout=timeout,
                check=False)
            code = run.returncode
        except subprocess.TimeoutExpired:
            return {"result": "UNVERIFIED", "reason": "TIMEOUT"}
        except OSError:
            return {"result": "UNVERIFIED", "reason": "PROCESS_ERROR"}
        output.seek(0)
        raw = output.read(MAX_OUTPUT + 1)
    return parse(raw, code, phase)


def trial(wine: Path, prefix: Path, fixture: Path, timeout: int = 45) -> dict:
    if os.name == "nt" or any(x.is_symlink() for x in (wine, prefix, fixture)):
        raise ValueError("This trial only runs under a marked nonlinked Wine prefix")
    wine, prefix, fixture = (
        p.resolve(strict=True) for p in (wine, prefix, fixture))
    validate_prefix(prefix)
    if (not wine.is_file() or not os.access(wine, os.X_OK) or
            not fixture.is_file() or fixture.name.casefold() != EXE_NAME):
        raise ValueError("Expected pinned Wine executable and self-authored CAD probe")
    doc = prefix / "drive_c" / DOC_NAME
    if doc.exists() or doc.is_symlink():
        raise ValueError("Refusing preexisting or linked CAD model artifact")
    phases = {x.lower(): {"result": "UNVERIFIED", "reason": "BAD_REPORT"}
              for x in PHASES}
    after_create = "ABSENT"
    after_edit = "ABSENT"
    after_verify = "ABSENT"
    cleaned = False
    try:
        phases["create"] = execute(wine, prefix, fixture, "CREATE", timeout)
        after_create = file_state(doc)
        if phases["create"]["result"] == "PASS" and after_create == "PRESENT_CFB":
            phases["edit"] = execute(wine, prefix, fixture, "EDIT", timeout)
            after_edit = file_state(doc)
            if phases["edit"]["result"] == "PASS" and after_edit == "PRESENT_CFB":
                phases["verify"] = execute(wine, prefix, fixture, "VERIFY", timeout)
                after_verify = file_state(doc)
    finally:
        if doc.is_symlink():
            cleaned = False
        elif doc.exists() and doc.is_file():
            try:
                doc.unlink()
                cleaned = not doc.exists()
            except OSError:
                cleaned = False
        else:
            cleaned = not doc.exists()
    passed = (
        all(phases[k]["result"] == "PASS" for k in phases)
        and after_create == after_edit == after_verify == "PRESENT_CFB"
        and cleaned
    )
    return {
        "schema": 1,
        "scope": "SELF_AUTHORED_CAD_OLE_DOCUMENT_NOT_SOLIDWORKS",
        "create": phases["create"],
        "edit": phases["edit"],
        "verify": phases["verify"],
        "after_create": after_create, "after_edit": after_edit,
        "after_verify": after_verify,
        "cleanup": "REMOVED" if cleaned else "FAILED",
        "synthetic_document_roundtrip": passed,
        "native_solidworks_document": False,
        "solidworks_compatibility": "NOT_DEMONSTRATED",
    }


def validate(r: dict) -> bool:
    keys = {
        "schema", "scope", "create", "edit", "verify",
        "after_create", "after_edit", "after_verify", "cleanup",
        "synthetic_document_roundtrip", "native_solidworks_document",
        "solidworks_compatibility",
    }
    if type(r) is not dict or set(r) != keys or r["schema"] != 1:
        return False
    if (r["scope"] != "SELF_AUTHORED_CAD_OLE_DOCUMENT_NOT_SOLIDWORKS"
            or r["solidworks_compatibility"] != "NOT_DEMONSTRATED"
            or r["native_solidworks_document"] is not False
            or type(r["synthetic_document_roundtrip"]) is not bool
            or r["cleanup"] not in {"REMOVED", "FAILED"}):
        return False
    for phase in ("create", "edit", "verify"):
        entry = r[phase]
        if (type(entry) is not dict or set(entry) != {"result", "reason"}
                or entry["result"] not in PHASE_STATES
                or entry["reason"] not in REASONS):
            return False
        if (entry["result"] == "PASS") != (entry["reason"] == "OK"):
            return False
    if any(r[key] not in FILE_STATES for key in
           ("after_create", "after_edit", "after_verify")):
        return False
    actual_pass = (
        all(r[key]["result"] == "PASS" for key in ("create", "edit", "verify"))
        and all(r[key] == "PRESENT_CFB"
                for key in ("after_create", "after_edit", "after_verify"))
        and r["cleanup"] == "REMOVED"
    )
    return r["synthetic_document_roundtrip"] == actual_pass


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Original x64 COM compound-document CAD-like lifetime experiment")
    for name in ("wine", "prefix", "fixture", "output"):
        p.add_argument("--" + name, type=Path, required=True)
    p.add_argument("--timeout", type=int, default=45)
    p.add_argument("--agree-disposable-prefix", action="store_true", required=True)
    args = p.parse_args(argv)
    if not 20 <= args.timeout <= 120:
        p.error("Invalid stage timeout")
    try:
        if args.output.is_symlink() or args.output.resolve() in {
            p.resolve() for p in (args.wine, args.prefix, args.fixture)}:
            raise ValueError("Output would overwrite executable or prefix")
        r = trial(args.wine, args.prefix, args.fixture, args.timeout)
        if not validate(r):
            raise ValueError("CAD document stage report invalid")
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(r, indent=2) + "\n", encoding="ascii")
    except (OSError, ValueError):
        p.error("Refusing invalid or unsafe CAD document trial")
    for phase in ("create", "edit", "verify"):
        print("Synthetic CAD OLE", phase.upper(), r[phase]["result"],
              r[phase]["reason"])
    for key in ("after_create", "after_edit", "after_verify", "cleanup"):
        print("Synthetic CAD OLE", key, r[key])
    print("Synthetic CAD OLE roundtrip:", r["synthetic_document_roundtrip"])
    print("SOLIDWORKS CAD compatibility: NOT DEMONSTRATED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
