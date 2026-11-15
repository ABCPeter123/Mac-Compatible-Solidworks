"""Read-only deferred MSI SCM API comparison, source-authored fixture only.

No vendor MSI, Windows servicing, service mutation, private Wine logs, original
DLLs or installation claims are used. Positive means only the harmless
source-authored deferred DLL completed and its expected file was installed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
from scripts.netfx481_trial import validate_prefix
from swcompat.wine_paths import windows_media_path

MSI_NAME = "swcompat_deferred_scm_probe.msi"
MARKER = b"SWCOMPAT_DEFERRED_SCM_PROBE"
STATUS_FILE = "swcompat-deferred-scm.status"
CREATE_STATUS_FILE = "swcompat-deferred-scm-create.status"
REGISTRY_STATUS_FILE = "swcompat-deferred-registry.status"
STATES = {"PASS", "MANAGER_FAILED", "SERVICE_FAILED", "QUERY_FAILED", "NO_REPORT", "INVALID_REPORT"}
CREATE_STATES = {"PASS", "CREATE_MANAGER_FAILED", "CREATE_PATH_FAILED",
                 "CREATE_FAILED", "CONFIG_FAILED", "QUERY_FAILED", "DELETE_FAILED",
                 "NO_REPORT", "INVALID_REPORT"}
REGISTRY_STATES = {"PASS", "CREATE_FAILED", "WRITE_FAILED", "READ_FAILED",
                   "VERIFY_FAILED", "DELETE_FAILED", "KEY_ALREADY_EXISTS",
                   "NO_REPORT", "INVALID_REPORT"}
PROCESSES = {"ZERO", "NONZERO", "TIMED_OUT", "START_FAILED"}


def valid(result: dict) -> bool:
    return (type(result) is dict
            and set(result) == {"process", "deferred_scm", "deferred_create", "deferred_registry", "installed_file",
                                "self_authored_transaction", "native_microsoft_clr",
                                "solidworks_compatibility"}
            and result["process"] in PROCESSES
            and result["deferred_scm"] in STATES
            and result["deferred_create"] in CREATE_STATES
            and result["deferred_registry"] in REGISTRY_STATES
            and result["installed_file"] in {"ABSENT", "PRESENT_MATCH", "PRESENT_DIFFERENT"}
            and type(result["self_authored_transaction"]) is bool
            and result["self_authored_transaction"] ==
                (result["process"] == "ZERO" and result["deferred_scm"] == "PASS"
                 and result["deferred_create"] == "PASS"
                 and result["deferred_registry"] == "PASS"
                 and result["installed_file"] == "PRESENT_MATCH")
            and result["native_microsoft_clr"] is False
            and result["solidworks_compatibility"] == "NOT_DEMONSTRATED")


def _status(prefix: Path, filename: str = STATUS_FILE) -> str:
    if filename not in {STATUS_FILE, CREATE_STATUS_FILE, REGISTRY_STATUS_FILE}:
        raise ValueError("Unsupported fixed status path")
    allowed = (STATES if filename == STATUS_FILE else
               CREATE_STATES if filename == CREATE_STATUS_FILE else REGISTRY_STATES)
    for name in ("Temp", "temp"):
        path = prefix / "drive_c" / "windows" / name / filename
        if path.is_symlink():
            return "INVALID_REPORT"
        if not path.is_file():
            continue
        try:
            raw = path.read_bytes()
        except OSError:
            return "INVALID_REPORT"
        if len(raw) > 32:
            return "INVALID_REPORT"
        try:
            state = raw.decode("ascii")
        except UnicodeDecodeError:
            return "INVALID_REPORT"
        return state if state in allowed - {"NO_REPORT", "INVALID_REPORT"} else "INVALID_REPORT"
    return "NO_REPORT"


def _marker(prefix: Path) -> str:
    path = prefix / "drive_c" / "Program Files" / "SWCompatDeferredScmProbe" / "msi_deferred_scm_marker.txt"
    if path.is_symlink() or path.parent.is_symlink():
        return "PRESENT_DIFFERENT"
    try:
        data = path.read_bytes()
    except FileNotFoundError:
        return "ABSENT"
    except OSError:
        return "PRESENT_DIFFERENT"
    return "PRESENT_MATCH" if data == MARKER else "PRESENT_DIFFERENT"


def inspect(wine: Path, prefix: Path, msi: Path, sha: Path, timeout: int = 120) -> dict:
    if os.name == "nt":
        raise ValueError("This differential requires disposable Wine")
    if not 15 <= timeout <= 180:
        raise ValueError("Bounded timeout required")
    if any(path.is_symlink() for path in (wine, prefix, msi, sha)):
        raise ValueError("Symlinked probe input")
    wine, prefix, msi, sha = (p.resolve(strict=True) for p in (wine, prefix, msi, sha))
    validate_prefix(prefix)
    if not os.access(wine, os.X_OK) or not wine.is_file() or msi.name != MSI_NAME:
        raise ValueError("Unexpected source-authored fixture")
    expected = sha.read_text(encoding="ascii").strip().lower()
    if len(expected) != 64 or any(c not in "0123456789abcdef" for c in expected):
        raise ValueError("Invalid build digest")
    h = hashlib.sha256()
    with msi.open("rb") as inp:
        for chunk in iter(lambda: inp.read(65536), b""):
            h.update(chunk)
    if h.hexdigest() != expected:
        raise ValueError("Fixture digest does not match Windows reference")
    if (_status(prefix) != "NO_REPORT"
            or _status(prefix, CREATE_STATUS_FILE) != "NO_REPORT"
            or _status(prefix, REGISTRY_STATUS_FILE) != "NO_REPORT"
            or _marker(prefix) != "ABSENT"):
        raise ValueError("Probe evidence must not preexist")
    path = windows_media_path(wine, prefix, msi)
    env = {**os.environ, "WINEPREFIX": str(prefix), "WINEARCH": "win64",
           "WINEDEBUG": "-all,err+msi"}
    try:
        p = subprocess.run([str(wine), "msiexec.exe", "/i", path, "/qn", "/norestart"],
                           cwd=prefix, env=env, stdin=subprocess.DEVNULL,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           timeout=timeout, check=False)
        process = "ZERO" if p.returncode == 0 else "NONZERO"
    except subprocess.TimeoutExpired:
        process = "TIMED_OUT"
    except OSError:
        process = "START_FAILED"
    report = {"process": process, "deferred_scm": _status(prefix),
              "deferred_create": _status(prefix, CREATE_STATUS_FILE),
              "deferred_registry": _status(prefix, REGISTRY_STATUS_FILE),
              "installed_file": _marker(prefix),
              "native_microsoft_clr": False,
              "solidworks_compatibility": "NOT_DEMONSTRATED"}
    report["self_authored_transaction"] = (
        report["process"] == "ZERO" and report["deferred_scm"] == "PASS"
        and report["deferred_create"] == "PASS"
        and report["deferred_registry"] == "PASS"
        and report["installed_file"] == "PRESENT_MATCH")
    assert valid(report)
    return report


def main() -> int:
    p = argparse.ArgumentParser(description="Native vs Wine MSI deferred read-only SCM")
    for field in ("wine", "prefix", "msi", "sha", "output"):
        p.add_argument("--" + field, type=Path, required=True)
    p.add_argument("--timeout", type=int, default=120)
    p.add_argument("--agree-disposable-prefix", action="store_true")
    a = p.parse_args()
    if not a.agree_disposable_prefix:
        p.error("Must explicitly authorize disposable fixture")
    result = inspect(a.wine, a.prefix, a.msi, a.sha, a.timeout)
    a.output.parent.mkdir(parents=True, exist_ok=True)
    a.output.write_text(json.dumps(result, sort_keys=True), encoding="ascii")
    for key, value in result.items():
        print("Self-authored deferred SCM", key, value)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
