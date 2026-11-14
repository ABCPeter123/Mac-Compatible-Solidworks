"""Exercise a small, original, self-authored MSI installation under Wine.

The only payload is a text marker, built from in-repo WiX XML on disposable
Windows CI. The macOS fixture requires a marked ephemeral Wine prefix and a
SHA256-verified original build artifact. It never modifies user Wine prefixes
or interprets MSI exit zero as proof that the file was installed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess

from scripts.netfx481_trial import validate_prefix
from scripts.netfx40_legacy import set_legacy_winver
from swcompat.wine_paths import windows_media_path

MSI_NAME = "swcompat_msi_transaction.msi"
MARKER = b"SWCOMPAT_SELF_AUTHORED_MSI_TRANSACTION=1\n"
STATES = {"MEASURED", "ALREADY_MARKED", "WINVER_FAILED"}
PROCESS = {"NOT_RUN", "ZERO", "NONZERO", "TIMEOUT", "START_FAILED"}
FILES = {"ABSENT", "PRESENT_VERIFIED", "CHANGED", "LINKED", "IO_ERROR"}
REPORT_FIELDS = {
    "schema", "scope", "status", "winver", "msi_process",
    "unix_exit", "marker_before", "marker_after", "transaction_candidate",
    "dotnet_compatibility", "solidworks_compatibility",
}


def marker_path(prefix: Path) -> Path:
    validate_prefix(prefix)
    folder = prefix / "drive_c" / "Program Files" / "SWCompatMsiProbe"
    if folder.is_symlink():
        raise ValueError("Linked self-authored MSI target")
    return folder / "msi_transaction_marker.txt"


def marker_state(prefix: Path) -> str:
    folder = prefix / "drive_c" / "Program Files" / "SWCompatMsiProbe"
    path = marker_path(prefix)
    if path.is_symlink():
        return "LINKED"
    if not path.exists():
        return "ABSENT"
    if not path.is_file():
        return "CHANGED"
    try:
        return ("PRESENT_VERIFIED" if path.read_bytes() == MARKER else "CHANGED")
    except OSError:
        return "IO_ERROR"


def verify_msi(msi: Path, manifest: Path) -> None:
    if (msi.is_symlink() or manifest.is_symlink() or
            not msi.is_file() or not manifest.is_file() or
            msi.name.casefold() != MSI_NAME or
            not 1024 <= msi.stat().st_size <= 8 * 1024 * 1024):
        raise ValueError("Unexpected self-authored MSI media")
    expected = manifest.read_text(encoding="ascii").strip().lower()
    if len(expected) != 64 or any(c not in "0123456789abcdef" for c in expected):
        raise ValueError("Invalid self-authored MSI SHA256 manifest")
    h = hashlib.sha256()
    with msi.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            h.update(block)
    if h.hexdigest() != expected:
        raise ValueError("Self-authored MSI digest mismatch")


def install(wine: Path, prefix: Path, msi: Path, timeout: int) -> tuple[str, int | None]:
    validate_prefix(prefix)
    windows_path = windows_media_path(wine, prefix, msi)
    env = os.environ.copy()
    env.pop("WINEDLLOVERRIDES", None)
    env.update({"WINEPREFIX": str(prefix), "WINEARCH": "win64", "WINEDEBUG": "-all"})
    try:
        result = subprocess.run(
            [str(wine), "msiexec.exe", "/i", windows_path, "/qn", "/norestart"],
            cwd=prefix, env=env, stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=timeout, check=False,
        )
    except subprocess.TimeoutExpired:
        return "TIMEOUT", None
    except OSError:
        return "START_FAILED", None
    return ("ZERO" if result.returncode == 0 else "NONZERO",
            result.returncode if -255 <= result.returncode <= 255 else None)


def inspect(wine: Path, prefix: Path, msi: Path, manifest: Path,
            timeout: int = 150) -> dict:
    if os.name == "nt" or any(x.is_symlink() for x in (wine, prefix, msi, manifest)):
        raise ValueError("MSI test must only run on unlinked disposable Wine")
    wine, prefix, msi, manifest = (
        x.resolve(strict=True) for x in (wine, prefix, msi, manifest))
    validate_prefix(prefix)
    if not wine.is_file() or not os.access(wine, os.X_OK):
        raise ValueError("Wine executable missing")
    verify_msi(msi, manifest)
    before = marker_state(prefix)
    r = {
        "schema": 1, "scope": "SELF_AUTHORED_MSI_WINE_TRANSACTION",
        "status": "MEASURED", "winver": "NOT_RUN",
        "msi_process": "NOT_RUN", "unix_exit": None,
        "marker_before": before, "marker_after": before,
        "transaction_candidate": False, "dotnet_compatibility": False,
        "solidworks_compatibility": "NOT_DEMONSTRATED",
    }
    if before != "ABSENT":
        r["status"] = "ALREADY_MARKED"
        return r
    r["winver"] = set_legacy_winver(wine, prefix)
    if r["winver"] != "APPLIED":
        r["status"] = "WINVER_FAILED"
        return r
    status, code = install(wine, prefix, msi, timeout)
    r["msi_process"] = status
    r["unix_exit"] = code
    r["marker_after"] = marker_state(prefix)
    r["transaction_candidate"] = (
        status == "ZERO" and before == "ABSENT" and
        r["marker_after"] == "PRESENT_VERIFIED")
    return r


def validate(r: dict) -> bool:
    if type(r) is not dict or set(r) != REPORT_FIELDS:
        return False
    if (r["schema"] != 1 or r["scope"] != "SELF_AUTHORED_MSI_WINE_TRANSACTION"
            or r["status"] not in STATES
            or r["winver"] not in {"NOT_RUN", "APPLIED", "FAILED"}
            or r["msi_process"] not in PROCESS
            or r["marker_before"] not in FILES or r["marker_after"] not in FILES
            or type(r["transaction_candidate"]) is not bool
            or r["dotnet_compatibility"] is not False
            or r["solidworks_compatibility"] != "NOT_DEMONSTRATED"):
        return False
    if r["unix_exit"] is not None and (
            type(r["unix_exit"]) is not int or not -255 <= r["unix_exit"] <= 255):
        return False
    if r["msi_process"] in {"ZERO", "NONZERO"} and r["unix_exit"] is None:
        return False
    if r["msi_process"] in {"NOT_RUN", "TIMEOUT", "START_FAILED"} and r["unix_exit"] is not None:
        return False
    return r["transaction_candidate"] == (
        r["status"] == "MEASURED" and r["msi_process"] == "ZERO" and
        r["marker_before"] == "ABSENT" and r["marker_after"] == "PRESENT_VERIFIED")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Self-authored MSI transaction in a marked Wine prefix")
    for name in ("wine", "prefix", "msi", "sha256", "output"):
        p.add_argument("--" + name, type=Path, required=True)
    p.add_argument("--timeout", type=int, default=150)
    p.add_argument("--agree-disposable-prefix", action="store_true", required=True)
    args = p.parse_args(argv)
    if not 30 <= args.timeout <= 220:
        p.error("Unsupported MSI test timeout")
    try:
        if args.output.is_symlink() or args.output.resolve() in {
            p.resolve() for p in (args.wine, args.prefix, args.msi, args.sha256)
        }:
            raise ValueError("Result cannot overwrite source media")
        r = inspect(args.wine, args.prefix, args.msi, args.sha256, args.timeout)
        if not validate(r):
            raise ValueError("Unsafe MSI report")
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(r, indent=2) + "\n", encoding="utf-8")
    except (OSError, ValueError):
        p.error("Self-authored original MSI transaction refused")
    for key in ("status", "winver", "msi_process", "unix_exit", "marker_before",
                "marker_after", "transaction_candidate"):
        print("Self-authored MSI", key, r[key])
    print("SOLIDWORKS: NOT DEMONSTRATED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
