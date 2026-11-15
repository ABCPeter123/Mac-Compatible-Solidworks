"""Try Winetricks msxml3 in a fresh marked win64 Wine prefix before .NET 4.0.

An isolated prerequisite experiment, not a CLR installation shortcut.
Never publish Winetricks stdout/stderr, paths, downloads or vendor content.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess

from scripts.netfx481_trial import validate_prefix

STATUSES = {"VERB_SUCCEEDED", "VERB_FAILED", "VERB_TIMED_OUT",
            "VERB_START_FAILED"}
DLL_PATHS = {
    "x86": ("syswow64", "msxml3.dll"),
    "x64": ("system32", "msxml3.dll"),
}


def _digest(path: Path) -> bytes | None:
    if path.is_symlink() or not path.is_file():
        return None
    if not 4096 <= path.stat().st_size <= 80 * 1024 * 1024:
        return None
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.digest()


def _snapshot(prefix: Path) -> dict[str, bytes | None]:
    root = prefix / "drive_c" / "windows"
    if root.is_symlink():
        raise ValueError("Linked Win32 installation root")
    return {
        arch: _digest(root.joinpath(*parts))
        for arch, parts in DLL_PATHS.items()
    }


def blank(status: str = "VERB_START_FAILED") -> dict:
    return {"status": status, "x86_dll_changed": False, "x64_dll_changed": False}


def validate(report: dict) -> bool:
    return (type(report) is dict
            and set(report) == {"status", "x86_dll_changed", "x64_dll_changed"}
            and report["status"] in STATUSES
            and type(report["x86_dll_changed"]) is bool
            and type(report["x64_dll_changed"]) is bool
            and (report["status"] == "VERB_SUCCEEDED"
                 or not (report["x86_dll_changed"] or report["x64_dll_changed"])))


def _is_wine_host() -> bool:
    return os.name != "nt"


def inspect(wine: Path, prefix: Path, winetricks: Path, *,
            timeout: int = 300) -> dict:
    if not _is_wine_host() or not 60 <= timeout <= 420:
        raise ValueError("Only bounded disposable Wine experiments are allowed")
    if any(p.is_symlink() for p in (wine, prefix, winetricks)):
        raise ValueError("Linked experiment paths are forbidden")
    wine, prefix, winetricks = (
        p.resolve(strict=True) for p in (wine, prefix, winetricks)
    )
    validate_prefix(prefix)
    if not wine.is_file() or not os.access(wine, os.X_OK):
        raise ValueError("Wine executable is unavailable")
    if not winetricks.is_file() or not os.access(winetricks, os.X_OK):
        raise ValueError("Winetricks executable is unavailable")
    before = _snapshot(prefix)
    env = os.environ.copy()
    for key in ("WINEDLLOVERRIDES", "WINETRICKS_FORCE"):
        env.pop(key, None)
    env.update({
        "WINEPREFIX": str(prefix),
        "WINEARCH": "win64",
        "WINE": str(wine),
        "PATH": str(wine.parent) + os.pathsep + env.get("PATH", ""),
        "WINEDEBUG": "-all",
        "WINETRICKS_LATEST_VERSION_CHECK": "disabled",
    })
    env.pop("WINESERVER", None)
    if (wine.parent / "wineserver").is_file():
        env["WINESERVER"] = str(wine.parent / "wineserver")
    try:
        child = subprocess.run(
            [str(winetricks), "-q", "msxml3"],
            cwd=prefix, env=env,
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, timeout=timeout, check=False,
        )
    except subprocess.TimeoutExpired:
        return blank("VERB_TIMED_OUT")
    except OSError:
        return blank()
    if child.returncode:
        return blank("VERB_FAILED")
    after = _snapshot(prefix)
    result = {
        "status": "VERB_SUCCEEDED",
        "x86_dll_changed": after["x86"] is not None
        and before["x86"] != after["x86"],
        "x64_dll_changed": after["x64"] is not None
        and before["x64"] != after["x64"],
    }
    assert validate(result)
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Private Winetricks msxml3 prerequisite test")
    for key in ("wine", "prefix", "winetricks", "output"):
        parser.add_argument("--" + key, type=Path, required=True)
    parser.add_argument("--timeout", type=int, default=300)
    parser.add_argument("--agree-disposable-prefix", action="store_true", required=True)
    args = parser.parse_args(argv)
    report = inspect(args.wine, args.prefix, args.winetricks, timeout=args.timeout)
    if not validate(report):
        raise ValueError("Unsafe msxml3 prerequisite result")
    if args.output.is_symlink():
        raise ValueError("Linked output not allowed")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, sort_keys=True), encoding="ascii")
    for field in ("status", "x86_dll_changed", "x64_dll_changed"):
        print("Winetricks msxml3 prerequisite", field, report[field])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
