"""Select Windows x64 Mesa/Zink DLLs from an extracted, checksum-verified release.

Only installs into an explicitly supplied disposable Wine prefix directory.
No download, admin rights, registry modification, or proprietary components.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import struct
import sys
import time

REQUIRED = ("opengl32.dll", "libgallium_wgl.dll")
OPTIONAL = ("libglapi.dll",)
AMD64 = 0x8664


def pe_machine(path: Path) -> int | None:
    try:
        with path.open("rb") as stream:
            header = stream.read(64)
            if len(header) < 64 or header[:2] != b"MZ":
                return None
            offset = struct.unpack_from("<I", header, 0x3C)[0]
            if offset > 1024 * 1024:
                return None
            stream.seek(offset)
            record = stream.read(6)
        return struct.unpack_from("<H", record, 4)[0] if record[:4] == b"PE\0\0" else None
    except (OSError, struct.error):
        return None


def select_dlls(source: Path) -> dict[str, Path]:
    if not source.is_dir():
        raise ValueError(f"Missing extraction directory: {source}")
    wanted = set(REQUIRED + OPTIONAL)
    found: dict[str, list[Path]] = {name: [] for name in wanted}
    for path in source.rglob("*"):
        if path.is_file() and path.name.lower() in wanted and pe_machine(path) == AMD64:
            found[path.name.lower()].append(path)
    missing = [key for key in REQUIRED if not found[key]]
    if missing:
        raise ValueError(f"Missing x64 Mesa DLLs {missing}. Check release archive contents.")
    result = {}
    for key in REQUIRED + OPTIONAL:
        candidates = sorted(found[key], key=lambda p: (len(p.parts), str(p)))
        if candidates:
            result[key] = candidates[0]
    return result


def stage(source: Path, destination: Path) -> dict:
    if not destination.is_dir():
        raise ValueError(f"Destination Windows system32 directory does not exist: {destination}")
    selected = select_dlls(source)
    manifest = {"architecture": "x86_64", "dlls": []}
    for name, original in selected.items():
        dest = destination / name
        # Wine prefixes can contain symlinks into the Wine installation.
        # Never follow those links or overwrite the shared Wine runtime.
        if dest.is_symlink():
            dest.unlink()
        elif dest.exists():
            backup = destination / (name + ".swcompat-backup")
            if backup.exists() or backup.is_symlink():
                raise ValueError(f"Backup already exists, refusing overwrite: {backup}")
            dest.rename(backup)
        shutil.copy2(original, dest, follow_symlinks=False)
        sha = hashlib.sha256(dest.read_bytes()).hexdigest()
        manifest["dlls"].append({
            "name": name, "source": str(original.relative_to(source)),
            "sha256": sha, "size": dest.stat().st_size,
        })
    return manifest


def prefix_is_ready(prefix: Path) -> bool:
    return (prefix / "system.reg").is_file() and (prefix / "drive_c/windows/system32").is_dir()


def wait_for_prefix(prefix: Path, timeout_seconds: float = 45.0) -> bool:
    """Wine may return from wineboot before registry and system32 are written."""
    if not prefix.is_dir():
        return False
    deadline = time.monotonic() + timeout_seconds
    while True:
        if prefix_is_ready(prefix):
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.25)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--prefix", type=Path, required=True, help="Disposable Wine prefix, NOT a system path")
    parser.add_argument("--manifest", type=Path, default=Path("build/zink-stage.json"))
    args = parser.parse_args()
    prefix = args.prefix.expanduser().resolve()
    if not wait_for_prefix(prefix):
        missing = []
        if not (prefix / "system.reg").is_file():
            missing.append("system.reg")
        if not (prefix / "drive_c/windows/system32").is_dir():
            missing.append("drive_c/windows/system32")
        parser.error("Wine prefix was not ready after initialization; missing: " + ", ".join(missing))
    try:
        report = stage(args.source.resolve(), prefix / "drive_c/windows/system32")
    except ValueError as exc:
        parser.error(str(exc))
    args.manifest.parent.mkdir(parents=True, exist_ok=True)
    args.manifest.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
