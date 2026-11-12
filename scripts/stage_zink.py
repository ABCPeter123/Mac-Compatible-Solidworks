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
        return struct.unpack_from("<H", record, 4)[0] if record[:4] == b"PE\\0\\0" else None
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
        shutil.copy2(original, dest)
        sha = hashlib.sha256(dest.read_bytes()).hexdigest()
        manifest["dlls"].append({
            "name": name, "source": str(original.relative_to(source)),
            "sha256": sha, "size": dest.stat().st_size,
        })
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--prefix", type=Path, required=True, help="Disposable Wine prefix, NOT a system path")
    parser.add_argument("--manifest", type=Path, default=Path("build/zink-stage.json"))
    args = parser.parse_args()
    prefix = args.prefix.expanduser().resolve()
    if not (prefix / "system.reg").exists() or not (prefix / "drive_c/windows/system32").is_dir():
        parser.error("Target must be an initialized Wine prefix with a Windows system32 directory.")
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
