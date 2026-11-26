"""Decode original catalog IPD delta streams with a portable native codec.

The pinned MIT ms-delta CLI reconstructs individual original streams in a
private temporary directory. On Windows, compare reconstructed bytes with
the official IPD-aware Expand utility. On macOS use the same authenticated
catalog package, exercising the portable decoder without Wine or Windows.
Never install, publish, or modify Microsoft components or their catalogs.
"""
from __future__ import annotations
import argparse
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import zlib

from scripts.netfx481_catalog_wusa import verify_package
from scripts.netfx481_servicing_inventory import _invoke_sevenzip, _safe_embedded

MAX_FILE = 64 * 1024 * 1024
MAX_TOTAL = 1024 * 1024 * 1024
MAX_FILES = 12000
MAX_SAMPLE = 48


def format_and_offset(header: bytes, raw: bytes) -> tuple[str, int] | None:
    """Accept exact PA19/30/31 magic or a CRC32-prefixed patch envelope."""
    for magic, fmt in ((b"PA19", "pa19"), (b"PA30", "pa30"), (b"PA31", "pa31")):
        if header.startswith(magic):
            return fmt, 0
        if header[4:8] == magic and len(raw) >= 8:
            if int.from_bytes(raw[:4], "little") == zlib.crc32(raw[4:]):
                return fmt, 4
    return None


def files(root: Path) -> list[Path]:
    """Fail closed on links or unbounded extraction."""
    found = []
    total = 0
    dirs = 0
    for base, children, names in os.walk(root, followlinks=False):
        dirs += 1
        if dirs > MAX_FILES:
            raise ValueError("Extracted archive directory limit")
        here = Path(base)
        if any((here / d).is_symlink() for d in children):
            raise ValueError("Linked archive directory")
        children.sort()
        for name in sorted(names):
            path = here / name
            if path.is_symlink() or not path.is_file():
                raise ValueError("Linked or special extracted file")
            total += path.stat().st_size
            found.append(path)
            if len(found) > MAX_FILES or total > MAX_TOTAL:
                raise ValueError("Extracted archive exceeds bounds")
    return found


def sha256_file(path: Path) -> bytes:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.digest()


def run_private(command: list[str], root: Path, timeout: int) -> bool:
    try:
        result = subprocess.run(command, cwd=root, stdin=subprocess.DEVNULL,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0


def decode_one(codec: Path, raw: bytes, root: Path, serial: int) -> tuple[str, bytes | None]:
    """Do actual portable empty-source patch reconstruction, with bounded output."""
    if len(raw) > MAX_FILE:
        return "UNSUPPORTED", None
    framing = format_and_offset(raw[:8], raw)
    if framing is None:
        return "UNSUPPORTED", None
    fmt, offset = framing
    delta = root / f"delta-{serial}.bin"
    target = root / f"target-{serial}.bin"
    if delta.exists() or target.exists() or delta.is_symlink() or target.is_symlink():
        raise ValueError("Delta target collision")
    delta.write_bytes(raw[offset:])
    try:
        if not run_private([str(codec), "apply", "--format", fmt, "--delta",
                            str(delta), "--output", str(target)], root, 45):
            return "DECODE_FAILED", None
        if target.is_symlink() or not target.is_file() or target.stat().st_size > MAX_FILE:
            return "DECODE_FAILED", None
        return "DECODED", sha256_file(target)
    finally:
        delta.unlink(missing_ok=True)
        if target.is_file() or target.is_symlink():
            target.unlink()


def inspect(package: Path, manifest: Path, sevenzip: Path, codec: Path,
            expand: Path | None = None) -> dict:
    paths = [package, manifest, sevenzip, codec] + ([expand] if expand else [])
    if any(p.is_symlink() for p in paths):
        raise ValueError("Linked inputs prohibited")
    package, manifest, sevenzip, codec = (p.resolve(strict=True) for p in paths[:4])
    verify_package(package, manifest)
    if expand:
        if os.name != "nt":
            raise ValueError("Native Windows Expand oracle required")
        expand = expand.resolve(strict=True)
    if not codec.is_file() or codec.name.casefold() not in {"ms-delta", "ms-delta.exe"}:
        raise ValueError("Expected pinned portable delta CLI")
    report = {"catalog_verified": True, "cab_count": 0, "ipd_cabs": 0,
              "candidate_streams": 0, "sampled_streams": 0, "decoded": 0,
              "failed": 0, "oracle_available": bool(expand), "oracle_matches": 0,
              "oracle_mismatches": 0, "servicing_performed": False}
    with tempfile.TemporaryDirectory(prefix="swcompat-native-delta-") as td:
        root = Path(td)
        cabs = root / "cabs"
        cabs.mkdir()
        state, _ = _invoke_sevenzip(sevenzip, ["x", "-y", "-r", "-o" + str(cabs),
                                             str(package), "*.cab"], root, timeout=150)
        if state != "OK":
            raise ValueError("Original catalog cabinet extraction failed")
        packages, partial = _safe_embedded(cabs)
        if partial:
            raise ValueError("Incomplete cabinet inventory")
        work = root / "work"
        work.mkdir()
        for index, cab in enumerate(packages):
            if cab.suffix.casefold() != ".cab":
                continue
            report["cab_count"] += 1
            raw_dir = root / f"raw-{index}"
            raw_dir.mkdir()
            state, _ = _invoke_sevenzip(sevenzip, ["x", "-y", "-o" + str(raw_dir),
                                                 str(cab)], root, timeout=150)
            if state != "OK":
                raise ValueError("Original CAB extraction failed")
            extracted = files(raw_dir)
            if not any(p.name.casefold() == "_manifest_.cix.xml" for p in extracted):
                continue
            report["ipd_cabs"] += 1
            oracle_hashes: set[bytes] = set()
            if expand:
                expanded = root / f"expanded-{index}"
                expanded.mkdir()
                if not run_private([str(expand), "-F:*", str(cab), str(expanded)], root, 150):
                    raise ValueError("Native Windows IPD reference expansion failed")
                for p in files(expanded):
                    if p.stat().st_size <= MAX_FILE:
                        oracle_hashes.add(sha256_file(p))
                if not oracle_hashes:
                    raise ValueError("Empty Windows reference expansion")
            # Prefer small streams and deterministic order to bound CI cost.
            for p in sorted(extracted, key=lambda p: (p.stat().st_size, str(p))):
                if not 8 <= p.stat().st_size <= MAX_FILE:
                    continue
                with p.open("rb") as f:
                    header = f.read(8)
                if not any(header[:4] == m or header[4:8] == m
                           for m in (b"PA19", b"PA30", b"PA31")):
                    continue
                raw = p.read_bytes()
                if format_and_offset(header, raw) is None:
                    continue
                report["candidate_streams"] += 1
                if report["sampled_streams"] >= MAX_SAMPLE:
                    continue
                serial = report["sampled_streams"]
                report["sampled_streams"] += 1
                state, digest = decode_one(codec, raw, work, serial)
                if state != "DECODED":
                    report["failed"] += 1
                    continue
                report["decoded"] += 1
                if expand:
                    report["oracle_matches" if digest in oracle_hashes else "oracle_mismatches"] += 1
    return report


def main() -> int:
    import json
    p = argparse.ArgumentParser(description=__doc__)
    for key in ("package", "sha256-file", "sevenzip", "codec", "output"):
        p.add_argument("--" + key, required=True, type=Path)
    p.add_argument("--expand", type=Path)
    a = p.parse_args()
    if a.output.is_symlink() or a.output.exists():
        p.error("Report must be a fresh path")
    r = inspect(a.package, a.sha256_file, a.sevenzip, a.codec, a.expand)
    a.output.write_text(json.dumps(r, sort_keys=True), encoding="ascii")
    for key, value in r.items():
        print("Native IPD delta reconstruction", key, value)
    # Diagnostic job success does not mean decoder readiness or servicing.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
