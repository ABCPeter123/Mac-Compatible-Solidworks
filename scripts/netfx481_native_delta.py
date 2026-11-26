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
import json
import os
from pathlib import Path
import subprocess
import tempfile
import zlib
import shutil
from scripts.netfx481_cix_graph import parse as parse_cix, order as cix_order, path_key

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


ERROR_CLASSES = ("UNSUPPORTED", "INTEGRITY", "LIMIT", "INVALID", "LZX",
                 "ALLOCATION", "CLI_USAGE", "TIMEOUT", "START_FAILED", "OTHER",
                 "FRAMING", "MISSING_OUTPUT", "HASH_ALGORITHM", "TARGET_HASH", "PARAMETER_LIMIT",
                 "TRANSFORM", "SOURCE_ARCH", "PE_METADATA", "MATCH_WINDOW", "IO")


def classify_decoder_error(raw: bytes) -> str:
    # Only fixed categories leave the process; paths and vendor bytes do not.
    text = raw[:65536].decode("utf-8", errors="replace").lower()
    # Rust main returns Result, so its termination diagnostic uses Debug,
    # e.g. Error: Integrity("PA30 target hash mismatch"), not Display.
    for needle, category in (
        ("pa30 target hash algorithm", "HASH_ALGORITHM"),
        ("pa30 target hash mismatch", "TARGET_HASH"),
        ("pa30 parameter memory", "PARAMETER_LIMIT"),
        ("pa30 parameter blocks", "PARAMETER_LIMIT"),
        ("pa30 unknown transform flag", "TRANSFORM"),
        ("pa30 source architecture", "SOURCE_ARCH"),
        ("cli metadata", "PE_METADATA"), ("pa30 match window", "MATCH_WINDOW"),
        ("error: integrity(", "INTEGRITY"), ("error: invalid(", "INVALID"),
        ("error: unsupported(", "UNSUPPORTED"), ("error: limit(", "LIMIT"),
        ("error: codec(", "LZX"), ("error: allocation", "ALLOCATION"),
        ("error: io(", "IO"),
        ("unsupported", "UNSUPPORTED"), ("not implemented", "UNSUPPORTED"),
        ("integrity check failed", "INTEGRITY"), ("limit exceeded", "LIMIT"),
        ("invalid delta", "INVALID"), ("lzx delta decode failed", "LZX"),
        ("allocation failed", "ALLOCATION"), ("usage:", "CLI_USAGE"),
        ("unexpected argument", "CLI_USAGE"), ("required arguments", "CLI_USAGE"),
    ):
        if needle in text:
            return category
    return "OTHER"


def observe_decoder(command: list[str], root: Path, timeout: int) -> tuple[bool, str]:
    with tempfile.TemporaryFile() as log:
        try:
            process = subprocess.run(command, cwd=root, stdin=subprocess.DEVNULL,
                                     stdout=log, stderr=log, timeout=timeout, check=False)
        except subprocess.TimeoutExpired:
            return False, "TIMEOUT"
        except OSError:
            return False, "START_FAILED"
        if process.returncode == 0:
            return True, "OTHER"
        log.seek(0)
        return False, classify_decoder_error(log.read(65536))


DIFFERENTIAL_FIELDS = frozenset({
    "file_type", "flags", "different", "runs", "max_run", "near_e8", "near_e9",
    "source_same", "header", "text", "rdata", "data", "rsrc", "reloc", "unwind", "other"
})


def observe_reference_difference(helper: Path, basis: Path, delta: Path,
                                 reference: Path, root: Path) -> dict | None:
    if os.name != "nt":
        return None
    with tempfile.TemporaryFile() as log:
        try:
            p = subprocess.run([str(helper), "--diagnose", str(basis), str(delta),
                                str(reference)], cwd=root, stdin=subprocess.DEVNULL,
                               stdout=log, stderr=subprocess.DEVNULL, timeout=90,
                               check=False)
        except (OSError, subprocess.TimeoutExpired):
            return None
        if p.returncode:
            return None
        log.seek(0)
        try:
            r = json.loads(log.read(4097))
        except (ValueError, UnicodeError):
            return None
    if (type(r) is not dict or set(r) != DIFFERENTIAL_FIELDS
            or any(type(v) is not int or not 0 <= v <= 2**64 - 1 for v in r.values())
            or r["file_type"] not in {1, 2, 4, 8, 16, 32, 64, 128}
            or r["different"] > reference.stat().st_size
            or sum(r[k] for k in ("header", "text", "rdata", "data", "rsrc", "reloc", "unwind", "other")) != r["different"]
            or any(r[k] > r["different"] for k in ("runs", "max_run", "near_e8", "near_e9", "source_same"))):
        return None
    return r


def native_delta_reference(raw: bytes, basis: Path | None,
                           expected: Path | None, length: int) -> str:
    """Native Windows ApplyDeltaB check; never retain or use its result as a basis."""
    if os.name != "nt" or expected is None or expected.stat().st_size != length:
        return "UNAVAILABLE"
    import ctypes as c
    from ctypes import wintypes
    class Input(c.Structure):
        _fields_ = [("start", c.c_void_p), ("size", c.c_size_t), ("editable", wintypes.BOOL)]
    class Output(c.Structure):
        _fields_ = [("start", c.c_void_p), ("size", c.c_size_t)]
    dll = c.WinDLL("msdelta.dll", use_last_error=True, winmode=0x800)
    apply = dll.ApplyDeltaB
    apply.argtypes = [c.c_int64, Input, Input, c.POINTER(Output)]
    apply.restype = wintypes.BOOL
    free = dll.DeltaFree
    free.argtypes = [c.c_void_p]
    free.restype = wintypes.BOOL
    source = basis.read_bytes() if basis else b""
    src = c.create_string_buffer(source)
    delta = c.create_string_buffer(raw)
    out = Output()
    try:
        if not apply(0, Input(c.addressof(src) if source else None, len(source), False),
                     Input(c.addressof(delta), len(raw), False), c.byref(out)):
            return "REJECTED"
        if out.size != length or (out.size and not out.start):
            return "MISMATCH"
        digest = hashlib.sha256(c.string_at(out.start, out.size) if out.size else b"").digest()
        return "MATCH" if digest == sha256_file(expected) else "MISMATCH"
    finally:
        if out.start:
            free(out.start)


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


def reconstruct(codec: Path, raw_dir: Path, extracted: list[Path],
                work: Path, expanded: Path | None,
                verified_codec: Path | None = None) -> dict:
    """Reconstruct every eligible CIX node with its declared private basis.

    Native Windows Expand is an independent oracle, never a source for the
    portable graph. Exact logical destination paths and sizes are compared.
    """
    index = {}
    for p in extracted:
        key = path_key(p.relative_to(raw_dir).as_posix())
        if key in index:
            raise ValueError("Ambiguous extracted member")
        index[key] = p
    manifest = index.get("_manifest_.cix.xml")
    if manifest is None or manifest.stat().st_size > 16 * 1024 * 1024:
        raise ValueError("Missing or oversized CIX")
    entries, unsupported = parse_cix(manifest.read_bytes())
    ordered, unresolved = cix_order(entries)
    report = {"cix_entries": len(entries) + unsupported, "cix_unsupported": unsupported,
              "cix_unresolved": len(unresolved), "cix_basis": sum(e.basis is not None for e in entries.values()),
              "cix_raw": sum(e.kind == "RAW" for e in entries.values()),
              "cix_reconstructed": 0, "cix_delta_reconstructed": 0, "cix_delta_failed": 0,
              "cix_basis_blocked": 0, "cix_missing_source": 0, "cix_size_mismatch": 0,
              "cix_oracle_matches": 0, "cix_oracle_mismatches": 0, "cix_oracle_missing": 0,
              "cix_empty_source_recovered": 0, "cix_external_hash_recovered": 0,
              "cix_parameter_budget_recovered": 0, "cix_compat_attempted": 0,
              "cix_compat_recovered": 0, "cix_compat_failed": 0,
              "cix_differential_reports": 0,
              "cix_target_hash_pa30": 0, "cix_target_hash_pa31": 0, "cix_target_hash_pa19": 0,
              **{"cix_error_" + k.lower(): 0 for k in ERROR_CLASSES},
              **{"cix_native_reference_" + k.lower(): 0
                 for k in ("MATCH", "MISMATCH", "REJECTED", "UNAVAILABLE")}}
    oracle = {}
    if expanded:
        for p in files(expanded):
            key = path_key(p.relative_to(expanded).as_posix())
            if key in oracle:
                raise ValueError("Ambiguous reference member")
            oracle[key] = p
    outputs: dict[str, Path] = {}
    empty_basis = work / "cix-empty-basis"
    empty_basis.write_bytes(b"")
    total = 0
    # A cumulative budget limits even valid authenticated decompression.
    for fid in ordered:
        e = entries[fid]
        source = index.get(e.source)
        if source is None or source.stat().st_size > MAX_FILE:
            report["cix_missing_source"] += 1
            continue
        basis = outputs.get(e.basis) if e.basis else None
        if e.basis and basis is None:
            report["cix_basis_blocked"] += 1
            continue
        target = work / ("cix-target-" + fid)
        if target.exists() or target.is_symlink() or total + e.length > MAX_TOTAL:
            raise ValueError("CIX output collision or total limit")
        if e.kind == "RAW":
            if source.stat().st_size != e.length:
                report["cix_size_mismatch"] += 1
                continue
            shutil.copyfile(source, target)
        else:
            raw = source.read_bytes()
            framing = format_and_offset(raw[:8], raw)
            if framing is None or framing[0] != e.kind.lower():
                report["cix_delta_failed"] += 1
                report["cix_error_framing"] += 1
                continue
            delta = work / ("cix-delta-" + fid)
            delta.write_bytes(raw[framing[1]:])
            command = [str(codec), "apply", "--format", framing[0], "--delta",
                       str(delta), "--output", str(target)]
            if basis is not None:
                command += ["--source", str(basis)]
            try:
                ok, reason = observe_decoder(command, work, 45)
                # A null source and an explicit empty input are distinct CLI
                # representations. Only retry nodes whose CIX declares no basis.
                if not ok and basis is None and reason not in {"TIMEOUT", "START_FAILED", "LIMIT"}:
                    if target.is_symlink() or target.is_file():
                        target.unlink()
                    ok, reason = observe_decoder(command + ["--source", str(empty_basis)], work, 45)
                    if ok and target.is_file() and not target.is_symlink() and target.stat().st_size == e.length:
                        report["cix_empty_source_recovered"] += 1
                # Raise only the explicitly failed parameter-workspace limit.
                # All source/output/window limits and intrinsic hashes remain.
                if not ok and reason == "PARAMETER_LIMIT":
                    if target.is_symlink() or target.is_file():
                        target.unlink()
                    ok, reason = observe_decoder(command + ["--max-parameter-bytes", "33554432"], work, 45)
                    if ok and target.is_file() and not target.is_symlink() and target.stat().st_size == e.length:
                        report["cix_parameter_budget_recovered"] += 1
                if not ok and reason == "TARGET_HASH":
                    report["cix_target_hash_" + framing[0]] += 1
                    if e.kind == "PA30" and verified_codec is not None:
                        expected = oracle.get(e.name) if expanded else None
                        if not expanded or (expected is not None and expected.stat().st_size == e.length):
                            report["cix_compat_attempted"] += 1
                            if target.is_symlink() or target.is_file():
                                target.unlink()
                            ok = run_private([str(verified_codec), str(basis or empty_basis), str(delta),
                                              str(target), str(e.length),
                                              sha256_file(expected).hex() if expected is not None else "-"],
                                             work, 120)
                            if (ok and target.is_file() and not target.is_symlink()
                                    and target.stat().st_size == e.length
                                    and (expected is None or sha256_file(target) == sha256_file(expected))):
                                report["cix_compat_recovered"] += 1
                            else:
                                report["cix_compat_failed"] += 1
                                ok = False
                if (not ok and reason == "TARGET_HASH" and e.kind == "PA30"
                        and expanded and verified_codec is not None):
                    expected = oracle.get(e.name)
                    if expected is not None and expected.stat().st_size == e.length:
                        differential = observe_reference_difference(verified_codec, basis or empty_basis,
                                                                  delta, expected, work)
                        if differential is not None:
                            report["cix_differential_reports"] += 1
                            print("Native PA30 fixed differential", json.dumps(differential, sort_keys=True))
                # The upstream verifier API is restricted to CALG_NONE + empty
                # intrinsic hash. Supply an independent native Windows Expand
                # digest, never a digest derived from the decoder's own output.
                if (not ok and reason == "HASH_ALGORITHM" and e.kind == "PA30"
                        and verified_codec is not None and expanded):
                    expected = oracle.get(e.name)
                    if expected is not None and expected.stat().st_size == e.length:
                        if target.is_symlink() or target.is_file():
                            target.unlink()
                        ok = run_private([str(verified_codec), str(basis or empty_basis), str(delta),
                                          str(target), str(e.length), sha256_file(expected).hex()],
                                         work, 45)
                        if (ok and target.is_file() and not target.is_symlink()
                                and target.stat().st_size == e.length
                                and sha256_file(target) == sha256_file(expected)):
                            report["cix_external_hash_recovered"] += 1
                        else:
                            ok = False
            finally:
                delta.unlink(missing_ok=True)
            if not ok or target.is_symlink() or not target.is_file():
                if target.is_symlink() or target.is_file():
                    target.unlink()
                report["cix_delta_failed"] += 1
                report["cix_error_" + (reason if not ok else "MISSING_OUTPUT").lower()] += 1
                if expanded:
                    reference = native_delta_reference(raw[framing[1]:], basis,
                                                       oracle.get(e.name), e.length)
                    report["cix_native_reference_" + reference.lower()] += 1
                continue
            if target.stat().st_size != e.length:
                target.unlink()
                report["cix_size_mismatch"] += 1
                continue
            report["cix_delta_reconstructed"] += 1
        outputs[fid] = target
        total += e.length
        report["cix_reconstructed"] += 1
        if expanded:
            reference = oracle.get(e.name)
            if reference is None:
                report["cix_oracle_missing"] += 1
            elif reference.stat().st_size == e.length and sha256_file(target) == sha256_file(reference):
                report["cix_oracle_matches"] += 1
            else:
                report["cix_oracle_mismatches"] += 1
    return report


def inspect(package: Path, manifest: Path, sevenzip: Path, codec: Path,
            expand: Path | None = None,
            verified_codec: Path | None = None) -> dict:
    paths = [package, manifest, sevenzip, codec] + ([expand] if expand else [])
    if any(p.is_symlink() for p in paths):
        raise ValueError("Linked inputs prohibited")
    package, manifest, sevenzip, codec = (p.resolve(strict=True) for p in paths[:4])
    verify_package(package, manifest)
    if expand:
        if os.name != "nt":
            raise ValueError("Native Windows Expand oracle required")
        expand = expand.resolve(strict=True)
    if verified_codec is not None:
        if verified_codec.is_symlink():
            raise ValueError("Linked compatibility decoder forbidden")
        verified_codec = verified_codec.resolve(strict=True)
        if not verified_codec.is_file() or verified_codec.name.casefold() not in {"swcompat-verified-delta", "swcompat-verified-delta.exe"}:
            raise ValueError("Unexpected independent verifier")
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
            expanded = None
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
            graph_work = work / f"graph-{index}"
            graph_work.mkdir()
            graph = reconstruct(codec, raw_dir, extracted, graph_work, expanded, verified_codec)
            for key, value in graph.items():
                report[key] = report.get(key, 0) + value
            # Preserve the earlier independent empty-source control sample.
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
    p.add_argument("--verified-codec", type=Path)
    a = p.parse_args()
    if a.output.is_symlink() or a.output.exists():
        p.error("Report must be a fresh path")
    r = inspect(a.package, a.sha256_file, a.sevenzip, a.codec, a.expand, a.verified_codec)
    a.output.write_text(json.dumps(r, sort_keys=True), encoding="ascii")
    for key, value in r.items():
        print("Native IPD delta reconstruction", key, value)
    # Diagnostic job success does not mean decoder readiness or servicing.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
