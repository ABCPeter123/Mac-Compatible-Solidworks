"""Read only the structural semantics of authenticated Microsoft servicing MUM files.

No Windows package is installed or applied. No MUM contents, assembly identity,
package name, original path, hash or XML bytes leave this bounded inventory.
"""
from __future__ import annotations
import os
from pathlib import Path
import subprocess
import xml.etree.ElementTree as ET

TAGS = ("assembly", "assemblyIdentity", "package", "update", "parent",
        "dependency", "file", "registryKeys", "registryKey", "registryValue",
        "deployment", "customInformation", "securityDescriptor")
ARCH = ("amd64", "x86", "arm64", "neutral")
STATUSES = {"NOT_RUN", "PARSED", "NO_MUM", "PARTIAL",
            "EXTRACTION_FAILED", "UNSAFE_DIRECTORY"}
MAX_MUMS = 48
MAX_FILE = 512 * 1024
MAX_TOTAL = 8 * 1024 * 1024
MAX_ELEMENTS = 30000


def blank(status: str = "NOT_RUN") -> dict:
    if status not in STATUSES:
        raise ValueError("Unrecognized original servicing MUM state")
    return {
        "status": status,
        "mums_seen": 0,
        "mums_parsed": 0,
        "mum_with_update": 0,
        "mum_with_package": 0,
        "mum_with_dependency": 0,
        "tags": {key: 0 for key in TAGS},
        "architectures": {key: 0 for key in ARCH},
        "genuine_servicing_performed": False,
    }


def valid(r: object) -> bool:
    if type(r) is not dict or set(r) != set(blank()):
        return False
    if r["status"] not in STATUSES or r["genuine_servicing_performed"] is not False:
        return False
    for key in ("mums_seen", "mums_parsed", "mum_with_update",
                "mum_with_package", "mum_with_dependency"):
        if type(r[key]) is not int or not 0 <= r[key] <= MAX_MUMS:
            return False
    if not (r["mums_parsed"] <= r["mums_seen"]
            and all(r[k] <= r["mums_parsed"] for k in
                    ("mum_with_update", "mum_with_package", "mum_with_dependency"))):
        return False
    for field, names in (("tags", TAGS), ("architectures", ARCH)):
        values = r[field]
        if (type(values) is not dict or set(values) != set(names)
                or any(type(n) is not int or not 0 <= n <= MAX_ELEMENTS for n in values.values())):
            return False
    return True


def summarize_mum(raw: bytes) -> dict | None:
    """Parse bounded XML without copying element attributes or text to output."""
    if not raw or len(raw) > MAX_FILE or b"<!DOCTYPE" in raw.upper():
        return None
    try:
        root = ET.fromstring(raw)
    except (ET.ParseError, ValueError, UnicodeError):
        return None
    counts = {key: 0 for key in TAGS}
    arch = {key: 0 for key in ARCH}
    total = 0
    for node in root.iter():
        total += 1
        if total > MAX_ELEMENTS:
            return None
        local = node.tag.rsplit("}", 1)[-1] if isinstance(node.tag, str) else ""
        if local in counts:
            counts[local] += 1
        if local == "assemblyIdentity":
            value = node.attrib.get("processorArchitecture", "").casefold()
            if value in arch:
                arch[value] += 1
    return {"tags": counts, "architectures": arch,
            "with_update": counts["update"] > 0,
            "with_package": counts["package"] > 0,
            "with_dependency": counts["dependency"] > 0}


def inspect_cab_mums(sevenzip: Path, archive: Path, destination: Path) -> dict:
    """Extract only .mum files from one validated private CAB to a fresh root."""
    if (sevenzip.is_symlink() or archive.is_symlink()
            or destination.exists() or destination.is_symlink()):
        return blank("UNSAFE_DIRECTORY")
    destination.mkdir(mode=0o700)
    try:
        with open(os.devnull, "wb") as null:
            try:
                done = subprocess.run(
                    [str(sevenzip), "x", "-r", "-y",
                     "-o" + str(destination), str(archive), "*.mum"],
                    stdin=null, stdout=null, stderr=null,
                    cwd=destination, timeout=80, check=False)
            except (OSError, subprocess.TimeoutExpired):
                return blank("EXTRACTION_FAILED")
        if done.returncode != 0:
            return blank("EXTRACTION_FAILED")
        result = blank()
        total_bytes = 0
        directories = 0
        incomplete = False
        for base, dirs, files in os.walk(destination, topdown=True, followlinks=False):
            directories += 1
            if directories > 100:
                incomplete = True
                break
            root = Path(base)
            safe_dirs = sorted(d for d in dirs if not (root / d).is_symlink())
            if len(safe_dirs) != len(dirs):
                incomplete = True
            dirs[:] = safe_dirs[:16]
            for name in sorted(files):
                path = root / name
                if path.is_symlink() or not path.is_file():
                    incomplete = True
                    continue
                if path.suffix.casefold() != ".mum":
                    continue
                if result["mums_seen"] >= MAX_MUMS:
                    incomplete = True
                    break
                result["mums_seen"] += 1
                size = path.stat().st_size
                total_bytes += size
                if size > MAX_FILE or total_bytes > MAX_TOTAL:
                    incomplete = True
                    break
                with path.open("rb") as inp:
                    data = inp.read(MAX_FILE + 1)
                parsed = summarize_mum(data)
                if parsed is None:
                    incomplete = True
                    continue
                result["mums_parsed"] += 1
                for key in TAGS:
                    result["tags"][key] = min(MAX_ELEMENTS,
                                              result["tags"][key] + parsed["tags"][key])
                for key in ARCH:
                    result["architectures"][key] = min(
                        MAX_ELEMENTS,
                        result["architectures"][key] + parsed["architectures"][key])
                for flag, target in (("with_update", "mum_with_update"),
                                     ("with_package", "mum_with_package"),
                                     ("with_dependency", "mum_with_dependency")):
                    result[target] += int(parsed[flag])
            if incomplete:
                break
        result["status"] = ("PARTIAL" if incomplete else
                            "PARSED" if result["mums_parsed"] else "NO_MUM")
        assert valid(result)
        return result
    finally:
        # Explicitly keep all original Microsoft XML in the already disposable
        # CI scratch location; the enclosing TemporaryDirectory removes it.
        pass


def combine(reports: list[dict]) -> dict:
    """Aggregate actual distinct CABs, preserving partial and no-op semantics."""
    if not reports:
        return blank()
    if any(not valid(r) for r in reports):
        raise ValueError("Unverified original servicing MUM report")
    result = blank()
    partial = False
    for report in reports:
        if report["status"] != "PARSED":
            partial = True
        for field in ("mums_seen", "mums_parsed", "mum_with_update",
                      "mum_with_package", "mum_with_dependency"):
            result[field] += report[field]
        for key in TAGS:
            result["tags"][key] += report["tags"][key]
        for key in ARCH:
            result["architectures"][key] += report["architectures"][key]
    if not valid({**result, "status": "PARSED"}):
        raise ValueError("Aggregated original servicing payload exceeds bounded limits")
    result["status"] = ("PARTIAL" if partial else
                        "PARSED" if result["mums_parsed"] else "NO_MUM")
    assert valid(result)
    return result
