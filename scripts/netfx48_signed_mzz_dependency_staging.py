"""Privately stage only missing x64 CLR imports from the same authenticated MZZ.

The original Microsoft offline media must already have passed Windows
Authenticode and independent full SHA256 equality. This helper never installs
.NET, creates registry values, uploads Microsoft binaries or prints filenames.
Staged members exist only in the ephemeral temp directory beside clr.dll.
"""
from __future__ import annotations

import re
from pathlib import Path
import subprocess
import tempfile

from scripts.netfx481_payload_audit import pe_type
from scripts.netfx4x_mzz_import_evidence import FAMILIES, family

MAX_IMPORTS = 16
MAX_LIST = 8 * 1024 * 1024
MAX_MZZ = 24
MAX_CLR = 100 * 1024 * 1024
MAX_MEMBERS = 30000
NAME = re.compile(r"^Path = (.{1,512})$")
DLL = re.compile(r"[a-z0-9_.-]{1,90}\.dll\Z")
RESULTS = {"NOT_RUN", "NO_MZZ_MATCH", "STAGED", "PARTIAL"}


def blank() -> dict:
    return {
        "status": "NOT_RUN", "missing_requested": 0,
        "located": 0, "staged": 0,
        "families": {
            k: {"located": 0, "staged": 0} for k in FAMILIES
        },
        "original_runtime_installed": False,
    }


def valid(r: object) -> bool:
    if type(r) is not dict or set(r) != set(blank()):
        return False
    if r["status"] not in RESULTS or r["original_runtime_installed"] is not False:
        return False
    for key in ("missing_requested", "located", "staged"):
        if type(r[key]) is not int or not 0 <= r[key] <= MAX_IMPORTS:
            return False
    if not r["staged"] <= r["located"] <= r["missing_requested"]:
        return False
    if type(r["families"]) is not dict or set(r["families"]) != set(FAMILIES):
        return False
    for v in r["families"].values():
        if type(v) is not dict or set(v) != {"located", "staged"}:
            return False
        if any(type(x) is not int or x < 0 for x in v.values()):
            return False
    if any(sum(x[k] for x in r["families"].values()) != r[k]
           for k in ("located", "staged")):
        return False
    if r["status"] == "NOT_RUN":
        return r == blank()
    if r["status"] == "STAGED":
        return r["staged"] > 0 and r["staged"] == r["located"]
    if r["status"] == "NO_MZZ_MATCH":
        return r["located"] == 0 and r["staged"] == 0
    return r["located"] > 0


def candidates(dll: str) -> set[str]:
    if not DLL.fullmatch(dll) or dll != dll.casefold():
        raise ValueError("Unsafe original CLR direct-import member name")
    stem = dll[:-4]
    return {
        dll, stem + "_dll_amd64", stem + "_dll_x64",
        stem + "-dll-amd64", stem + "_amd64.dll",
        dll.replace(".", "_") + "_amd64",
    }


def mzz_members(raw: bytes) -> dict[str, str]:
    """Keep original MZZ member names in process memory only."""
    if not raw or len(raw) > MAX_LIST or b"\x00" in raw:
        return {}
    try:
        lines = raw.decode("utf-8-sig").splitlines()
    except UnicodeError:
        return {}
    begun = False
    found: dict[str, str] = {}
    count = 0
    for line in lines:
        if line.startswith("----------"):
            begun = True
            continue
        if not begun:
            continue
        m = NAME.fullmatch(line)
        if m is None:
            continue
        count += 1
        if count > MAX_MEMBERS:
            return {}
        value = m.group(1).strip()
        base = value.replace("\\", "/").rsplit("/", 1)[-1]
        if len(base) > 128 or not re.fullmatch(r"[a-zA-Z0-9_.-]{1,128}", base):
            continue
        if base.casefold() not in found:
            found[base.casefold()] = value
    return found


def stage(original_private_dir: Path, sevenzip: Path,
          missing: list[str]) -> dict:
    if (original_private_dir.is_symlink() or not original_private_dir.is_dir()
            or not sevenzip.is_file() or not 1 <= len(missing) <= MAX_IMPORTS
            or len(set(missing)) != len(missing)):
        raise ValueError("Invalid private original Microsoft MZZ source")
    for value in missing:
        candidates(value)
    archives = original_private_dir / "archives"
    if archives.is_symlink() or not archives.is_dir():
        raise ValueError("Original signed MZZ archive not staged privately")
    sources = sorted(archives.iterdir())
    if len(sources) > MAX_MZZ or any(p.is_symlink() or not p.is_file() for p in sources):
        raise ValueError("Untrusted original Microsoft MZZ set")
    files = [p for p in sources if p.suffix.lower() == ".mzz"]
    result = blank()
    result["missing_requested"] = len(missing)
    if not files:
        result["status"] = "NO_MZZ_MATCH"
        return result
    found: dict[str, tuple[Path, str]] = {}
    for archive in files:
        with tempfile.TemporaryFile() as stdout:
            try:
                proc = subprocess.run(
                    [str(sevenzip), "l", "-slt", str(archive)],
                    cwd=original_private_dir,
                    stdin=subprocess.DEVNULL, stdout=stdout,
                    stderr=subprocess.DEVNULL, timeout=60, check=False)
                stdout.seek(0)
                listing = stdout.read(MAX_LIST + 1)
            except (OSError, subprocess.TimeoutExpired):
                continue
        if proc.returncode != 0:
            continue
        members = mzz_members(listing)
        for dep in missing:
            for variant in candidates(dep):
                if variant in members:
                    found.setdefault(dep, (archive, members[variant]))
    for dep in missing:
        source = found.get(dep)
        if source is None:
            continue
        fam = family(dep)
        result["located"] += 1
        result["families"][fam]["located"] += 1
        archive, member = source
        target = original_private_dir / dep
        if target.exists() or target.is_symlink():
            continue
        try:
            with target.open("xb") as output:
                proc = subprocess.run(
                    [str(sevenzip), "e", "-so", str(archive), member],
                    cwd=original_private_dir, stdin=subprocess.DEVNULL,
                    stdout=output, stderr=subprocess.DEVNULL,
                    timeout=75, check=False)
            if (proc.returncode != 0 or not 512 <= target.stat().st_size <= MAX_CLR):
                target.unlink(missing_ok=True)
                continue
            with target.open("rb") as stream:
                architecture = pe_type(stream.read(8192))
            if architecture != "PE_AMD64":
                target.unlink(missing_ok=True)
                continue
        except (OSError, subprocess.TimeoutExpired):
            target.unlink(missing_ok=True)
            continue
        result["staged"] += 1
        result["families"][fam]["staged"] += 1
    result["status"] = (
        "NO_MZZ_MATCH" if result["located"] == 0 else
        "STAGED" if result["located"] == result["staged"] else "PARTIAL")
    assert valid(result)
    return result
