"""Experimental GAC registration using original KB5011048 file directives.

The caller must independently authenticate the complete stage and finish the
file/registry transaction. Native Fusion chooses assembly identity and cache
layout. Never manufacture cache directory names, spoof assembly identity,
or claim Windows CBS equivalence from this experiment.
"""
from __future__ import annotations

from collections import Counter
import os
from pathlib import Path
import re
import subprocess
import tempfile
import xml.etree.ElementTree as ET

from scripts.netfx481_ipd_stage import digest_file
from scripts.netfx481_ipd_wusa_dryrun import windows_path
from scripts.netfx481_trial import validate_prefix


def local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1].split(":")[-1]


class GacRejected(ValueError):
    """Finite reason code only; no original manifest values or private paths."""


def registration_sources(members: dict[str, Path], *, expected_count: int = 274) -> list:
    entries = []
    for name, manifest in sorted(members.items()):
        if "/" in name or not name.endswith((".manifest", ".mum")):
            continue
        if manifest.stat().st_size > 16 * 1024 * 1024:
            raise GacRejected("MANIFEST_OVERSIZE")
        raw = manifest.read_bytes()
        if any(marker in raw.replace(b"\0", b"").upper() for marker in (b"<!DOCTYPE", b"<!ENTITY")):
            raise GacRejected("MANIFEST_UNSAFE")
        try:
            root = ET.fromstring(raw)
        except ET.ParseError:
            raise GacRejected("MANIFEST_XML") from None
        for file in root:
            if local(file.tag) != "file":
                continue
            for directive in file.iter():
                if local(directive.tag).casefold() != "gac":
                    continue
                if len(directive):
                    raise GacRejected("GAC_CHILDREN")
                attrs = {local(k): v for k, v in directive.attrib.items()}
                if len(attrs) != len(directive.attrib) or set(attrs) not in (
                        {"clrarch", "clrversion", "managedversion"},
                        {"clrarch", "clrversion", "managedversion", "fileCopy"}):
                    raise GacRejected("GAC_ATTRIBUTES")
                # CLR 4 version labels may have the conventional v prefix.
                # Only the authenticated CLR4 package and known routes qualify.
                if attrs["clrversion"].casefold() not in {"v4.0.30319", "4.0.30319", "v4.0", "4.0", "4.0.0.0", "v4.0.0.0"}:
                    raise GacRejected("GAC_CLR_VERSION")
                if attrs["clrarch"].casefold() not in {"amd64", "msil", "x86"}:
                    raise GacRejected("GAC_ARCHITECTURE")
                if attrs["managedversion"] not in {"2.0.0.0", "4.0.0.0", "10.0.0.0"}:
                    raise GacRejected("GAC_MANAGED_VERSION")
                if attrs.get("fileCopy", "false").casefold() != "false":
                    raise GacRejected("GAC_COPY_FLAG")
                name_source = file.get("sourceName", "")
                key = name.rsplit(".", 1)[0] + "/" + name_source.replace("\\", "/").casefold()
                if key not in members:
                    raise GacRejected("SOURCE_NOT_PACKAGED")
                src = members[key]
                if (src.is_symlink() or not src.is_file()
                        or src.suffix.casefold() not in {".dll", ".exe"}
                        or src.stat().st_size > 64 * 1024 * 1024):
                    raise GacRejected("SOURCE_TYPE_OR_SIZE")
                entries.append(src)
    if len(entries) != expected_count:
        raise GacRejected("DIRECTIVE_COUNT")
    return entries


def cached_sources(prefix: Path, entries: list) -> set:
    """Measure original payload bytes in real GAC paths, never create paths."""
    wanted = {}
    for p in entries:
        wanted.setdefault(p.name.casefold(), set()).add(digest_file(p))
    found = set()
    windows = prefix / "drive_c" / "windows"
    for root in (windows / "Microsoft.NET" / "assembly", windows / "assembly"):
        if root.is_symlink() or not root.is_dir():
            continue
        for cache in root.iterdir():
            if cache.name.casefold() not in {"gac", "gac_32", "gac_64", "gac_msil"} or cache.is_symlink() or not cache.is_dir():
                continue
            for folder, dirs, files in os.walk(cache, followlinks=False):
                base = Path(folder)
                dirs[:] = [d for d in dirs if not (base / d).is_symlink()]
                for name in files:
                    p = base / name
                    hashes = wanted.get(name.casefold())
                    if hashes and not p.is_symlink() and p.is_file() and p.stat().st_size <= 64 * 1024 * 1024:
                        digest = digest_file(p)
                        if digest in hashes:
                            found.add((name.casefold(), digest))
    return found


def register(wine: Path, prefix: Path, fixture: Path, members: dict[str, Path]) -> dict:
    validate_prefix(prefix)
    runner = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
    if (prefix.resolve() != runner / "netfx40-msxml3-prefix"
            or fixture.is_symlink() or fixture.resolve() != runner / "swcompat-netfx481-ipd-gac.exe"):
        raise GacRejected("PRIVATE_PATHS")
    try:
        entries = registration_sources(members)
    except GacRejected as exc:
        return {"transport": "REJECTED", "reason": str(exc)}
    unique = {}
    for src in entries:
        unique.setdefault((src.name.casefold(), digest_file(src)), src)
    before = cached_sources(prefix, entries)
    remaining = [p for k, p in unique.items() if k not in before]
    result = {"directives": len(entries), "unique_payloads": len(unique),
              "cached_before": len(before), "attempted": 0, "successful_hresult": 0,
              "failed_hresult": {}, "transport": "COMPLETED", "cached_after": 0}
    fusion = prefix / "drive_c" / "windows" / "Microsoft.NET" / "Framework64" / "v4.0.30319" / "fusion.dll"
    candidates = [p for name, p in members.items() if name.endswith("/fusion.dll")]
    if (fusion.is_symlink() or not fusion.is_file()
            or digest_file(fusion) not in {digest_file(p) for p in candidates}):
        result["transport"] = "ORIGINAL_FUSION_NOT_VERIFIED"
        return result
    env = os.environ.copy()
    env.update(WINEPREFIX=str(prefix), WINEARCH="win64", WINEDEBUG="-all",
               WINEDLLOVERRIDES="fusion=n;mscoree=n;clr=n")
    failures = Counter()
    for start in range(0, len(remaining), 16):
        batch = remaining[start:start + 16]
        result["attempted"] += len(batch)
        try:
            with tempfile.TemporaryFile() as out:
                proc = subprocess.run([str(wine), str(fixture), *map(windows_path, batch)],
                                      env=env, cwd=prefix, stdin=subprocess.DEVNULL,
                                      stdout=out, stderr=subprocess.DEVNULL, timeout=45, check=False)
                out.seek(0)
                raw = out.read(4097)
        except (OSError, subprocess.TimeoutExpired):
            result["transport"] = "PROCESS_FAILED_OR_TIMEOUT"
            break
        if proc.returncode or len(raw) > 4096:
            result["transport"] = "INVALID_PROCESS_RESULT"
            break
        lines = raw.splitlines()
        if not lines or lines[0] != b"SWCOMPAT_IPD_GAC_SCHEMA=1":
            result["transport"] = "INVALID_PACKET"
            break
        if len(lines) == 2 and re.fullmatch(rb"SWCOMPAT_IPD_GAC_FAILURE=[123]:[0-9A-F]{8}", lines[1]):
            result["transport"] = "FUSION_" + lines[1].split(b"=")[1].decode("ascii")
            break
        if len(lines) != len(batch) + 1 or any(not re.fullmatch(rb"SWCOMPAT_IPD_GAC_ITEM=[0-9A-F]{8}", l) for l in lines[1:]):
            result["transport"] = "INVALID_PACKET"
            break
        for line in lines[1:]:
            code = line.split(b"=")[1].decode("ascii")
            if int(code, 16) & 0x80000000:
                failures[code] += 1
            else:
                result["successful_hresult"] += 1
    result["failed_hresult"] = dict(sorted(failures.items()))
    result["cached_after"] = len(cached_sources(prefix, entries))
    return result
