"""Bounded, private reconstruction of the genuine CIX dependency graph.

CIX File/Delta/Source/Basis describes *intra-package* source files, not an
installed Windows system. Resolve exact IDs, reject cycles and unknown
operations, check each declared target length and never export vendor files.
"""
from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import re
import xml.etree.ElementTree as ET

MAX_NODES = 12000
MAX_MANIFEST = 16 * 1024 * 1024
MAX_FILE = 64 * 1024 * 1024


@dataclass(frozen=True)
class Entry:
    id: str
    name: str
    length: int
    kind: str
    source: str
    basis: str | None


def path_key(name: str) -> str:
    if not name or len(name) > 1024 or any(ord(c) < 32 for c in name):
        raise ValueError("Invalid CIX member")
    parts = name.replace("\\", "/").split("/")
    if any(not p or p in {".", ".."} or ":" in p or p.endswith((".", " "))
           for p in parts):
        raise ValueError("Unsafe CIX member")
    return "/".join(parts).casefold()


def parse(raw: bytes) -> tuple[dict[str, Entry], int]:
    if len(raw) > MAX_MANIFEST or b"<!DOCTYPE" in raw.replace(b"\0", b"").upper() or b"<!ENTITY" in raw.replace(b"\0", b"").upper():
        raise ValueError("Unsafe CIX XML")
    try:
        root = ET.fromstring(raw)
    except ET.ParseError:
        raise ValueError("Invalid CIX XML") from None
    def tag(node):
        return node.tag.rsplit("}", 1)[-1]
    nodes = list(root.iter())
    if len(nodes) > MAX_NODES * 10:
        raise ValueError("CIX element limit")
    entries = {}
    seen_names = set()
    unsupported = 0
    for node in nodes:
        if tag(node) != "File":
            continue
        fid = node.get("id", "")
        if not re.fullmatch(r"[0-9]{1,10}", fid) or fid in entries:
            raise ValueError("Invalid or duplicate CIX ID")
        name = path_key(node.get("name", ""))
        if name in seen_names:
            raise ValueError("Duplicate CIX target")
        seen_names.add(name)
        length = node.get("length", "")
        if not re.fullmatch(r"[0-9]{1,12}", length):
            raise ValueError("Invalid CIX length")
        delta = [n for n in node if tag(n) == "Delta"]
        source = [n for n in delta[0] if tag(n) == "Source"] if len(delta) == 1 else []
        basis = [n for n in delta[0] if tag(n) == "Basis"] if len(delta) == 1 else []
        if (len(delta) != 1 or len(source) != 1 or len(basis) > 1
                or any(tag(n) not in {"Source", "Basis"} for n in delta[0])
                or source[0].get("type", "").upper() not in {"RAW", "PA19", "PA30", "PA31"}
                or int(length) > MAX_FILE):
            unsupported += 1
            continue
        kind = source[0].get("type", "").upper()
        ref = basis[0].get("file", "") if basis else None
        if ref is not None and not re.fullmatch(r"[0-9]{1,10}", ref):
            raise ValueError("Invalid CIX basis ID")
        if kind == "RAW" and ref is not None:
            unsupported += 1
            continue
        entries[fid] = Entry(fid, name, int(length), kind,
                             path_key(source[0].get("name", "")), ref)
        if len(entries) + unsupported > MAX_NODES:
            raise ValueError("CIX file count limit")
    return entries, unsupported


def order(entries: dict[str, Entry]) -> tuple[list[str], set[str]]:
    """Kahn traversal; absent references and cyclic chains stay blocked."""
    from collections import deque
    ready = deque(k for k, v in entries.items() if v.basis is None)
    followers: dict[str, list[str]] = {}
    for key, entry in entries.items():
        if entry.basis is not None:
            followers.setdefault(entry.basis, []).append(key)
    emitted = []
    while ready:
        key = ready.popleft()
        emitted.append(key)
        ready.extend(followers.get(key, ()))
    return emitted, set(entries) - set(emitted)
