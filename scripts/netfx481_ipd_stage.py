"""Materialize the exact verified IPD CIX tree for private Wine servicing.

No update descriptors, component manifests, or catalogs are rewritten.
This is an extraction stage, not an installer or signature verifier.
"""
from __future__ import annotations
import hashlib
import os
from pathlib import Path
import shutil
import tempfile

from scripts.netfx481_cix_graph import path_key
from scripts.netfx481_native_delta_gate import EXPECTED_COUNT, EXPECTED_TREE_SHA256

MAX_TOTAL = 1024 * 1024 * 1024


def digest_file(path: Path) -> bytes:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.digest()


def safe_name(name: str) -> str:
    if path_key(name) != name:
        raise ValueError("Noncanonical CIX staging path")
    reserved = {"con", "prn", "aux", "nul", *(f"com{i}" for i in range(1, 10)),
                *(f"lpt{i}" for i in range(1, 10))}
    for part in name.split("/"):
        if (part.split(".")[0] in reserved or any(c in part for c in '<>"|?*')
                or len(part.encode("utf-8")) > 255):
            raise ValueError("Unsafe Windows staging member")
    return name


def digest_tree(members: dict[str, Path]) -> str:
    h = hashlib.sha256(b"swcompat-cix-tree-v1\0")
    total = 0
    for name, path in sorted(members.items()):
        safe_name(name)
        if path.is_symlink() or not path.is_file():
            raise ValueError("Linked or missing staged file")
        length = path.stat().st_size
        total += length
        if total > MAX_TOTAL:
            raise ValueError("Stage exceeds total size limit")
        encoded = name.encode("utf-8")
        h.update(len(encoded).to_bytes(4, "little"))
        h.update(encoded)
        h.update(length.to_bytes(8, "little"))
        h.update(digest_file(path))
    return h.hexdigest()


def inventory(root: Path) -> dict[str, Path]:
    if root.is_symlink() or not root.is_dir():
        raise ValueError("Invalid staged tree")
    result = {}
    for base, dirs, names in os.walk(root, followlinks=False):
        here = Path(base)
        if any((here / name).is_symlink() for name in dirs):
            raise ValueError("Linked staged directory")
        for name in names:
            path = here / name
            if path.is_symlink() or not path.is_file():
                raise ValueError("Linked or special staged member")
            key = safe_name(path.relative_to(root).as_posix())
            if key in result or len(result) >= 12000:
                raise ValueError("Duplicate or excessive staged member")
            result[key] = path
    return result


def copy_verified_tree(members: dict[str, Path], destination: Path,
                       expected_count: int, expected_digest: str) -> dict:
    """Copy only a verified full tree, then independently re-read it."""
    if len(members) != expected_count or digest_tree(members) != expected_digest:
        raise ValueError("Source staging tree incomplete or mismatched")
    if destination.exists() or destination.is_symlink():
        raise ValueError("Staging destination must be fresh")
    parent = destination.parent
    if parent.is_symlink() or not parent.is_dir() or parent.resolve() != parent.absolute():
        raise ValueError("Unsafe staging parent")
    with tempfile.TemporaryDirectory(prefix="swcompat-ipd-copy-", dir=parent) as private:
        staged = Path(private) / "tree"
        staged.mkdir(mode=0o700)
        for name, original in sorted(members.items()):
            target = staged.joinpath(*safe_name(name).split("/"))
            target.parent.mkdir(parents=True, exist_ok=True)
            with original.open("rb") as src, target.open("xb") as dst:
                shutil.copyfileobj(src, dst, length=1024 * 1024)
        actual = inventory(staged)
        if len(actual) != expected_count or digest_tree(actual) != expected_digest:
            raise ValueError("Copied staging tree differs from Windows reference")
        if destination.exists() or destination.is_symlink():
            raise ValueError("Staging collision")
        staged.rename(destination)
    return {
        "stage_verified": True,
        "stage_files": expected_count,
        "stage_root_manifests": sum("/" not in n and n.endswith(".manifest") for n in members),
        "stage_root_mums": sum("/" not in n and n.endswith(".mum") for n in members),
        "stage_catalogs": sum(n.endswith(".cat") for n in members),
        "stage_nested_files": sum("/" in n for n in members),
        "stage_tree_sha256": expected_digest,
    }


def stage_original(members: dict[str, Path], destination: Path) -> dict:
    runner = os.environ.get("RUNNER_TEMP")
    if (not runner or destination.name != "netfx481-ipd-stage"
            or destination.parent.resolve() != Path(runner).resolve()):
        raise ValueError("Stage requires dedicated private CI runner directory")
    return copy_verified_tree(members, destination, EXPECTED_COUNT, EXPECTED_TREE_SHA256)
