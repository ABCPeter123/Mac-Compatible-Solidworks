"""Install one checksum-pinned upstream MageVK dylib in a disposable CI engine.

Do not unpack archive paths or trust its symlinks. No user prefix is changed.
"""
import hashlib
import os
from pathlib import Path, PurePosixPath
import shutil
import tarfile

DIGEST = "849d24b809f60e73631e6fa9d92bfbeea04178ceb04ad828bfd457a02a9452e5"
MAX_LIBRARY = 128 * 1024 * 1024


def extract_library(archive: Path, target: Path, *, digest: str = DIGEST):
    if archive.is_symlink() or not archive.is_file() or target.exists() or target.is_symlink():
        raise ValueError("Require regular archive and fresh target")
    with archive.open("rb") as f:
        if hashlib.file_digest(f, "sha256").hexdigest() != digest:
            raise ValueError("MageVK archive digest mismatch")
    with tarfile.open(archive, "r:gz") as tar:
        candidates = []
        for member in tar:
            p = PurePosixPath(member.name)
            if p.is_absolute() or ".." in p.parts:
                raise ValueError("Unsafe archive path")
            if p.name == "libMoltenVK.dylib" and member.isfile():
                if not 1024 <= member.size <= MAX_LIBRARY:
                    raise ValueError("Unexpected library size")
                candidates.append(member)
        if len(candidates) != 1:
            raise ValueError("Expected one regular MoltenVK library")
        target.parent.mkdir(parents=True, exist_ok=True)
        with tar.extractfile(candidates[0]) as source, target.open("xb") as out:
            shutil.copyfileobj(source, out)
        if target.stat().st_size != candidates[0].size:
            target.unlink()
            raise ValueError("Incomplete library")
    return target


def wire_loader(engine: Path, destination: Path):
    """Keep the original entries for inspection; only modify this private engine."""
    if destination.is_symlink() or not destination.is_file():
        raise ValueError("Verified regular replacement required")
    directories = (engine / "lib", engine / "lib/wine/x86_64-unix")
    entries = []
    for directory in directories:
        if not directory.is_dir() or not directory.resolve().is_relative_to(engine.resolve()):
            raise ValueError("Missing engine library directory")
        link = directory / "libvulkan.1.dylib"
        backup = directory / "libvulkan.1.dylib.swcompat-original"
        if backup.exists() or backup.is_symlink():
            raise ValueError("Unexpected previous backup")
        if link.is_symlink():
            category = "SYMLINK_RESOLVED" if link.exists() else "SYMLINK_DANGLING"
        elif link.is_file():
            category = "REGULAR_FILE"
        elif link.exists():
            raise ValueError("Unexpected Vulkan loader type")
        else:
            category = "ABSENT"
        entries.append((link, backup, category))
    completed = []
    try:
        for link, backup, category in entries:
            if category != "ABSENT":
                link.rename(backup)
            completed.append((link, backup, category))
            link.symlink_to(destination)
            if not link.is_file() or link.resolve() != destination.resolve():
                raise ValueError("Replacement loader did not resolve")
    except Exception:
        for link, backup, category in reversed(completed):
            if link.is_symlink():
                link.unlink()
            if category != "ABSENT":
                backup.rename(link)
        raise
    for i, (_, _, category) in enumerate(entries):
        print("Original Vulkan loader slot", i, ":", category)


def main():
    root = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
    engine = root / "msxml3-wine-build" / "wiage"
    wine = engine / "bin/wine"
    if (engine.is_symlink() or engine.resolve() != engine
            or not wine.is_file() or not os.access(wine, os.X_OK)):
        raise ValueError("Pinned engine required")
    destination = root / "magevk-pinned" / "libMoltenVK.dylib"
    extract_library(root / "magevk-lib.tar.gz", destination)
    wire_loader(engine, destination)
    print("Pinned MageVK loader installed in isolated CI engine")


if __name__ == "__main__":
    main()
