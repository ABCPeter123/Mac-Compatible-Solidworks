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


def main():
    root = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
    engine = root / "msxml3-wine-build" / "wiage"
    wine = engine / "bin/wine"
    if engine.is_symlink() or not wine.is_file() or not os.access(wine, os.X_OK):
        raise ValueError("Pinned engine required")
    destination = root / "magevk-pinned" / "libMoltenVK.dylib"
    extract_library(root / "magevk-lib.tar.gz", destination)
    # The upstream Wiage README documents these two loader locations.
    # Never overwrite an existing regular file or an unrelated symlink.
    for directory in (engine / "lib", engine / "lib/wine/x86_64-unix"):
        if not directory.is_dir() or not directory.resolve().is_relative_to(engine.resolve()):
            raise ValueError("Missing engine library directory")
        link = directory / "libvulkan.1.dylib"
        if link.exists() or link.is_symlink():
            if link.resolve() != destination:
                raise ValueError("Existing Vulkan loader must be measured separately")
        else:
            link.symlink_to(destination)
    print("Pinned MageVK loader installed in isolated CI engine")


if __name__ == "__main__":
    main()
