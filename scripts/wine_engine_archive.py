"""Verify pinned experimental Wine runtime archive paths before extraction.

Authenticity comes from the release SHA256 check in the caller. This module
only checks extraction metadata for path traversal, out-of-tree symlinks and
special device files. It never extracts or runs the archive itself.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import posixpath
import tarfile

MAX_ENTRIES = 100000
MAX_EXPANDED = 4 * 1024 * 1024 * 1024
EXPECTED_ROOT = "wiage"
WINE = "wiage/bin/wine"
SERVER = "wiage/bin/wineserver"


def _safe_name(name: str) -> bool:
    if (not name or name.startswith("/") or chr(92) in name
            or chr(0) in name or len(name) > 1024):
        return False
    parts = name.split("/")
    return (".." not in parts
            and posixpath.normpath(name).split("/")[0] == EXPECTED_ROOT)


MAX_APPLEDOUBLE = 1024 * 1024


def _appledouble_sidecar(member: tarfile.TarInfo) -> bool:
    """Accept only small regular AppleDouble metadata that will be excluded.

    The SHA256-pinned macOS tar includes '._wiage' and nested sidecars.
    Neither host metadata nor an unexpected symlink can be executable Wine.
    """
    name = member.name
    parts = name.split("/")
    if (not name or name.startswith("/") or chr(92) in name
            or ".." in parts or chr(0) in name or len(name) > 1024):
        return False
    normalized = posixpath.normpath(name)
    if normalized == "._wiage":
        return member.isfile() and member.size <= MAX_APPLEDOUBLE
    if not normalized.startswith(EXPECTED_ROOT + "/"):
        return False
    basename = posixpath.basename(normalized)
    return (basename.startswith("._") and len(basename) > 2
            and member.isfile() and member.size <= MAX_APPLEDOUBLE)


def verify(path: Path) -> dict[str, object]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("Only downloaded, authenticated regular runtime archives")
    seen = set()
    has_wine = False
    has_server = False
    size = 0
    count = 0
    try:
        with tarfile.open(path, "r:gz") as archive:
            for member in archive:
                count += 1
                if count > MAX_ENTRIES:
                    raise ValueError("Excessive Wine runtime archive entries")
                name = posixpath.normpath(member.name)
                # tar -czf runtime.tar.gz -C dist . emits an initial './'
                # directory. This is safe only when it is a directory;
                # never permit a root-level file or root-level symlink.
                if name == "." and member.isdir():
                    continue
                # Exact publisher archive includes AppleDouble host metadata.
                # These never count toward Wine payloads and MUST be excluded
                # by both macOS and Linux extraction commands.
                if _appledouble_sidecar(member):
                    size += member.size
                    if size > MAX_EXPANDED:
                        raise ValueError("Excessive expanded Wine metadata")
                    if name in seen:
                        raise ValueError("Duplicate Wine host metadata")
                    seen.add(name)
                    continue
                if not _safe_name(member.name):
                    raise ValueError("Unsafe Wine runtime archive entry")
                if name in seen and not member.isdir():
                    raise ValueError("Duplicate Wine runtime file")
                seen.add(name)
                if not (member.isdir() or member.isfile()
                        or member.issym() or member.islnk()):
                    raise ValueError("Unsafe Wine runtime device or special entry")
                if member.isfile():
                    size += member.size
                    if size > MAX_EXPANDED:
                        raise ValueError("Excessive expanded Wine runtime")
                elif member.issym() or member.islnk():
                    target = (posixpath.join(posixpath.dirname(name), member.linkname)
                              if member.issym() else member.linkname)
                    if (not member.linkname or member.linkname.startswith("/")
                            or not _safe_name(posixpath.normpath(target))):
                        raise ValueError("Wine runtime link escapes archive root")
                if name == WINE:
                    has_wine = member.isfile() or member.issym() or member.islnk()
                elif name == SERVER:
                    has_server = member.isfile() or member.issym() or member.islnk()
    except (OSError, EOFError, tarfile.TarError) as exc:
        raise ValueError("Unreadable pinned Wine runtime archive") from exc
    if not (has_wine and has_server):
        raise ValueError("Pinned Wine runtime lacks expected wine/wineserver")
    return {"status": "SAFE", "files_checked": count}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--archive", type=Path, required=True)
    report = verify(parser.parse_args().archive)
    assert report["status"] == "SAFE" and report["files_checked"] > 0
    print("Experimental authenticated Wine runtime archive metadata: SAFE")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
