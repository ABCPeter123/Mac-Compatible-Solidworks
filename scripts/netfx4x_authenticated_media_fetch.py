"""Download genuine Microsoft .NET installers privately, never via Actions artifacts.

Windows CI first Authenticode-verifies each independently downloaded Microsoft
installer and uploads only its SHA-256 digest alongside self-authored binaries.
A macOS runner then downloads the original from Microsoft's fixed URL and
requires exact same-run digest equality before use in its disposable Wine prefix.
The original installer stays in local ephemeral build/ and is NEVER uploaded.
"""
from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import re
import subprocess
import tempfile

# Media filenames and HTTPS sources are strictly hardcoded. No user URL input.
MEDIA = {
    "40": (
        "dotNetFx40_Full_x86_x64.exe", "netfx40.sha256",
        "https://download.microsoft.com/download/9/5/A/95A9616B-7A37-4AF6-BC36-D6EA96C8DAAE/dotNetFx40_Full_x86_x64.exe",
    ),
    "48": (
        "NDP48-x86-x64-AllOS-ENU.exe", "netfx48.sha256",
        "https://download.microsoft.com/download/f/3/a/f3a6af84-da23-40a5-8d1c-49cc10c8e76f/NDP48-x86-x64-AllOS-ENU.exe",
    ),
    "481": (
        "NDP481-x86-x64-AllOS-ENU.exe", "netfx481.sha256",
        "https://download.microsoft.com/download/4/b/2/cd00d4ed-ebdd-49ee-8a33-eabc3d1030e3/NDP481-x86-x64-AllOS-ENU.exe",
    ),
}
KNOWN_ORIGINAL40_SHA256 = "65e064258f2e418816b304f646ff9e87af101e4c9552ab064bb74d281c38659f"
MIN_BYTES = 15 * 1024 * 1024
MAX_BYTES = 250 * 1024 * 1024
DIGEST = re.compile(r"[a-f0-9]{64}\Z")


def verified_windows_digest(build: Path, version: str) -> str:
    """Read only the exact checksum emitted by Authenticode-valid Windows CI."""
    if version not in MEDIA:
        raise ValueError("Unrecognized original framework media")
    file = build / MEDIA[version][1]
    if file.is_symlink() or not file.is_file() or file.stat().st_size > 80:
        raise ValueError("Authenticated Windows digest missing or invalid")
    try:
        value = file.read_text(encoding="ascii")
    except (UnicodeError, OSError) as exc:
        raise ValueError("Invalid signed-Windows digest") from exc
    if not DIGEST.fullmatch(value):
        raise ValueError("Signed-Windows digest must be 64 lowercase hex characters")
    if version == "40" and value != KNOWN_ORIGINAL40_SHA256:
        raise ValueError("Original .NET 4.0 no longer matches pinned upstream media")
    return value


def private_download(build: Path, version: str, expected: str) -> None:
    """Never print original media, original files, URLs or diagnostic output."""
    filename, _, url = MEDIA[version]
    final = build / filename
    if final.exists() or final.is_symlink():
        raise ValueError("Refusing to overwrite any Microsoft installer")
    fd, tmp_name = tempfile.mkstemp(prefix=".original-netfx-", suffix=".tmp", dir=build)
    os.close(fd)
    tmp = Path(tmp_name)
    try:
        try:
            result = subprocess.run(
                ["curl", "--fail", "--location", "--silent", "--retry", "3",
                 "--connect-timeout", "30", "--max-time", "600", "--output",
                 str(tmp), url],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, timeout=660, check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ValueError("Private Microsoft media retrieval did not complete") from exc
        if result.returncode != 0:
            raise ValueError("Private Microsoft media retrieval failed")
        size = tmp.stat().st_size
        if not MIN_BYTES <= size <= MAX_BYTES:
            raise ValueError("Original Microsoft media length not accepted")
        digest = hashlib.sha256()
        with tmp.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        if digest.hexdigest() != expected:
            raise ValueError("Microsoft media differs from Windows Authenticode reference")
        if final.exists() or final.is_symlink():
            raise ValueError("Private installer destination changed during download")
        os.replace(tmp, final)
    finally:
        tmp.unlink(missing_ok=True)


def stage(build: Path, versions: list[str]) -> None:
    if build.is_symlink() or not build.is_dir():
        raise ValueError("Expected safe local build directory")
    if not versions or len(set(versions)) != len(versions) or any(v not in MEDIA for v in versions):
        raise ValueError("Invalid requested framework versions")
    # Authenticate every expected checksum before downloading any original.
    digests = {v: verified_windows_digest(build, v) for v in versions}
    for version in versions:
        private_download(build, version, digests[version])
        print("AUTHENTIC_MICROSOFT_NETFX_PRIVATE_DOWNLOAD", version, "SHA256_VERIFIED")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--build", type=Path, default=Path("build"))
    parser.add_argument("--version", choices=tuple(MEDIA), required=True,
                        action="append")
    args = parser.parse_args(argv)
    stage(args.build, args.version)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
