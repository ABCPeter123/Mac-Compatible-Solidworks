"""Genuine Microsoft .NET Framework 4.8.1 installer experiment on Apple Silicon Wine.

Strictly disposable prefixes, original Microsoft-signed Windows payload (signature
verified on Windows CI), complete SHA-256, bounded Windows executable, and a
self-authored managed fixture. A Wine Mono PASS is explicitly NOT .NET 4.8.1.
No arbitrary raw installer logs, hashes, paths, versions, or license data are
included in the emitted report.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import tempfile

SENTINEL = ".swcompat-netfx481-disposable"
MIN_BYTES = 15 * 1024 * 1024
MAX_BYTES = 250 * 1024 * 1024
MAX_PROBE_OUTPUT = 4096
FIELDS = {
    "SCHEMA": {"1"},
    "REGISTRY": {"AT_LEAST_481", "BELOW_481", "NOT_FOUND", "UNAVAILABLE"},
    "CLR_FAMILY": {"MONO", "MICROSOFT_CLR_CANDIDATE", "UNKNOWN"},
    "MANAGED": {"PASS", "FAIL"},
}
LINE = re.compile(r"^SWCOMPAT_NETFX481_([A-Z_]+)=([A-Z0-9_]+)$")
SHA = re.compile(r"[0-9a-fA-F]{64}\Z")


def validate_prefix(prefix: Path) -> None:
    if (prefix.is_symlink() or not (prefix / SENTINEL).is_file()
            or not (prefix / "drive_c").is_dir()
            or not (prefix / "system.reg").is_file()):
        raise ValueError("Only initialized, marked disposable Wine prefixes are allowed")


def verify_media(installer: Path, manifest: Path) -> bool:
    if installer.is_symlink() or manifest.is_symlink():
        raise ValueError("Linked installer files are not permitted")
    if installer.name.casefold() != "ndp481-x86-x64-allos-enu.exe" or not installer.is_file():
        raise ValueError("Expected Microsoft .NET Framework 4.8.1 offline installer")
    if not MIN_BYTES <= installer.stat().st_size <= MAX_BYTES:
        raise ValueError("Unexpected Microsoft installer size")
    expected = manifest.read_text(encoding="ascii").strip()
    if not SHA.fullmatch(expected):
        raise ValueError("Invalid SHA256 manifest")
    digest = hashlib.sha256()
    with installer.open("rb") as stream:
        for data in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(data)
    if digest.hexdigest().lower() != expected.lower():
        raise ValueError("SHA256 mismatch")
    return True


def parse_probe(raw: bytes, exit_code: int) -> dict[str, str]:
    empty = {key.lower(): "NOT_VERIFIED" for key in FIELDS if key != "SCHEMA"}
    if exit_code not in (0, 1) or len(raw) > MAX_PROBE_OUTPUT or b"\x00" in raw:
        return empty
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError:
        return empty
    values: dict[str, str] = {}
    for line in text.splitlines():
        match = LINE.fullmatch(line.strip())
        if not match:
            if line.startswith("SWCOMPAT_NETFX481_"):
                return empty
            continue
        key, value = match.groups()
        if key not in FIELDS or value not in FIELDS[key] or key in values:
            return empty
        values[key] = value
    if set(values) != set(FIELDS) or values["SCHEMA"] != "1":
        return empty
    result = {key.lower(): values[key] for key in FIELDS if key != "SCHEMA"}
    if (result["managed"] == "PASS") != (exit_code == 0):
        return empty
    return result


# Only these isolated DLL-load experiments are accepted; do not modify the
# host Wine prefix or turn off normal Windows DLL loading globally.
NATIVE_DLL_OVERRIDES = {
    "native_first": "mscoree=n,b;clr=n,b",
    "native_only": "mscoree=n;clr=n",
}


def probe(wine: Path, prefix: Path, fixture: Path, timeout: int = 70, *,
          override: str | None = None) -> dict[str, str]:
    if override is not None and override not in NATIVE_DLL_OVERRIDES:
        raise ValueError("Unknown controlled DLL-load experiment")
    env = os.environ.copy()
    env.pop("WINEDLLOVERRIDES", None)
    env.update({"WINEPREFIX": str(prefix), "WINEARCH": "win64", "WINEDEBUG": "-all"})
    if override is not None:
        env["WINEDLLOVERRIDES"] = NATIVE_DLL_OVERRIDES[override]
    with tempfile.TemporaryFile() as out:
        try:
            run = subprocess.run(
                [str(wine), str(fixture)], cwd=fixture.parent, env=env,
                stdin=subprocess.DEVNULL, stdout=out, stderr=subprocess.STDOUT,
                timeout=timeout, check=False,
            )
            exit_code = run.returncode
        except (OSError, subprocess.TimeoutExpired):
            exit_code = 124
        out.seek(0)
        raw = out.read(MAX_PROBE_OUTPUT + 1)
    return parse_probe(raw, exit_code)


def runtime_ready(state: dict[str, str]) -> bool:
    return (state.get("registry") == "AT_LEAST_481"
            and state.get("clr_family") == "MICROSOFT_CLR_CANDIDATE"
            and state.get("managed") == "PASS")


def run_installer(wine: Path, prefix: Path, installer: Path, timeout: int) -> tuple[str, int | None]:
    env = os.environ.copy()
    env.update({"WINEPREFIX": str(prefix), "WINEARCH": "win64", "WINEDEBUG": "-all"})
    # /q is Microsoft's documented unattended option. Do not supply
    # /AcceptEULA or make any claims about licensing agreement on behalf
    # of the end user. The installer may refuse to run without it.
    try:
        proc = subprocess.Popen(
            [str(wine), str(installer), "/q", "/norestart"],
            cwd=installer.parent, env=env, stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
    except OSError:
        return "START_FAILED", None
    try:
        rc = proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGTERM)
        except (OSError, AttributeError):
            proc.kill()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except OSError:
                pass
            proc.wait(timeout=5)
        return "TIMEOUT", None
    return ("EXIT_ZERO" if rc == 0 else "EXIT_NONZERO", rc)


def combine(before: dict, after: dict, termination: str, code: int | None,
            *, native_first: dict | None = None,
            native_only: dict | None = None) -> dict:
    if termination not in {"START_FAILED", "EXIT_ZERO", "EXIT_NONZERO", "TIMEOUT", "SKIPPED_ALREADY_READY"}:
        raise ValueError("Unsupported termination")
    native_first = native_first or {"registry": "NOT_VERIFIED", "clr_family": "NOT_VERIFIED", "managed": "NOT_VERIFIED"}
    native_only = native_only or {"registry": "NOT_VERIFIED", "clr_family": "NOT_VERIFIED", "managed": "NOT_VERIFIED"}
    return {
        "schema": 1,
        "scope": "MICROSOFT_NETFX481_WINE_DISPOSABLE_EXPERIMENT",
        "media_sha256_verified": True,
        "publisher_signature": "VERIFIED_BY_WINDOWS_CI_NOT_THIS_SCRIPT",
        "before": before,
        "after": after,
        "after_native_first": native_first,
        "after_native_only": native_only,
        "install_execution": termination,
        "installer_exit_code": code if termination in {"EXIT_ZERO", "EXIT_NONZERO"} else None,
        "framework_runtime_ready": runtime_ready(after),
        "native_first_runtime_ready": runtime_ready(native_first),
        "native_only_runtime_ready": runtime_ready(native_only),
        "runtime_ready_with_controlled_override": (
            runtime_ready(native_first) or runtime_ready(native_only)
        ),
        "new_framework_installation_confirmed": (
            termination == "EXIT_ZERO" and not runtime_ready(before)
            and (runtime_ready(after) or runtime_ready(native_first) or runtime_ready(native_only))
        ),
        "registry_signal_only": after.get("registry") == "AT_LEAST_481" and not runtime_ready(after),
        "solidworks_compatibility": "NOT_DEMONSTRATED",
    }


def trial(wine: Path, prefix: Path, installer: Path, manifest: Path, fixture: Path,
          timeout: int = 210) -> dict:
    if os.name == "nt":
        raise ValueError("Native Windows execution is not permitted")
    for path in (wine, prefix, installer, manifest, fixture):
        if path.is_symlink():
            raise ValueError("Symbolic link inputs are not permitted")
    wine = wine.resolve(strict=True)
    prefix = prefix.resolve(strict=True)
    installer = installer.resolve(strict=True)
    manifest = manifest.resolve(strict=True)
    fixture = fixture.resolve(strict=True)
    validate_prefix(prefix)
    if not wine.is_file() or not os.access(wine, os.X_OK):
        raise ValueError("Wine executable is missing")
    if fixture.name.casefold() != "netfx481_runtime_probe.exe" or not fixture.is_file():
        raise ValueError("Original compiled .NET runtime fixture missing")
    verify_media(installer, manifest)
    before = probe(wine, prefix, fixture)
    if runtime_ready(before):
        return combine(before, before, "SKIPPED_ALREADY_READY", None)
    termination, code = run_installer(wine, prefix, installer, timeout)
    after = probe(wine, prefix, fixture)
    # Try native Microsoft CLR DLL loading without installing or patching any
    # product binaries. This discriminates Wine Mono being selected by default
    # from a functioning native CLR that Wine's loader could actually invoke.
    native_first = probe(wine, prefix, fixture, override="native_first")
    native_only = probe(wine, prefix, fixture, override="native_only")
    return combine(before, after, termination, code,
                   native_first=native_first, native_only=native_only)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Opt-in signed Microsoft .NET Framework 4.8.1 experiment on disposable Wine")
    ap.add_argument("--wine", type=Path, required=True)
    ap.add_argument("--prefix", type=Path, required=True)
    ap.add_argument("--installer", type=Path, required=True)
    ap.add_argument("--sha256-file", type=Path, required=True)
    ap.add_argument("--probe", type=Path, required=True)
    ap.add_argument("--output", type=Path, required=True)
    ap.add_argument("--timeout", type=int, default=210)
    ap.add_argument("--agree-disposable-prefix", action="store_true", required=True)
    args = ap.parse_args(argv)
    if not 60 <= args.timeout <= 360:
        ap.error("Invalid bounded timeout")
    try:
        if args.output.is_symlink() or args.output.resolve() in {
            args.installer.resolve(), args.sha256_file.resolve(), args.probe.resolve()
        }:
            raise ValueError("Report would overwrite input or symlink")
        result = trial(args.wine, args.prefix, args.installer, args.sha256_file, args.probe, args.timeout)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    except (OSError, ValueError):
        ap.error("Trial refused: inspect disposable Wine setup and verified Microsoft package")
    print("Microsoft .NET 4.8.1 original setup:", result["install_execution"])
    print("Independent Microsoft CLR candidate after:", result["after"]["clr_family"])
    print("Registered .NET 4.8.1 after:", result["after"]["registry"])
    print("Functional managed execution after:", result["after"]["managed"])
    print("Real .NET 4.8.1 readiness:", result["framework_runtime_ready"])
    print("Native-first Microsoft CLR candidate:", result["after_native_first"]["clr_family"])
    print("Native-only Microsoft CLR candidate:", result["after_native_only"]["clr_family"])
    print("Runtime ready with controlled native loading:", result["runtime_ready_with_controlled_override"])
    print("SOLIDWORKS: NOT_DEMONSTRATED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
