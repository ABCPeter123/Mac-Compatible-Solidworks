"""Optional native Microsoft 4.0 -> 4.8 intermediary via pinned Winetricks.

This does NOT establish 4.8.1, Wine CBS support, or SOLIDWORKS readiness.
Do not run on an existing user Wine prefix or publish vendor/Winetricks logs.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import tempfile

from scripts.netfx40_msxml3_restart import validate as validate_native40
from scripts.netfx481_clr_load import run as load_clr, STATUSES as LOADER_STATES
from scripts.netfx481_payload_audit import snapshot
from scripts.netfx481_trial import validate_prefix, probe, wineboot_restart

STATES = {"NOT_ELIGIBLE", "MEASURED"}
VERB = {"SUCCESS", "EXIT_NONZERO", "TIMED_OUT", "START_FAILED", "NOT_RUN"}
# Only bounded milestones derived from private Winetricks output may leave CI.
PROGRESS = {"NOT_RUN", "NO_OUTPUT", "WINETRICKS_ACTIVE", "DOTNET48_VERB_SEEN",
            "DOTNET48_PACKAGE_MENTIONED", "OUTPUT_TOO_LARGE"}
MAX_PRIVATE_OUTPUT = 1024 * 1024
BOOT = {"COMPLETED", "TIMED_OUT", "START_FAILED", "EXIT_NONZERO", "NOT_RUN"}
WINVER = {"APPLIED", "FAILED", "NOT_RUN"}
RELEASE = {"NOT_FOUND", "BELOW_48", "NETFX48_RANGE", "AT_LEAST_481", "UNAVAILABLE"}
RELEASE_PATTERN = re.compile(rb"(?i)\bRelease\s+REG_DWORD\s+0x([0-9a-f]{1,8})\b")


def blank() -> dict:
    return {"status": "NOT_ELIGIBLE", "native40_persistent": False,
            "verb": "NOT_RUN", "verb_progress": "NOT_RUN",
            "win7": "NOT_RUN", "win10": "NOT_RUN",
            "restart": "NOT_RUN", "clr64_changed": False,
            "release": "UNAVAILABLE", "loader": "NOT_VERIFIED",
            "native_only_managed": "NOT_VERIFIED",
            "native48_candidate": False, "framework481_confirmed": False,
            "solidworks_compatibility": "NOT_DEMONSTRATED"}


def validate(result: object) -> bool:
    if type(result) is not dict or set(result) != set(blank()):
        return False
    if (result["status"] not in STATES
            or result["verb"] not in VERB or result["verb_progress"] not in PROGRESS
            or result["restart"] not in BOOT
            or result["win7"] not in WINVER or result["win10"] not in WINVER
            or result["release"] not in RELEASE
            or result["loader"] not in LOADER_STATES
            or result["native_only_managed"] not in {"NOT_VERIFIED", "PASS", "FAIL"}
            or result["framework481_confirmed"] is not False
            or result["solidworks_compatibility"] != "NOT_DEMONSTRATED"
            or any(type(result[k]) is not bool for k in (
                "native40_persistent", "clr64_changed", "native48_candidate"))):
        return False
    if result["status"] == "NOT_ELIGIBLE":
        return result == blank()
    eligible = (result["native40_persistent"]
                and result["verb"] == "SUCCESS"
                and result["win7"] == "APPLIED"
                and result["win10"] == "APPLIED"
                and result["restart"] == "COMPLETED"
                and result["clr64_changed"]
                and result["release"] == "NETFX48_RANGE"
                and result["loader"] == "LOADED"
                and result["native_only_managed"] == "PASS")
    return result["native48_candidate"] == eligible


def parse_release(raw: bytes, exit_code: int) -> str:
    if exit_code == 1:
        return "NOT_FOUND"
    if exit_code != 0 or not isinstance(raw, bytes) or len(raw) > 4096:
        return "UNAVAILABLE"
    match = RELEASE_PATTERN.search(raw)
    if not match or len(RELEASE_PATTERN.findall(raw)) != 1:
        return "UNAVAILABLE"
    value = int(match.group(1), 16)
    return ("AT_LEAST_481" if value >= 533320
            else "NETFX48_RANGE" if value >= 528040
            else "BELOW_48")


def _env(wine: Path, prefix: Path) -> dict[str, str]:
    env = os.environ.copy()
    for name in ("WINEDLLOVERRIDES", "WINESERVER", "WINETRICKS_FORCE",
                 "WINE_BIN", "WINESERVER_BIN", "WINE_BINDIR"):
        env.pop(name, None)
    env.update({"WINEPREFIX": str(prefix), "WINEARCH": "win64",
                "WINE": str(wine), "WINE_BIN": str(wine),
                "WINE_BINDIR": str(wine.parent), "WINEDEBUG": "-all",
                "PATH": str(wine.parent) + os.pathsep + env.get("PATH", ""),
                "WINETRICKS_LATEST_VERSION_CHECK": "disabled"})
    wineserver = wine.parent / "wineserver"
    if wineserver.is_file() and os.access(wineserver, os.X_OK):
        env["WINESERVER"] = str(wineserver)
        env["WINESERVER_BIN"] = str(wineserver)
    return env


def _run(command: list[str], env: dict[str, str], cwd: Path,
         timeout: int) -> str:
    try:
        child = subprocess.run(command, cwd=cwd, env=env,
                               stdin=subprocess.DEVNULL,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                               timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        return "TIMED_OUT"
    except OSError:
        return "START_FAILED"
    return "SUCCESS" if child.returncode == 0 else "EXIT_NONZERO"



def classify_progress(raw: bytes) -> str:
    """Return fixed milestones, never raw Winetricks or Microsoft setup text.

    A package mention does not prove that the package installer executed.
    """
    if len(raw) > MAX_PRIVATE_OUTPUT:
        return "OUTPUT_TOO_LARGE"
    if not raw:
        return "NO_OUTPUT"
    if re.search(rb"(?i)(?:dotnetfx48[_-]full|ndp48[-_].*?\.exe)", raw):
        return "DOTNET48_PACKAGE_MENTIONED"
    if re.search(rb"(?i)(?:load_dotnet48|install_dotnet48)", raw):
        return "DOTNET48_VERB_SEEN"
    return "WINETRICKS_ACTIVE"


def _terminate_group(child: subprocess.Popen) -> None:
    """Timeout must kill the whole installer session, not just its shell."""
    try:
        os.killpg(child.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        child.wait(timeout=5)
    except subprocess.TimeoutExpired:
        pass
    # A parent shell can exit while an installer descendant is still alive.
    # Send SIGKILL to the group regardless of the parent's status.
    try:
        os.killpg(child.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        child.wait(timeout=5)
    except subprocess.TimeoutExpired:
        pass


def _run_winetricks(command: list[str], env: dict[str, str],
                    cwd: Path, timeout: int) -> tuple[str, str]:
    """Bound the verb and keep its entire diagnostic stream private."""
    with tempfile.TemporaryFile() as output:
        try:
            child = subprocess.Popen(
                command, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                stdout=output, stderr=subprocess.STDOUT,
                start_new_session=True,
            )
        except OSError:
            return "START_FAILED", "NOT_RUN"
        try:
            rc = child.wait(timeout=timeout)
            status = "SUCCESS" if rc == 0 else "EXIT_NONZERO"
        except subprocess.TimeoutExpired:
            _terminate_group(child)
            status = "TIMED_OUT"
        output.seek(0)
        progress = classify_progress(output.read(MAX_PRIVATE_OUTPUT + 1))
    return status, progress


def _set_winver(wine: Path, prefix: Path, env: dict[str, str],
                value: str) -> str:
    if value not in {"win7", "win10"}:
        raise ValueError("Invalid setup profile")
    state = _run([str(wine), "winecfg.exe", "-v", value], env, prefix, 45)
    return "APPLIED" if state == "SUCCESS" else "FAILED"


def _release(wine: Path, prefix: Path, env: dict[str, str]) -> str:
    key = r"HKLM\Software\Microsoft\NET Framework Setup\NDP\v4\Full"
    with tempfile.TemporaryFile() as f:
        try:
            child = subprocess.run([str(wine), "reg.exe", "query", key, "/v", "Release"],
                                   cwd=prefix, env=env, stdin=subprocess.DEVNULL,
                                   stdout=f, stderr=subprocess.DEVNULL,
                                   timeout=25, check=False)
        except (OSError, subprocess.TimeoutExpired):
            return "UNAVAILABLE"
        f.seek(0)
        return parse_release(f.read(4097), child.returncode)


def inspect(wine: Path, prefix: Path, winetricks: Path, loader: Path,
            managed: Path, native40: dict, *, timeout: int = 840) -> dict:
    if os.name == "nt" or not 120 <= timeout <= 900:
        raise ValueError("Only bounded disposable Wine tests supported")
    if any(p.is_symlink() for p in (wine, prefix, winetricks, loader, managed)):
        raise ValueError("Linked experiment input")
    wine, prefix, winetricks, loader, managed = (
        p.resolve(strict=True) for p in (wine, prefix, winetricks, loader, managed))
    validate_prefix(prefix)
    if (not validate_native40(native40)
            or not native40["persistent_native_managed"]):
        return blank()
    if (loader.name != "netfx481_clr_load.exe"
            or managed.name != "netfx481_runtime_probe.exe"
            or winetricks.name not in {"winetricks", "winetricks.sh"}
            or not wine.is_file() or not os.access(wine, os.X_OK)
            or not winetricks.is_file() or not os.access(winetricks, os.X_OK)):
        raise ValueError("Unexpected runtime test inputs")
    before = snapshot(prefix)
    if (before["CLR64"][0] != "PE_AMD64"
            or load_clr(wine, prefix, loader) != "LOADED"
            or probe(wine, prefix, managed, override="native_only")["managed"] != "PASS"):
        return blank()
    env = _env(wine, prefix)
    win7 = _set_winver(wine, prefix, env, "win7")
    verb = "NOT_RUN"
    verb_progress = "NOT_RUN"
    try:
        if win7 == "APPLIED":
            verb, verb_progress = _run_winetricks(
                ["bash", str(winetricks), "-q", "dotnet48"], env, prefix, timeout)
    finally:
        win10 = _set_winver(wine, prefix, env, "win10")
    restart = wineboot_restart(wine, prefix) if win10 == "APPLIED" else "NOT_RUN"
    after = snapshot(prefix)
    same = before["CLR64"][1] == after["CLR64"][1]
    output = {"status": "MEASURED", "native40_persistent": True,
              "verb": verb, "verb_progress": verb_progress,
              "win7": win7, "win10": win10,
              "restart": restart,
              "clr64_changed": (not same and after["CLR64"][0] == "PE_AMD64"),
              "release": _release(wine, prefix, env),
              "loader": load_clr(wine, prefix, loader),
              "native_only_managed": probe(
                  wine, prefix, managed, override="native_only")["managed"],
              "native48_candidate": False, "framework481_confirmed": False,
              "solidworks_compatibility": "NOT_DEMONSTRATED"}
    output["native48_candidate"] = (
        output["verb"] == "SUCCESS" and output["win7"] == "APPLIED"
        and output["win10"] == "APPLIED" and output["restart"] == "COMPLETED"
        and output["clr64_changed"]
        and output["release"] == "NETFX48_RANGE"
        and output["loader"] == "LOADED"
        and output["native_only_managed"] == "PASS")
    if not validate(output):
        raise ValueError("Invalid original 4.8 intermediate runtime outcome")
    return output


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Isolated native .NET 4.8 interim prerequisite")
    for field in ("wine", "prefix", "winetricks", "loader", "managed",
                  "native40-report", "output"):
        p.add_argument("--" + field, type=Path, required=True)
    p.add_argument("--timeout", type=int, default=840)
    p.add_argument("--agree-disposable-prefix", action="store_true", required=True)
    args = p.parse_args(argv)
    result = inspect(args.wine, args.prefix, args.winetricks, args.loader,
                     args.managed, json.loads(args.native40_report.read_text()),
                     timeout=args.timeout)
    if args.output.is_symlink():
        raise ValueError("Linked result file")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, sort_keys=True), encoding="ascii")
    for field, value in result.items():
        print("Native Microsoft .NET 4.8 intermediate", field, value)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
