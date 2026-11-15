"""Try upstream Winetricks dotnet48 as a genuine Microsoft .NET 4.8.1 bridge.

Only original signed 4.8.1 media, native CLR validation and disposable Wine.
The Winetricks recipe owns its 4.0 -> 4.8 prerequisite installations.
"""
from __future__ import annotations
import argparse
import json
import os
import re
from pathlib import Path
import subprocess
from scripts.netfx481_trial import validate_prefix, verify_media, probe, wineboot_restart
from scripts.netfx481_payload_audit import snapshot, compare
from scripts.netfx481_clr_load import run as load_clr, STATUSES as LOAD_STATES
from scripts.netfx481_win32_exit import launch, blank as blank_launch, validate as valid_launch

STATES = {"VERB_FAILED", "VERB_TIMED_OUT", "VERB_START_FAILED",
          "PREREQUISITE_NOT_READY", "WINVER_FAILED", "MEASURED"}
UPGRADE = {"NOT_RUN", "COMPLETED", "TIMED_OUT", "START_FAILED", "EXIT_NONZERO",
           "SKIPPED_CHILD_UNVERIFIED", "WINEBOOT_MISSING"}
FILE_STATES = {"NOT_VERIFIED", "ABSENT", "PE_AMD64", "PE_I386",
               "PE_OTHER", "NOT_PE", "LINKED", "IO_ERROR", "INVALID_SIZE"}
CHANGE = {"NOT_VERIFIED", "CREATED", "REMOVED", "CHANGED", "UNCHANGED", "UNVERIFIED"}
LOADER = LOAD_STATES | {"NOT_VERIFIED"}
FAMILY = {"NOT_VERIFIED", "MONO", "UNKNOWN", "MICROSOFT_CLR_CANDIDATE"}
REG = {"NOT_VERIFIED", "NOT_FOUND", "BELOW_481", "AT_LEAST_481", "UNAVAILABLE"}
RELEASE48 = {"NOT_VERIFIED", "NOT_FOUND", "BELOW_48", "AT_LEAST_48"}
MIN_RELEASE_48 = 528040
RELEASE_LINE = re.compile(rb"(?im)^\s*Release\s+REG_DWORD\s+0x([0-9a-f]{1,8})\s*$")


def classify_release_48(raw: bytes, code: int) -> str:
    """Parse only the original 4.8 Release DWORD; never return raw registry output."""
    if code != 0 or len(raw) > 4096 or b"\x00" in raw:
        return "NOT_VERIFIED"
    found = RELEASE_LINE.findall(raw)
    if len(found) != 1:
        return "NOT_FOUND" if not found else "NOT_VERIFIED"
    release = int(found[0], 16)
    return "AT_LEAST_48" if release >= MIN_RELEASE_48 else "BELOW_48"


def probe_release_48(wine: Path, prefix: Path) -> str:
    env = os.environ.copy()
    env.pop("WINEDLLOVERRIDES", None)
    env.update({"WINEPREFIX": str(prefix), "WINEARCH": "win64", "WINEDEBUG": "-all"})
    try:
        r = subprocess.run(
            [str(wine), "reg.exe", "query",
             r"HKLM\Software\Microsoft\NET Framework Setup\NDP\v4\Full",
             "/v", "Release", "/reg:64"], cwd=prefix, env=env,
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, timeout=30, check=False)
        if r.returncode == 1:
            return "NOT_FOUND"
        return classify_release_48(r.stdout, r.returncode)
    except (OSError, subprocess.TimeoutExpired):
        return "NOT_VERIFIED"


def blank(status: str = "VERB_START_FAILED") -> dict:
    return {"status": status, "winetricks48_exit": "NOT_VERIFIED",
            "native48_candidate": False, "native48_release": "NOT_VERIFIED",
            "verb_reboot": "NOT_RUN", "clr64_before481": "NOT_VERIFIED",
            "clr64_after481": "NOT_VERIFIED", "clr64_change": "UNVERIFIED",
            "native_loader": "NOT_VERIFIED", "native_only_managed": "NOT_VERIFIED",
            "runtime_family": "NOT_VERIFIED", "framework481_registry": "NOT_VERIFIED",
            "setup": blank_launch(), "restart": "NOT_RUN",
            "native481_confirmed": False, "solidworks": "NOT_DEMONSTRATED"}


def validate(r: dict) -> bool:
    if type(r) is not dict or set(r) != set(blank()):
        return False
    if (r["status"] not in STATES or
            r["winetricks48_exit"] not in {"NOT_VERIFIED", "ZERO", "NONZERO", "TIMEOUT", "START_FAILED"}
            or type(r["native48_candidate"]) is not bool
            or r["native48_release"] not in RELEASE48
            or r["verb_reboot"] not in UPGRADE
            or r["clr64_before481"] not in FILE_STATES
            or r["clr64_after481"] not in FILE_STATES
            or r["clr64_change"] not in CHANGE
            or r["native_loader"] not in LOADER
            or r["native_only_managed"] not in {"NOT_VERIFIED", "PASS", "FAIL"}
            or r["runtime_family"] not in FAMILY
            or r["framework481_registry"] not in REG
            or not valid_launch(r["setup"])
            or r["restart"] not in UPGRADE
            or type(r["native481_confirmed"]) is not bool
            or r["solidworks"] != "NOT_DEMONSTRATED"):
        return False
    if r["status"] != "MEASURED":
        if r["status"] == "PREREQUISITE_NOT_READY":
            return (r["winetricks48_exit"] in {"ZERO", "NONZERO", "TIMEOUT"}
                    and not r["native48_candidate"] and not r["native481_confirmed"]
                    and r["setup"] == blank_launch())
        return not r["native48_candidate"] and not r["native481_confirmed"]
    if (not r["native48_candidate"] or r["native48_release"] != "AT_LEAST_48"
            or r["clr64_before481"] != "PE_AMD64"):
        return False
    candidate = (r["setup"]["status"] == "EXIT_CAPTURED"
                 and r["setup"]["category"] in {"SUCCESS", "REBOOT_REQUIRED"}
                 and (r["setup"]["category"] == "SUCCESS" or r["restart"] == "COMPLETED")
                 and r["clr64_after481"] == "PE_AMD64"
                 and r["clr64_change"] == "CHANGED"
                 and r["native_loader"] == "LOADED"
                 and r["native_only_managed"] == "PASS"
                 and r["runtime_family"] == "MICROSOFT_CLR_CANDIDATE"
                 and r["framework481_registry"] == "AT_LEAST_481")
    return candidate is r["native481_confirmed"]


def inspect(wine: Path, prefix: Path, tricks: Path, installer481: Path,
            sha481: Path, launcher481: Path, loader: Path, managed: Path,
            timeout: int = 600) -> dict:
    if os.name == "nt" or not 120 <= timeout <= 900:
        raise ValueError("Only bounded disposable Apple Silicon Wine tests supported")
    paths = (wine, prefix, tricks, installer481, sha481, launcher481, loader, managed)
    if any(p.is_symlink() for p in paths):
        raise ValueError("Linked external test input refused")
    wine, prefix, tricks, installer481, sha481, launcher481, loader, managed = (
        p.resolve(strict=True) for p in paths)
    validate_prefix(prefix)
    verify_media(installer481, sha481)
    if (not wine.is_file() or not os.access(wine, os.X_OK)
            or not tricks.is_file() or not os.access(tricks, os.X_OK)
            or launcher481.name != "netfx481_win32_launch.exe"
            or loader.name != "netfx481_clr_load.exe"
            or managed.name != "netfx481_runtime_probe.exe"):
        raise ValueError("Unexpected native test tools")
    env = os.environ.copy()
    for key in ("WINEDLLOVERRIDES", "WINESERVER"):
        env.pop(key, None)
    env.update({"WINEPREFIX": str(prefix), "WINEARCH": "win64",
                "WINE": str(wine), "WINEDEBUG": "-all",
                "PATH": str(wine.parent) + os.pathsep + env.get("PATH", ""),
                "WINETRICKS_LATEST_VERSION_CHECK": "disabled"})
    if (wine.parent / "wineserver").is_file():
        env["WINESERVER"] = str(wine.parent / "wineserver")
    verb_exit = "START_FAILED"
    try:
        process = subprocess.run([str(tricks), "-q", "dotnet48"], cwd=prefix,
                                 env=env, stdin=subprocess.DEVNULL,
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                 check=False, timeout=timeout)
        verb_exit = "ZERO" if process.returncode == 0 else "NONZERO"
    except subprocess.TimeoutExpired:
        verb_exit = "TIMEOUT"
    except OSError:
        return {**blank(), "winetricks48_exit": "START_FAILED"}
    verb_reboot = "NOT_RUN"
    if verb_exit in {"TIMEOUT", "NONZERO"}:
        # A timed-out bootstrapper can have installed a functioning CLR.
        # Quiesce the disposable prefix before native CLR inspection.
        verb_reboot = wineboot_restart(wine, prefix, timeout=120)
        if verb_reboot != "COMPLETED":
            result = {**blank("VERB_TIMED_OUT" if verb_exit == "TIMEOUT" else "VERB_FAILED"),
                      "winetricks48_exit": verb_exit, "verb_reboot": verb_reboot}
            assert validate(result)
            return result
    before = snapshot(prefix)
    runtime = probe(wine, prefix, managed, override="native_only")
    load_before = load_clr(wine, prefix, loader)
    release48 = probe_release_48(wine, prefix)
    native48 = (before["CLR64"][0] == "PE_AMD64"
                and before["MSCORLIB64"][0] == "PE_AMD64"
                and load_before == "LOADED"
                and runtime["clr_family"] == "MICROSOFT_CLR_CANDIDATE"
                and runtime["managed"] == "PASS"
                and release48 == "AT_LEAST_48")
    if not native48:
        result = {**blank("PREREQUISITE_NOT_READY"),
                  "winetricks48_exit": verb_exit, "verb_reboot": verb_reboot,
                  "native48_release": release48,
                  "clr64_before481": before["CLR64"][0],
                  "native_loader": load_before,
                  "native_only_managed": runtime["managed"],
                  "runtime_family": runtime["clr_family"]}
        assert validate(result)
        return result
    try:
        winver = subprocess.run([str(wine), "winecfg.exe", "-v", "win10"],
                                cwd=prefix, env=env,
                                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, timeout=45, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return {**blank("WINVER_FAILED"), "winetricks48_exit": verb_exit}
    if winver.returncode:
        return {**blank("WINVER_FAILED"), "winetricks48_exit": verb_exit}
    setup = launch(wine, prefix, installer481, launcher481,
                   timeout=245, fusion_builtin=True)
    assert valid_launch(setup)
    restart = "NOT_RUN"
    if setup["status"] == "EXIT_CAPTURED" and setup["category"] == "REBOOT_REQUIRED":
        if setup["child_lifecycle"] in {"STILL_ACTIVE", "PARTIAL", "UNKNOWN"}:
            restart = "SKIPPED_CHILD_UNVERIFIED"
        else:
            restart = wineboot_restart(wine, prefix, timeout=120)
    changes = compare(before, snapshot(prefix))
    after = probe(wine, prefix, managed, override="native_only")
    result = {**blank("MEASURED"), "winetricks48_exit": verb_exit,
              "verb_reboot": verb_reboot, "native48_release": release48,
              "native48_candidate": True,
              "clr64_before481": changes["before"]["CLR64"],
              "clr64_after481": changes["after"]["CLR64"],
              "clr64_change": changes["changes"]["CLR64"],
              "native_loader": load_clr(wine, prefix, loader),
              "native_only_managed": after["managed"],
              "runtime_family": after["clr_family"],
              "framework481_registry": after["registry"],
              "setup": setup, "restart": restart}
    result["native481_confirmed"] = (
        setup["status"] == "EXIT_CAPTURED"
        and setup["category"] in {"SUCCESS", "REBOOT_REQUIRED"}
        and (setup["category"] == "SUCCESS" or restart == "COMPLETED")
        and result["clr64_after481"] == "PE_AMD64"
        and result["clr64_change"] == "CHANGED"
        and result["native_loader"] == "LOADED"
        and result["native_only_managed"] == "PASS"
        and result["runtime_family"] == "MICROSOFT_CLR_CANDIDATE"
        and result["framework481_registry"] == "AT_LEAST_481")
    assert validate(result)
    return result


def main() -> int:
    ap = argparse.ArgumentParser(description="Winetricks dotnet48 and original Microsoft 481 chain")
    for name in ("wine", "prefix", "winetricks", "installer481", "sha481",
                 "launcher481", "loader", "managed", "output"):
        ap.add_argument("--" + name, required=True, type=Path)
    ap.add_argument("--timeout", type=int, default=600)
    ap.add_argument("--agree-disposable-prefix", action="store_true", required=True)
    args = ap.parse_args()
    result = inspect(args.wine, args.prefix, args.winetricks, args.installer481,
                     args.sha481, args.launcher481, args.loader, args.managed,
                     args.timeout)
    assert validate(result)
    if args.output.is_symlink():
        raise ValueError("Linked output refused")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, sort_keys=True), encoding="ascii")
    for key in ("status", "winetricks48_exit", "verb_reboot", "native48_release", "native48_candidate",
                "clr64_before481", "clr64_after481", "clr64_change",
                "native_loader", "native_only_managed", "runtime_family",
                "framework481_registry", "restart", "native481_confirmed"):
        print("Native .NET 4.8 to 4.8.1 upgrade", key, result[key])
    for key in ("status", "category", "child_lifecycle"):
        print("Original Microsoft 4.8.1 after native 4.8", key, result["setup"][key])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
