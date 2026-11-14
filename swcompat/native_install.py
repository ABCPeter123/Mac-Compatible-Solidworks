"""Local, interactive SOLIDWORKS installation workflow for macOS Wine.

Uses only user-supplied legitimate installation media. It does not download,
modify, patch or redistribute SOLIDWORKS, accept EULAs, enter serials, or
bypass activation. A zero exit code NEVER proves CAD was installed.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import os
from pathlib import Path
import re
import shutil
import subprocess

# SOLIDWORKS 2026 administrative-image prerequisites from Dassault's guide.
# Ordered so actual native prerequisites run before the Installation Manager.
COMPONENTS = (
    ("visual_cpp_x64", "vc_redist.x64.exe"),
    ("visual_cpp_x86", "vc_redist.x86.exe"),
    ("dotnet_481", "ndp481-x86-x64-allos-enu.exe"),
    ("webview2", "MicrosoftEdgeWebView2RuntimeInstallerX64.exe"),
    ("visual_basic", "vba71.msi"),
    ("visual_basic_en", "vba71_1033.msi"),
    ("swcef", "CEF for SOLIDWORKS Applications.msi"),
)

MAX_MEDIA_FILES = 50000
MAX_DEPTH = 9


@dataclass(frozen=True)
class MediaInventory:
    media: Path
    launcher: Path | None
    launcher_kind: str
    components: dict[str, Path | None]
    ambiguous: frozenset[str]

    def public_report(self) -> dict:
        statuses = {
            name: "AMBIGUOUS" if name in self.ambiguous
            else "PRESENT" if path is not None else "MISSING"
            for name, path in self.components.items()
        }
        return {
            "schema": 1,
            "source": "LOCAL_USER_SUPPLIED_MEDIA",
            "launcher": self.launcher_kind,
            "prerequisite_media": statuses,
            "prerequisite_files_complete": all(s == "PRESENT" for s in statuses.values()),
            "installed_runtime_functionality": "NOT_VERIFIED",
            "full_solidworks_installation": "NOT_VERIFIED",
            "activation": "NOT_ATTEMPTED",
        }


def scan_media(location: Path) -> MediaInventory:
    """Find official-media filename candidates, never traverse symlinks.

    Presence means only that a file has that name, not publisher/signature
    authentication, executable validity, installed runtime functionality or
    confirmed complete SOLIDWORKS media.
    """
    location = location.expanduser()
    if location.is_symlink() or not location.exists():
        raise ValueError("Media must be an existing non-symlink file or folder")
    source = location.resolve()
    if source.is_file():
        if source.name.casefold() != "solidworkssetup.exe":
            raise ValueError("Single-file mode accepts only SolidworksSetup.exe")
        return MediaInventory(source, source, "BOOTSTRAPPER_ONLY",
                              {name: None for name, _ in COMPONENTS}, frozenset())
    if not source.is_dir():
        raise ValueError("Invalid media directory")

    wanted = {name.casefold(): key for key, name in COMPONENTS}
    found: dict[str, list[Path]] = {key: [] for key, _ in COMPONENTS}
    launchers: dict[str, Path] = {}
    count = 0
    for directory, dirs, files in os.walk(source, followlinks=False):
        here = Path(directory)
        depth = len(here.relative_to(source).parts)
        dirs[:] = sorted(d for d in dirs if not (here / d).is_symlink()) if depth < MAX_DEPTH else []
        for filename in sorted(files):
            path = here / filename
            if path.is_symlink() or not path.is_file():
                continue
            count += 1
            if count > MAX_MEDIA_FILES:
                raise ValueError("Media scan exceeds safe file count")
            lower = filename.casefold()
            if lower in wanted:
                found[wanted[lower]].append(path)
            if depth == 0 and lower in {"setup.exe", "solidworkssetup.exe", "sldim.exe"}:
                launchers[lower] = path
            elif depth == 1 and here.name.casefold() == "sldim" and lower == "sldim.exe":
                launchers["sldim/sldim.exe"] = path

    # Install manager / full-media candidates take priority over web bootstrap.
    for target in ("setup.exe", "sldim/sldim.exe", "sldim.exe", "solidworkssetup.exe"):
        if target in launchers:
            kind = "BOOTSTRAPPER_ONLY" if target == "solidworkssetup.exe" else "INSTALLATION_MEDIA_CANDIDATE"
            launcher = launchers[target]
            break
    else:
        kind = "NOT_FOUND"
        launcher = None

    components = {name: matches[0] if len(matches) == 1 else None for name, matches in found.items()}
    ambiguous = frozenset(name for name, matches in found.items() if len(matches) > 1)
    return MediaInventory(source, launcher, kind, components, ambiguous)


def validate_prefix(prefix: Path) -> None:
    if prefix.is_symlink() or not prefix.is_dir() or not (prefix / "drive_c").is_dir() or not (prefix / "system.reg").is_file():
        raise ValueError("Wine prefix is not fully initialized")


def wine_env(prefix: Path) -> dict[str, str]:
    env = os.environ.copy()
    env.update({"WINEPREFIX": str(prefix), "WINEARCH": "win64", "WINEDEBUG": "-all"})
    return env


def run_interactive(command: list[str], *, prefix: Path, logs: Path,
                    label: str, cwd: Path, timeout: int | None = None) -> int:
    """Use an actual macOS-hosted Wine process with a visible native GUI.

    Runtime output stays in a private on-device file, never public CI artifacts.
    No timeout is imposed on the user-facing interactive installer.
    """
    logs.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    log = logs / (stamp + "-" + label + "-" + str(os.getpid()) + ".log")
    fd = os.open(log, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as output:
        output.write("SWCompat interactive Wine session. Raw local output is private.\n")
        output.flush()
        try:
            result = subprocess.run(
                command, cwd=cwd, env=wine_env(prefix),
                stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT,
                timeout=timeout, check=False,
            )
            return result.returncode
        except subprocess.TimeoutExpired:
            return 124
        except OSError:
            return 127


def initialize_prefix(wine: Path, prefix: Path, logs: Path) -> str:
    """Create a persistent user-owned Wine environment; never erase one."""
    if prefix.exists() or prefix.is_symlink():
        validate_prefix(prefix)
        return "EXISTING"
    boot = wine.with_name("wineboot")
    if not boot.is_file() or not os.access(boot, os.X_OK):
        fallback = shutil.which("wineboot")
        if not fallback:
            raise ValueError("Wine distribution is missing wineboot")
        boot = Path(fallback)
    prefix.parent.mkdir(parents=True, exist_ok=True)
    status = run_interactive([str(boot), "--init"], prefix=prefix, logs=logs,
                             cwd=prefix.parent, label="wineboot", timeout=240)
    if status != 0:
        raise ValueError("Wine prefix initialization failed")
    validate_prefix(prefix)
    status = run_interactive([str(wine), "winecfg", "/v", "win11"],
                             prefix=prefix, logs=logs, cwd=prefix, label="win11", timeout=60)
    if status != 0:
        raise ValueError("Wine Windows 11 reported-version configuration failed")
    return "CREATED_WINDOWS11_PROFILE"


def install_local(wine: Path, prefix: Path, logs: Path, media: Path, *,
                  install_prerequisites: bool = False, permit_bootstrapper: bool = False,
                  require_webview2_probe: Path | None = None, runner=None) -> int:
    """Launch original media, optionally installing selected official prerequisites.

    This waits for the interactive installer rather than intentionally killing
    it after 120 seconds. Prerequisite process exit is never conflated with
    verification that the Windows runtime functions in Wine.
    """
    if os.name == "nt":
        raise ValueError("Use this Mac/Linux Wine workflow, never native Windows")
    runner = runner or run_interactive
    inventory = scan_media(media)
    if inventory.launcher is None:
        raise ValueError("No recognized SOLIDWORKS setup executable in this media")
    if inventory.launcher_kind == "BOOTSTRAPPER_ONLY" and not permit_bootstrapper:
        raise ValueError("Bootstrapper-only media; use complete installation media or --permit-bootstrapper")
    if install_prerequisites:
        missing = [key for key, path in inventory.components.items()
                   if path is None or key in inventory.ambiguous]
        if missing:
            # Only fixed public component names, not user filesystem paths.
            raise ValueError("Official prerequisite media missing or ambiguous: " + ", ".join(missing))
    if prefix.expanduser().is_symlink():
        raise ValueError("Refusing a symbolic-link Wine prefix")
    prefix = prefix.expanduser().resolve()
    wine = wine.expanduser().resolve()
    if not wine.is_file() or not os.access(wine, os.X_OK):
        raise ValueError("Executable Wine runtime not found")
    print("Original SOLIDWORKS media classification:", inventory.launcher_kind)
    print("Prerequisite presence is not proof of runtime functionality.")
    state = initialize_prefix(wine, prefix, logs)
    print("Persistent Wine prefix:", state)
    if install_prerequisites:
        from .wine_paths import windows_media_path
        for key, _ in COMPONENTS:
            path = inventory.components[key]
            assert path is not None
            command = ([str(wine), "msiexec.exe", "/i", windows_media_path(wine, prefix, path)]
                       if path.suffix.lower() == ".msi" else [str(wine), str(path)])
            print("Starting prerequisite:", key, "(interactive, no EULA automation)")
            code = runner(command, prefix=prefix, logs=logs, label=key, cwd=path.parent)
            print("Prerequisite installer exit:", key, "ZERO_UNVERIFIED" if code == 0 else "NONZERO")
            if code != 0:
                print("Stopped before SOLIDWORKS installer; prerequisite failure requires investigation.")
                return 1
    if require_webview2_probe is not None:
        from .native_webview2 import check_webview2
        if not check_webview2(wine, prefix, require_webview2_probe):
            print("Microsoft WebView2 browser controller: NOT_READY")
            print("SOLIDWORKS installer was not launched.")
            return 1
        print("Microsoft WebView2 browser controller: READY")
    launcher = inventory.launcher
    print("Starting original SOLIDWORKS installation manager interactively (no timeout).")
    command = [str(wine), str(launcher)]
    code = runner(command, prefix=prefix, logs=logs, label="solidworks-setup", cwd=launcher.parent)
    print("SOLIDWORKS installer process:", "EXIT_ZERO_NOT_INSTALLATION_PROOF" if code == 0 else "EXIT_NONZERO")
    print("Installation/activation/CAD: NOT_VERIFIED")
    return 0 if code == 0 else 1
