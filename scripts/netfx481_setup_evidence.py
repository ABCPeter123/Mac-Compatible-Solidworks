"""Private, allowlisted .NET Framework setup log classification for disposable Wine.

The Microsoft /log transcript remains inside the short-lived Wine prefix and
is NEVER printed, uploaded or copied into the sanitized report. Return
fixed-schema enumerations only; neither raw paths nor arbitrary error strings.
"""
from __future__ import annotations

from pathlib import Path
import re

FOLDER = "swcompat-netfx481-private"
NAME = "framework-setup.txt"
WINDOWS_LOG_PATH = r"C:\swcompat-netfx481-private\framework-setup.txt"
MAX_LOG_BYTES = 8 * 1024 * 1024

# Codes are preselected public Windows error classifications, not user input.
KNOWN_CODES = {
    "0X80070005": "ACCESS_DENIED",
    "0X80070002": "FILE_NOT_FOUND",
    "0X8007007E": "MODULE_NOT_FOUND",
    "0X800700C1": "BAD_EXECUTABLE_FORMAT",
    "0X80070422": "WINDOWS_SERVICE_DISABLED",
    "0X80070424": "WINDOWS_SERVICE_MISSING",
    "0X80070643": "MSI_FATAL_ERROR",
    "0X80070652": "INSTALL_ALREADY_RUNNING",
    "0X800F081F": "SERVICING_SOURCE_MISSING",
    "0X800F0922": "SERVICING_FAILURE",
    "0X800F081E": "SERVICING_NOT_APPLICABLE",
    "0X80004005": "UNSPECIFIED_FAILURE",
}

# Only use codes on log lines that actually report an error or failed action.
ERROR_LINE = re.compile(r"(?i)\b(fail(?:ed|ure)?|error|result|return(?:ed)? code|hresult)\b")
HEX_CODE = re.compile(r"(?i)(?<![a-z0-9])0x[0-9a-f]{8}(?![a-z0-9])")
PHASE_HINTS = (
    ("SERVICING", re.compile(r"(?i)\b(cbs|servicing|dism|component store|windows update)\b")),
    ("MSI_INSTALL", re.compile(r"(?i)\b(msi|msiexec|windows installer|custom action|msp)\b")),
    ("PAYLOAD_EXTRACTION", re.compile(r"(?i)\b(extract|decompress|unpack)\b")),
    ("PREREQUISITE", re.compile(r"(?i)\b(prerequisite|os version|unsupported|blocked|system requirement)\b")),
    ("REBOOT", re.compile(r"(?i)\b(reboot|restart|pending restart)\b")),
)
KNOWN_PHASES = {name for name, _ in PHASE_HINTS} | {"UNKNOWN"}
KNOWN_RESULTS = {"NOT_REQUESTED", "NOT_FOUND", "EMPTY", "TOO_LARGE", "INVALID_ENCODING", "READ_FAILED", "CLASSIFIED"}


def private_log_path(prefix: Path) -> Path:
    """Produce a hard-coded C: drive location, never a user-supplied path."""
    from scripts.netfx481_trial import validate_prefix
    validate_prefix(prefix)
    target = prefix / "drive_c" / FOLDER
    if target.is_symlink():
        raise ValueError("Linked diagnostic directory")
    target.mkdir(mode=0o700, exist_ok=True)
    if not target.is_dir():
        raise ValueError("Invalid diagnostic folder")
    output = target / NAME
    if output.is_symlink() or output.exists():
        raise ValueError("Pre-existing or linked setup transcript")
    return output


def _decode(raw: bytes) -> str | None:
    if raw.startswith(b"\xff\xfe") or raw.startswith(b"\xfe\xff"):
        try:
            return raw.decode("utf-16")
        except UnicodeDecodeError:
            return None
    if raw.count(b"\x00") > max(16, len(raw) // 10):
        try:
            return raw.decode("utf-16-le")
        except UnicodeDecodeError:
            return None
    try:
        return raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        # Windows .NET installer logs may contain localized Windows-1252.
        try:
            return raw.decode("cp1252")
        except UnicodeDecodeError:
            return None


def classify_text(raw: bytes) -> dict[str, object]:
    """Report only predefined failure categories, never original transcript."""
    if len(raw) > MAX_LOG_BYTES:
        return {"status": "TOO_LARGE", "phase": "UNKNOWN", "codes": []}
    if not raw:
        return {"status": "EMPTY", "phase": "UNKNOWN", "codes": []}
    decoded = _decode(raw)
    if decoded is None:
        return {"status": "INVALID_ENCODING", "phase": "UNKNOWN", "codes": []}
    counts: dict[str, int] = {phase: 0 for phase in KNOWN_PHASES}
    found: set[str] = set()
    for line in decoded.splitlines():
        if len(line) > 8192:
            continue
        if not ERROR_LINE.search(line):
            continue
        for phase, pattern in PHASE_HINTS:
            if pattern.search(line):
                counts[phase] += 1
        for m in HEX_CODE.finditer(line):
            code = KNOWN_CODES.get(m.group().upper())
            if code:
                found.add(code)
    # Report the most frequently associated failure phase, never copy wording.
    relevant = [p for p in PHASE_HINTS if counts[p[0]] > 0]
    phase = max(relevant, key=lambda p: counts[p[0]])[0] if relevant else "UNKNOWN"
    return {"status": "CLASSIFIED", "phase": phase, "codes": sorted(found)}


def classify_log(logfile: Path) -> dict[str, object]:
    if logfile.is_symlink():
        return {"status": "READ_FAILED", "phase": "UNKNOWN", "codes": []}
    try:
        if not logfile.is_file():
            return {"status": "NOT_FOUND", "phase": "UNKNOWN", "codes": []}
        with logfile.open("rb") as file:
            raw = file.read(MAX_LOG_BYTES + 1)
    except OSError:
        return {"status": "READ_FAILED", "phase": "UNKNOWN", "codes": []}
    return classify_text(raw)


def discard_log(logfile: Path) -> None:
    """Remove only the one fixed output, not any user or Microsoft files."""
    if not logfile.is_symlink():
        try:
            logfile.unlink(missing_ok=True)
            logfile.parent.rmdir()
        except OSError:
            pass


# Microsoft .NET deployment can write additional bootstrapper, setup utility,
# CBS and framework logs to Windows %TEMP% and servicing directories. Inspect
# *only* ephemeral Wine-owned paths, with a strict bounded search and NO raw
# log content, filenames, error messages or paths in the result.
SECONDARY_MAX_FILES = 24
SECONDARY_MAX_DIRS = 120
SECONDARY_MAX_PER_FILE = 2 * 1024 * 1024
_SECONDARY_FILENAME = re.compile(
    r"(?i)^(?:dd_[a-z0-9_.() -]{1,120}\.(?:txt|log|html)"
    r"|NetFxSetupEvents\.txt"
    r"|Microsoft \.NET Framework 4(?:\.8(?:\.1)?)? Setup_[a-z0-9_.() -]{1,100}\.(?:txt|html)"
    r"|CBS\.log)$"
)
SECONDARY_SOURCE_NAMES = {
    "BOOTSTRAPPER_TEMP", "FRAMEWORK_SETUP", "SETUP_EVENTS", "SERVICING_CBS"
}
SECONDARY_STATUSES = {"NOT_REQUESTED", "NOT_FOUND", "CLASSIFIED", "PARTIAL_SCAN", "INVALID_ROOT"}
SECONDARY_FAMILIES = {"NETFX481", "NETFX48"}


def _source_group(name: str) -> str:
    lowered = name.lower()
    if lowered == "cbs.log":
        return "SERVICING_CBS"
    if lowered.startswith("microsoft .net framework"):
        return "FRAMEWORK_SETUP"
    if lowered == "netfxsetupevents.txt":
        return "SETUP_EVENTS"
    return "BOOTSTRAPPER_TEMP"


def _is_481_log_name(name: str) -> bool:
    """Require an explicit 4.8.1 source name before attributing a StopBlock.

    Generic dd_, CBS, and NetFxSetupEvents logs may belong to the preceding
    .NET 4.0 or msxml3 installation. Never merge their blockers into 4.8.1.
    """
    lower = name.casefold()
    return (lower.startswith("microsoft .net framework 4.8.1 setup_")
            or lower.startswith(("dd_ndp481", "dd_netfx481", "dd_dotnetfx481")))


def _is_target_log_name(name: str, family: str) -> bool:
    """Only attribute a setup-named blocker to its original framework family."""
    if family not in SECONDARY_FAMILIES:
        raise ValueError("Unsupported original setup family")
    if family == "NETFX481":
        return _is_481_log_name(name)
    lower = name.casefold()
    return (lower.startswith("microsoft .net framework 4.8 setup_")
            or lower.startswith(("dd_ndp48-", "dd_ndp48_", "dd_netfx48-",
                                 "dd_netfx48_", "dd_dotnetfx48-",
                                 "dd_dotnetfx48_")))


def _secondary_roots(prefix: Path) -> list[Path]:
    drive_c = prefix / "drive_c"
    return [
        drive_c / "users",
        drive_c / "windows" / "temp",
        drive_c / "windows" / "Temp",
        drive_c / "Temp",
        drive_c / "windows" / "logs" / "CBS",
    ]


def _metadata(file: Path) -> tuple[int, int, int]:
    """Private identity and modification fields, never copied into evidence."""
    import os
    stat = file.stat(follow_symlinks=False)
    return (stat.st_ino, stat.st_size, stat.st_mtime_ns)


def snapshot_secondary_logs(prefix: Path) -> dict[Path, tuple[int, int, int]]:
    """Capture bounded pre-upgrade file metadata, without reading log content.

    If enumeration is incomplete, refuse attribution rather than treating old
    files outside the inventory as if they were created by .NET 4.8.1.
    """
    import os
    from scripts.netfx481_trial import validate_prefix

    validate_prefix(prefix)
    baseline: dict[Path, tuple[int, int, int]] = {}
    directories = 0
    for root in _secondary_roots(prefix):
        if not root.exists():
            continue
        if root.is_symlink() or not root.is_dir():
            raise ValueError("Unsafe secondary setup root")
        for current, subdirs, names in os.walk(root, topdown=True, followlinks=False):
            directories += 1
            if directories > SECONDARY_MAX_DIRS:
                raise ValueError("Secondary setup metadata directory limit")
            base = Path(current)
            if len(base.relative_to(root).parts) >= 7:
                subdirs.clear()
            else:
                subdirs[:] = sorted(x for x in subdirs
                                   if not (base / x).is_symlink())[:24]
            for name in sorted(names):
                if not _SECONDARY_FILENAME.fullmatch(name):
                    continue
                file = base / name
                if file.is_symlink() or not file.is_file() or file in baseline:
                    continue
                if len(baseline) >= SECONDARY_MAX_FILES:
                    raise ValueError("Secondary setup metadata file limit")
                baseline[file] = _metadata(file)
    return baseline


def scan_secondary_logs(prefix: Path, *,
                        baseline: dict[Path, tuple[int, int, int]] | None = None,
                        family: str = "NETFX481") -> dict[str, object]:
    """Bounded local classification of Microsoft logs in a disposable prefix.

    Never returns any source filename or raw log content. Directory enumeration
    is non-following and limited; unknown paths, symlinks and large files are
    skipped or classified as incomplete rather than leaking context.
    """
    import os
    from scripts.netfx481_prereq_diagnostic import (
        classify_text as classify_prerequisite_text,
        empty as empty_prerequisite, validate as validate_prerequisite,
    )

    from scripts.netfx481_trial import validate_prefix
    validate_prefix(prefix)
    if family not in SECONDARY_FAMILIES:
        raise ValueError("Unsupported original setup family")
    roots = _secondary_roots(prefix)
    if baseline is not None and (type(baseline) is not dict
            or any(not isinstance(k, Path) or type(v) is not tuple
                   or len(v) != 3 or any(type(n) is not int for n in v)
                   for k, v in baseline.items())):
        raise ValueError("Untrusted pre-upgrade log metadata")
    seen_files: set[Path] = set()
    totals = {name: 0 for name in sorted(SECONDARY_SOURCE_NAMES)}
    errors: set[str] = set()
    phases = {name: 0 for name in sorted(KNOWN_PHASES)}
    scanned = 0
    prerequisite_files = 0
    stage_files = 0
    stage_os: set[str] = set()
    stage_blockers: set[str] = set()
    stage_5100 = False
    prereq_os: set[str] = set()
    prereq_blockers: set[str] = set()
    prereq_5100 = False
    directories = 0
    partial = False
    invalid = False
    for root in roots:
        if not root.exists():
            continue
        if root.is_symlink() or not root.is_dir():
            invalid = True
            continue
        for current, subdirs, filenames in os.walk(root, topdown=True, followlinks=False):
            directories += 1
            base = Path(current)
            if directories > SECONDARY_MAX_DIRS:
                partial = True
                break
            relative_parts = len(base.relative_to(root).parts)
            if relative_parts >= 7:
                subdirs.clear()
            else:
                subdirs[:] = sorted(x for x in subdirs if not (base / x).is_symlink())[:24]
            for name in sorted(filenames):
                if not _SECONDARY_FILENAME.fullmatch(name):
                    continue
                file = base / name
                if file.is_symlink() or not file.is_file() or file in seen_files:
                    continue
                if scanned >= SECONDARY_MAX_FILES:
                    partial = True
                    break
                seen_files.add(file)
                scanned += 1
                source = _source_group(name)
                totals[source] += 1
                try:
                    with file.open("rb") as stream:
                        raw = stream.read(SECONDARY_MAX_PER_FILE + 1)
                except OSError:
                    partial = True
                    continue
                if len(raw) > SECONDARY_MAX_PER_FILE:
                    partial = True
                    continue
                new_or_changed = baseline is not None and (
                    file not in baseline or _metadata(file) != baseline[file])
                named_for_family = _is_target_log_name(name, family)
                # Do not classify a preceding original .NET 4.0 / 4.8.1
                # setup log as a .NET 4.8 failure merely because the file
                # already existed before the 4.8 attempt.
                family_stage_file = new_or_changed and (
                    family == "NETFX481" or not _is_481_log_name(name))
                if named_for_family or family_stage_file:
                    prereq = classify_prerequisite_text(raw)
                    if prereq["status"] != "CLASSIFIED":
                        partial = True
                    else:
                        if named_for_family:
                            prerequisite_files += 1
                            prereq_os.update(prereq["os_versions"])
                            prereq_blockers.update(prereq["blockers"])
                            prereq_5100 = prereq_5100 or prereq["5100_in_log"]
                        if family_stage_file:
                            stage_files += 1
                            stage_os.update(prereq["os_versions"])
                            stage_blockers.update(prereq["blockers"])
                            stage_5100 = stage_5100 or prereq["5100_in_log"]
                # For the .NET 4.8 direct setup, prior msxml3 / .NET 4.0
                # logs are not evidence of the current installer outcome.
                if family == "NETFX48" and not (named_for_family or family_stage_file):
                    continue
                result = classify_text(raw)
                if result["status"] != "CLASSIFIED":
                    partial = True
                    continue
                errors.update(result["codes"])
                if result["phase"] != "UNKNOWN":
                    phases[result["phase"]] += 1
            if scanned >= SECONDARY_MAX_FILES:
                partial = True
                break
    most_common = sorted(
        ((count, phase) for phase, count in phases.items() if phase != "UNKNOWN" and count > 0),
        key=lambda item: (-item[0], item[1]),
    )
    phase = most_common[0][1] if most_common else "UNKNOWN"
    status = ("PARTIAL_SCAN" if partial else
              "CLASSIFIED" if scanned > 0 else
              "INVALID_ROOT" if invalid else "NOT_FOUND")
    return {
        "status": status,
        "files_scanned": scanned,
        "prerequisite_files": prerequisite_files,
        "stage_files": stage_files,
        "stage_scope": "CAPTURED" if baseline is not None else "NOT_REQUESTED",
        "sources": totals,
        "phase": phase,
        "codes": sorted(errors),
        "prerequisite": (
            {"status": "CLASSIFIED", "os_versions": sorted(prereq_os),
             "blockers": sorted(prereq_blockers), "5100_in_log": prereq_5100}
            if prerequisite_files else empty_prerequisite("NOT_FOUND")
        ),
        "stage_prerequisite": (
            {"status": "CLASSIFIED", "os_versions": sorted(stage_os),
             "blockers": sorted(stage_blockers), "5100_in_log": stage_5100}
            if stage_files else empty_prerequisite(
                "NOT_FOUND" if baseline is not None else "NOT_REQUESTED")
        ),
    }


def validate_secondary_report(report: dict) -> bool:
    from scripts.netfx481_prereq_diagnostic import (
        validate as validate_prerequisite, empty as empty_prerequisite,
    )
    if type(report) is not dict or set(report) != {
            "status", "files_scanned", "prerequisite_files", "stage_files",
            "stage_scope", "sources", "phase", "codes", "prerequisite",
            "stage_prerequisite"}:
        return False
    if (not validate_prerequisite(report["prerequisite"])
            or not validate_prerequisite(report["stage_prerequisite"])):
        return False
    sources = report.get("sources")
    codes = report.get("codes")
    return (
        report.get("status") in SECONDARY_STATUSES
        and type(report["prerequisite_files"]) is int
        and 0 <= report["prerequisite_files"] <= report["files_scanned"]
        and report["stage_scope"] in {"NOT_REQUESTED", "CAPTURED"}
        and type(report["stage_files"]) is int
        and 0 <= report["stage_files"] <= report["files_scanned"]
        and (report["stage_files"] > 0 or report["stage_prerequisite"]
             == empty_prerequisite("NOT_FOUND" if
                report["stage_scope"] == "CAPTURED" else "NOT_REQUESTED"))
        and (report["stage_files"] == 0 or
             (report["stage_scope"] == "CAPTURED" and
              report["stage_prerequisite"]["status"] == "CLASSIFIED"))
        and (report["prerequisite_files"] > 0 or
             report["prerequisite"] == empty_prerequisite("NOT_FOUND"))
        and (report["prerequisite_files"] == 0 or
             report["prerequisite"]["status"] == "CLASSIFIED")
        and report.get("phase") in KNOWN_PHASES
        and isinstance(report.get("files_scanned"), int)
        and not isinstance(report["files_scanned"], bool)
        and 0 <= report["files_scanned"] <= SECONDARY_MAX_FILES
        and isinstance(sources, dict)
        and set(sources) == SECONDARY_SOURCE_NAMES
        and all(type(v) is int and 0 <= v <= SECONDARY_MAX_FILES for v in sources.values())
        and sum(sources.values()) == report["files_scanned"]
        and isinstance(codes, list)
        and len(codes) <= len(KNOWN_CODES)
        and codes == sorted(set(codes))
        and all(code in KNOWN_CODES.values() for code in codes)
    )
