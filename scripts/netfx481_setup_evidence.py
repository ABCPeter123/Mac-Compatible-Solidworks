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
