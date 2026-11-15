"""Classify original .NET 4.8.1 prerequisites without disclosing setup logs.

Only reads private, short-lived authenticated Microsoft /log material under
a marked Wine prefix. No dynamic strings, file paths, names or log lines
leave the process. Designed to identify the *actual OS version seen by setup*,
not the unrelated version reported by an independent test executable.
"""
from __future__ import annotations
from pathlib import Path
import re
from scripts.netfx481_setup_evidence import _decode

MAX_BYTES = 8 * 1024 * 1024
OS_CLASSES = {"BELOW_WINDOWS_10", "WINDOWS_10_TOO_OLD", "WINDOWS_10_SUPPORTED",
              "WINDOWS_11_SUPPORTED", "UNKNOWN_VERSION"}
CAUSES = {
    "OS_VERSION_BLOCK", "OS_EDITION_BLOCK", "WINDOWS_SERVICING_BLOCK",
    "MISSING_UPDATE_BLOCK", "PENDING_REBOOT_BLOCK", "ADMIN_RIGHTS_BLOCK",
    "PROCESSOR_BLOCK", "EXISTING_FRAMEWORK_BLOCK", "UNKNOWN_PREREQUISITE",
}
STATES = {"NOT_REQUESTED", "NOT_FOUND", "READ_FAILED", "TOO_LARGE",
          "INVALID_ENCODING", "CLASSIFIED"}
OS_LINE = re.compile(r"(?i)\bOS\s+Version\s*[=:]\s*(\d{1,2})\.(\d{1,2})\.(\d{1,6})\b")
FAIL_LINE = re.compile(
    r"(?i)\b(block(?:ed|ing)?|fail(?:ed|ure)?|unsupported|not supported|not applicable|"
    r"prerequisite|requirement|minimum|cannot (?:install|continue)|5100)\b"
)
CAUSE_REGEX = (
    ("OS_VERSION_BLOCK", re.compile(r"(?i)(?:operating system|os version|windows version).{0,90}"
                                   r"(?:not supported|unsupported|too old|requires|minimum|blocking|blocked)"
                                   r"|(?:not supported|unsupported|requires|minimum).{0,90}"
                                   r"(?:operating system|os version|windows version)")),
    ("OS_EDITION_BLOCK", re.compile(r"(?i)\b(?:edition|server core|product type|sku)\b")),
    ("WINDOWS_SERVICING_BLOCK", re.compile(r"(?i)\b(?:component store|servicing|CBS|DISM|windows update service)\b")),
    ("MISSING_UPDATE_BLOCK", re.compile(r"(?i)\b(?:KB\d{5,9}|missing update|cumulative update)\b")),
    ("PENDING_REBOOT_BLOCK", re.compile(r"(?i)\b(?:pending reboot|reboot required|restart required)\b")),
    ("ADMIN_RIGHTS_BLOCK", re.compile(r"(?i)\b(?:administrator privileges|elevat(?:ed|ion)|access denied)\b")),
    ("PROCESSOR_BLOCK", re.compile(r"(?i)\b(?:processor architecture|unsupported processor|unsupported cpu)\b")),
    ("EXISTING_FRAMEWORK_BLOCK", re.compile(r"(?i)\b(?:already installed|higher version|later version|existing framework)\b")),
)


def empty(status: str = "NOT_REQUESTED") -> dict:
    if status not in STATES:
        raise ValueError("Unrecognized original setup log state")
    return {"status": status, "os_versions": [], "blockers": [],
            "5100_in_log": False}


def validate(result: object) -> bool:
    if type(result) is not dict or set(result) != set(empty()):
        return False
    if (result["status"] not in STATES
            or type(result["os_versions"]) is not list
            or type(result["blockers"]) is not list
            or type(result["5100_in_log"]) is not bool):
        return False
    if (result["os_versions"] != sorted(set(result["os_versions"]))
            or result["blockers"] != sorted(set(result["blockers"]))
            or any(v not in OS_CLASSES for v in result["os_versions"])
            or any(v not in CAUSES for v in result["blockers"])):
        return False
    return result["status"] == "CLASSIFIED" or result == empty(result["status"])


def _os_class(major: int, minor: int, build: int) -> str:
    if major == 10 and minor == 0:
        if 19042 <= build < 22000:
            return "WINDOWS_10_SUPPORTED"
        if 22000 <= build < 30000:
            return "WINDOWS_11_SUPPORTED"
        return "WINDOWS_10_TOO_OLD"
    if major < 10:
        return "BELOW_WINDOWS_10"
    return "UNKNOWN_VERSION"


def classify_text(raw: bytes) -> dict:
    if len(raw) > MAX_BYTES:
        return empty("TOO_LARGE")
    content = _decode(raw)
    if content is None:
        return empty("INVALID_ENCODING")
    versions: set[str] = set()
    blockers: set[str] = set()
    return_code = False
    for line in content.splitlines()[:30000]:
        if len(line) > 8192:
            continue
        match = OS_LINE.search(line)
        if match:
            versions.add(_os_class(*[int(n) for n in match.groups()]))
        if not FAIL_LINE.search(line):
            continue
        if re.search(r"(?i)(?<!\d)5100(?!\d)|0x000013ec\b", line):
            return_code = True
        for category, regex in CAUSE_REGEX:
            if regex.search(line):
                blockers.add(category)
        if (not any(regex.search(line) for _, regex in CAUSE_REGEX)
                and re.search(r"(?i)\b(?:block(?:ed|ing)?|prerequisite|system requirement)\b", line)):
            blockers.add("UNKNOWN_PREREQUISITE")
    result = {"status": "CLASSIFIED", "os_versions": sorted(versions),
              "blockers": sorted(blockers), "5100_in_log": return_code}
    assert validate(result)
    return result


def classify_file(path: Path) -> dict:
    if path.is_symlink():
        return empty("READ_FAILED")
    try:
        if not path.is_file():
            return empty("NOT_FOUND")
        with path.open("rb") as stream:
            raw = stream.read(MAX_BYTES + 1)
    except OSError:
        return empty("READ_FAILED")
    return classify_text(raw)
