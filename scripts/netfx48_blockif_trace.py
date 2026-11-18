"""Privacy-safe evidence from the genuine Microsoft .NET 4.8 setup BlockIf trace.

Evaluated TRUE/ FALSE conditions are inspected only in a private, disposable
Wine setup log. Never return original descriptions, expressions, paths,
unrecognized error codes or dynamic strings in the public report.
"""
from __future__ import annotations

from pathlib import Path
import re

from scripts.netfx481_setup_evidence import _decode
from scripts.netfx481_prereq_diagnostic import CAUSE_REGEX
from scripts.netfx48_bootstrap_blockif import (
    BLOCK, BEGIN, RESULT, MAX_LINE, MAX_LINES, MAX_BLOCK_LINES, extract,
)

MAX_BYTES = 8 * 1024 * 1024
MAX_VERDICTS = 128
STATES = {"NOT_RUN", "NOT_FOUND", "READ_FAILED", "TOO_LARGE",
          "INVALID_ENCODING", "NO_VERDICTS", "CAPTURED", "LIMIT_REACHED"}
MILESTONES = {
    "BLOCKIF_TEXT", "BLOCKIF_OPENED", "BLOCKIF_EVALUATION",
    "BLOCKIF_VERDICT", "GLOBAL_BLOCK_CHECKS", "NO_BLOCKING_CONDITIONS",
    "OS_VERSION_REPORTED", "STOPBLOCK_TERMINAL", "PAYLOAD_EXTRACTION",
    "INSTALLER_PHASE", "SERVICE_QUERY_TEXT",
}
LINE_BANDS = {"NOT_REPORTED", "EMPTY", "ONE_TO_100", "101_TO_1000", "OVER_1000"}
MILESTONE_PATTERNS = (
    ("BLOCKIF_TEXT", re.compile(r"(?i)\bblockif\b")),
    ("BLOCKIF_OPENED", BLOCK),
    ("BLOCKIF_EVALUATION", BEGIN),
    ("BLOCKIF_VERDICT", RESULT),
    ("GLOBAL_BLOCK_CHECKS", re.compile(r"(?i)\bglobal\s+block\s+checks\b")),
    ("NO_BLOCKING_CONDITIONS", re.compile(r"(?i)\bno\s+blocking\s+conditions\s+found\b")),
    ("OS_VERSION_REPORTED", re.compile(r"(?i)\bOS\s+Version\s*[=:]\s*\d")),
    ("STOPBLOCK_TERMINAL", re.compile(r"(?i)\bstopblock\b|\b0x000013ec\b")),
    ("PAYLOAD_EXTRACTION", re.compile(r"(?i)\bextract(?:ion|ing|ed)?\b")),
    ("INSTALLER_PHASE", re.compile(r"(?i)\b(?:msiexec|MSI\s+install|installation\s+started)\b")),
    ("SERVICE_QUERY_TEXT", re.compile(r"(?i)\b(?:TrustedInstaller|OpenSCManager|OpenService|msiserver|wuauserv)\b")),
)
SIGNALS = {
    "TRUSTEDINSTALLER_SERVICE_QUERY", "TRUSTEDINSTALLER_MISSING_1060",
    "MSISERVER_SERVICE_QUERY", "MSISERVER_MISSING_1060",
    "WINDOWS_UPDATE_SERVICE_QUERY", "BITS_SERVICE_QUERY",
    "REGISTRY_CONDITION", "OS_VERSION_CONDITION",
}
MISSING = re.compile(
    r"(?i)(?:\berror\s+1060\b|\bdoes(?:n['’]t| not)\s+exist\b|"
    r"\bservice\s+does\s+not\s+exist\b)"
)
TRUST = re.compile(r"(?i)\bTrustedInstaller\b|\bWindows Modules Installer\b")
MSI = re.compile(r"(?i)\bmsiserver\b|\bWindows Installer Service\b")
UPDATE = re.compile(r"(?i)\bwuauserv\b|\bWindows Update Service\b")
BITS = re.compile(r"(?i)\bBITS\b|\bBackground Intelligent Transfer Service\b")
REG = re.compile(r"(?i)\b(?:RegKeyValue|RegKeyExists|RegistryValue)\s*:")
OS = re.compile(r"(?i)\b(?:GetOSVersion|OSVersion|WindowsVersion|VersionNT)\s*:")


def blank(status: str = "NOT_RUN") -> dict:
    if status not in STATES:
        raise ValueError("Unrecognized original installer BlockIf diagnostic")
    return {"status": status, "true_count": 0, "false_count": 0,
            "incomplete_count": 0, "true_cause_categories": [],
            "true_logic_signals": [], "milestones": [],
            "log_line_band": "NOT_REPORTED"}


def validate(value: object) -> bool:
    if type(value) is not dict or set(value) != set(blank()):
        return False
    if (value["status"] not in STATES
            or any(type(value[k]) is not int or not 0 <= value[k] <= MAX_VERDICTS
                   for k in ("true_count", "false_count", "incomplete_count"))
            or type(value["true_cause_categories"]) is not list
            or type(value["true_logic_signals"]) is not list
            or type(value["milestones"]) is not list
            or value["log_line_band"] not in LINE_BANDS):
        return False
    from scripts.netfx481_prereq_diagnostic import CAUSES
    for field, allowed in (("true_cause_categories", CAUSES),
                           ("true_logic_signals", SIGNALS)):
        entries = value[field]
        if entries != sorted(set(entries)) or any(
                type(item) is not str or item not in allowed for item in entries):
            return False
    if (value["milestones"] != sorted(set(value["milestones"]))
            or any(type(item) is not str or item not in MILESTONES
                   for item in value["milestones"])):
        return False
    if value["status"] in {"NOT_RUN", "NOT_FOUND", "READ_FAILED",
                           "TOO_LARGE", "INVALID_ENCODING", "LIMIT_REACHED"}:
        return value == blank(value["status"])
    if value["log_line_band"] == "NOT_REPORTED":
        return False
    if value["status"] == "NO_VERDICTS":
        return value["true_count"] == value["false_count"] == 0 and not (
            value["true_cause_categories"] or value["true_logic_signals"])
    if value["status"] == "CAPTURED":
        return 0 < value["true_count"] + value["false_count"] <= MAX_VERDICTS
    return False


def _signals(logic_lines: list[str]) -> set[str]:
    """Use only fixed recognizers on expression lines tied to a TRUE verdict."""
    matched: set[str] = set()
    for line in logic_lines:
        if TRUST.search(line):
            matched.add("TRUSTEDINSTALLER_SERVICE_QUERY")
            if MISSING.search(line):
                matched.add("TRUSTEDINSTALLER_MISSING_1060")
        if MSI.search(line):
            matched.add("MSISERVER_SERVICE_QUERY")
            if MISSING.search(line):
                matched.add("MSISERVER_MISSING_1060")
        if UPDATE.search(line):
            matched.add("WINDOWS_UPDATE_SERVICE_QUERY")
        if BITS.search(line):
            matched.add("BITS_SERVICE_QUERY")
        if REG.search(line):
            matched.add("REGISTRY_CONDITION")
        if OS.search(line):
            matched.add("OS_VERSION_CONDITION")
    return matched


def classify(raw: bytes) -> dict:
    if len(raw) > MAX_BYTES:
        return blank("TOO_LARGE")
    decoded = _decode(raw)
    if decoded is None:
        return blank("INVALID_ENCODING")
    lines = decoded.splitlines()[:MAX_LINES]
    line_count = len(lines)
    band = ("EMPTY" if not line_count else "ONE_TO_100" if line_count <= 100
            else "101_TO_1000" if line_count <= 1000 else "OVER_1000")
    milestones = set()
    for line in lines:
        if len(line) <= MAX_LINE:
            for kind, pattern in MILESTONE_PATTERNS:
                if pattern.search(line):
                    milestones.add(kind)
    any_evaluated, true_descriptions, _ = extract(lines)
    true_count = false_count = incomplete_count = 0
    signals: set[str] = set()
    active = False
    evaluating = False
    expressions: list[str] = []
    block_lines = 0

    for line in lines:
        if len(line) > MAX_LINE:
            continue
        opened = BLOCK.search(line)
        if opened and not BEGIN.search(line):
            if active:
                incomplete_count += 1
            active, evaluating, expressions, block_lines = True, False, [], 0
            continue
        if not active:
            continue
        block_lines += 1
        verdict = RESULT.search(line)
        if verdict:
            if verdict.group(1).lower() == "true":
                true_count += 1
                signals.update(_signals(expressions))
            else:
                false_count += 1
            active = evaluating = False
            expressions = []
            if true_count + false_count > MAX_VERDICTS:
                return blank("LIMIT_REACHED")
            continue
        if BEGIN.search(line):
            evaluating = True
        elif evaluating:
            # Strings are never retained outside this one call.
            expressions.append(line)
        if block_lines >= MAX_BLOCK_LINES:
            incomplete_count += 1
            active = evaluating = False
            expressions = []
    if active:
        incomplete_count += 1
    if incomplete_count > MAX_VERDICTS:
        return blank("LIMIT_REACHED")
    causes = set()
    for description in true_descriptions:
        found = False
        for cause, pattern in CAUSE_REGEX:
            if pattern.search(description):
                causes.add(cause)
                found = True
        if not found:
            causes.add("UNKNOWN_PREREQUISITE")
    result = {
        "status": "CAPTURED" if any_evaluated and true_count + false_count else "NO_VERDICTS",
        "true_count": true_count, "false_count": false_count,
        "incomplete_count": incomplete_count,
        "true_cause_categories": sorted(causes),
        "true_logic_signals": sorted(signals),
        "milestones": sorted(milestones), "log_line_band": band,
    }
    assert validate(result)
    return result


def classify_file(path: Path) -> dict:
    if path.is_symlink():
        return blank("READ_FAILED")
    try:
        if not path.is_file():
            return blank("NOT_FOUND")
        with path.open("rb") as stream:
            raw = stream.read(MAX_BYTES + 1)
    except OSError:
        return blank("READ_FAILED")
    return classify(raw)
